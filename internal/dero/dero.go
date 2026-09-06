// Package dero integrates Ghostdrop with the DERO network: daemon queries,
// wallet-RPC signing, address/name handling, and payment confirmation.
//
// # RPC convention
//
// DaemonClient speaks a minimal JSON-RPC 2.0 envelope shared by the DERO
// daemon and wallet RPC interfaces:
//
//	POST {endpoint}/json_rpc
//	{"jsonrpc":"2.0","id":"ghostdrop","method":"<m>","params":{...}}
//
// Methods used:
//
//	get_info        params {}                    -> {"status","height"}
//	resolve_name    params {"name"}              -> {"address","verified"}
//	get_transaction params {"txid"}              -> {"txid","address","amount","confirmations"}
//	get_version     params {} (wallet)           -> {"status","version"}
//	sign_data       params {"data": hex} (wallet)-> {"signature": hex, "public_key": hex}
//	transfer        params {"destinations",      -> {"tx_hash"}
//	                         "fee"} (wallet)
//
// Unknown names/transactions come back as JSON-RPC errors with code -32004.
//
// # Verification policy
//
// verified=true is returned ONLY when the daemon itself confirms a
// name->address mapping. A bare dero1... address that merely passes
// ValidateAddress is returned with verified=false (passthrough, unconfirmed).
// Local trust overrides live in internal/identity, never here.
//
// # Offline behavior (graceful, caller-safe)
//
// Any transport-level failure (connection refused, DNS, timeout, reset)
// is wrapped in ErrOffline; use IsOffline to detect it. Offline calls
// return zero values ("", false, ErrOffline) so callers can never mistake
// an outage for a valid answer. Daemon-reported errors (unknown name,
// unknown tx) are typed errors, NOT ErrOffline.
//
// Nothing in this package persists seeds, keys, or passphrases; signing and
// spending happen inside the user's wallet via RPC and require that wallet's
// own explicit approval. This package never auto-spends.
package dero

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	// ErrOffline wraps every transport-level failure talking to a daemon or
	// wallet endpoint. Callers MUST treat ("", false, ErrOffline) as "unknown",
	// never as a negative answer.
	ErrOffline = errors.New("dero: endpoint offline")

	// ErrTxNotFound means the daemon answered but knows no such transaction.
	// Pollers (e.g. payments.AwaitPayment) treat this as "not yet", not fatal.
	ErrTxNotFound = errors.New("dero: transaction not found")

	// ErrNameNotFound means the daemon answered but knows no such DERO name.
	ErrNameNotFound = errors.New("dero: name not found")

	// ErrInvalidName means the input is neither a valid DERO name nor address.
	ErrInvalidName = errors.New("dero: invalid DERO name")

	// ErrInvalidAddress means a destination failed structural validation.
	ErrInvalidAddress = errors.New("dero: invalid DERO address")

	// DefaultDaemonEndpoint is the local DERO daemon default used by the
	// package-level helpers. It is a var so tests and embedders can redirect it.
	DefaultDaemonEndpoint = "http://127.0.0.1:10102"

	// DefaultWalletEndpoint is the local wallet-RPC default.
	DefaultWalletEndpoint = "http://127.0.0.1:10103"
)

// MinConfirmations gates CheckPayment: a payment counts as confirmed only at
// this depth or beyond.
const MinConfirmations = 10

const (
	defaultRPCTimeout = 10 * time.Second
	maxBodyBytes      = 1 << 20 // 1 MiB cap on RPC responses
	rpcNotFoundCode   = -32004
)

var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,64}\.dero$`)

// NormalizeName trims and lowercases a DERO name ("Captain.dero" -> "captain.dero").
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidateName reports whether s is a well-formed DERO name
// (^[a-z0-9-]{1,64}\.dero$, case-insensitive input accepted).
func ValidateName(s string) bool {
	return namePattern.MatchString(NormalizeName(s))
}

// ValidateAddress is a structural check only: "dero1" prefix, total length
// 60..128 chars, alphanumeric body. It says nothing about ownership or
// existence on chain; use ResolveNameOrAddress for confirmed mappings.
func ValidateAddress(addr string) bool {
	a := strings.TrimSpace(addr)
	if !strings.HasPrefix(a, "dero1") {
		return false
	}
	if len(a) < 60 || len(a) > 128 {
		return false
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			continue
		}
		return false
	}
	return true
}

// IsOffline reports whether err wraps ErrOffline.
func IsOffline(err error) bool {
	return errors.Is(err, ErrOffline)
}

// RPCError is a JSON-RPC error object returned by the daemon/wallet.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("dero: rpc error %d: %s", e.Code, e.Message)
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
}

// DaemonClient queries a DERO daemon (and, as pure transport, wallet-RPC).
// Despite the name it speaks the same JSON-RPC envelope both expose; wallet
// helpers reuse it as transport only.
type DaemonClient struct {
	// Endpoint is the base URL, e.g. "http://127.0.0.1:10102".
	// A trailing "/json_rpc" suffix is accepted and not doubled.
	Endpoint string
	// HTTPClient, when nil, defaults to http.DefaultClient.
	HTTPClient *http.Client
	// Timeout applies when ctx carries no deadline. Zero selects 10s.
	Timeout time.Duration
}

// NewDaemonClient builds a client for the given base endpoint URL.
func NewDaemonClient(endpoint string) *DaemonClient {
	return &DaemonClient{Endpoint: endpoint}
}

func (c *DaemonClient) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *DaemonClient) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultRPCTimeout
}

func (c *DaemonClient) rpcURL() string {
	u := strings.TrimRight(strings.TrimSpace(c.Endpoint), "/")
	if strings.HasSuffix(u, "/json_rpc") {
		return u
	}
	return u + "/json_rpc"
}

func (c *DaemonClient) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout())
}

func (c *DaemonClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: "ghostdrop", Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("dero: encode %s request: %w", method, err)
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.rpcURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("dero: build %s request: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		// Transport failure of any kind (refused, DNS, timeout): offline.
		return nil, fmt.Errorf("dero: %s to %s: %w", method, c.Endpoint, ErrOffline)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("dero: read %s response: %w", method, err)
	}
	var env rpcResponse
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("dero: decode %s response: %w", method, err)
	}
	if env.Error != nil {
		return nil, env.Error
	}
	return env.Result, nil
}

// DaemonInfo is the subset of get_info Ghostdrop cares about.
type DaemonInfo struct {
	Status string `json:"status"`
	Height uint64 `json:"height"`
}

// GetInfo probes the daemon. Transport failure returns ErrOffline.
func (c *DaemonClient) GetInfo(ctx context.Context) (DaemonInfo, error) {
	var info DaemonInfo
	raw, err := c.call(ctx, "get_info", map[string]any{})
	if err != nil {
		return DaemonInfo{}, err
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return DaemonInfo{}, fmt.Errorf("dero: decode get_info: %w", err)
	}
	return info, nil
}

// ResolveNameOrAddress resolves a "name.dero" handle or passes a raw address
// through. verified is true ONLY on daemon confirmation; structurally valid
// but unconfirmed addresses return (addr, false, nil). Offline returns
// ("", false, ErrOffline) — never a fabricated answer.
func (c *DaemonClient) ResolveNameOrAddress(ctx context.Context, nameOrAddr string) (address string, verified bool, err error) {
	in := strings.TrimSpace(nameOrAddr)
	if ValidateAddress(in) {
		return in, false, nil
	}
	norm := NormalizeName(in)
	if !ValidateName(norm) {
		return "", false, fmt.Errorf("%w: %q", ErrInvalidName, nameOrAddr)
	}
	raw, err := c.call(ctx, "resolve_name", map[string]any{"name": norm})
	if err != nil {
		var rpcErr *RPCError
		if errors.As(err, &rpcErr) && rpcErr.Code == rpcNotFoundCode {
			return "", false, fmt.Errorf("%w: %s", ErrNameNotFound, norm)
		}
		return "", false, err
	}
	var out struct {
		Address  string `json:"address"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", false, fmt.Errorf("dero: decode resolve_name: %w", err)
	}
	if !ValidateAddress(out.Address) {
		return "", false, fmt.Errorf("dero: daemon returned invalid address for %s", norm)
	}
	return out.Address, out.Verified, nil
}

// ResolveName resolves name via the default daemon endpoint.
func ResolveName(ctx context.Context, name string) (address string, verified bool, err error) {
	return NewDaemonClient(DefaultDaemonEndpoint).ResolveNameOrAddress(ctx, name)
}

// WalletStatus probes a wallet-RPC endpoint. Online wallets answer
// get_version; transport failure returns (false, ErrOffline).
func WalletStatus(ctx context.Context, endpoint string) (online bool, err error) {
	raw, err := NewDaemonClient(endpoint).call(ctx, "get_version", map[string]any{})
	if err != nil {
		return false, err
	}
	var out struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, fmt.Errorf("dero: decode get_version: %w", err)
	}
	return true, nil
}

// SignWithWallet asks the wallet to sign msg (no key material leaves the
// wallet; nothing is persisted here). Returns hex signature + hex public key.
// The wallet itself must obtain any user approval.
func SignWithWallet(ctx context.Context, walletEndpoint string, msg []byte) (sigHex, pubHex string, err error) {
	if len(msg) == 0 {
		return "", "", fmt.Errorf("dero: cannot sign empty message")
	}
	raw, err := NewDaemonClient(walletEndpoint).call(ctx, "sign_data", map[string]any{"data": hex.EncodeToString(msg)})
	if err != nil {
		return "", "", err
	}
	var out struct {
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", "", fmt.Errorf("dero: decode sign_data: %w", err)
	}
	sig, err := hex.DecodeString(strings.TrimSpace(out.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", "", fmt.Errorf("dero: wallet returned bad signature")
	}
	pub, err := hex.DecodeString(strings.TrimSpace(out.PublicKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", "", fmt.Errorf("dero: wallet returned bad public key")
	}
	return out.Signature, out.PublicKey, nil
}

// VerifyWithPub verifies an Ed25519 signature against a hex public key.
// Any malformed input verifies as false, never an error.
func VerifyWithPub(pubHex string, msg, sig []byte) bool {
	pub, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// TransferWithWallet relays a wallet-RPC transfer request. This only forwards
// the user's explicit instruction — approval happens in the wallet, and this
// package stores no credentials, so it cannot spend on its own.
func TransferWithWallet(ctx context.Context, walletEndpoint, dest string, amount, fee uint64) (string, error) {
	dest = strings.TrimSpace(dest)
	if !ValidateAddress(dest) {
		return "", fmt.Errorf("%w: %q", ErrInvalidAddress, dest)
	}
	if amount == 0 {
		return "", fmt.Errorf("dero: transfer amount must be > 0")
	}
	raw, err := NewDaemonClient(walletEndpoint).call(ctx, "transfer", map[string]any{
		"destinations": []map[string]any{{"address": dest, "amount": amount}},
		"fee":          fee,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		TxHash string `json:"tx_hash"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("dero: decode transfer: %w", err)
	}
	if strings.TrimSpace(out.TxHash) == "" {
		return "", fmt.Errorf("dero: wallet returned empty tx_hash")
	}
	return out.TxHash, nil
}

// CheckPayment reports whether txid pays >= minAmount atomic units to address
// with at least MinConfirmations confirmations. Unknown transactions return
// (false, ErrTxNotFound); anything merely unconfirmed returns (false, nil).
// Transport failure returns (false, ErrOffline).
func CheckPayment(ctx context.Context, daemonEndpoint, txid, address string, minAmount uint64) (confirmed bool, err error) {
	txid = strings.TrimSpace(txid)
	if txid == "" {
		return false, fmt.Errorf("dero: empty txid")
	}
	raw, err := NewDaemonClient(daemonEndpoint).call(ctx, "get_transaction", map[string]any{"txid": txid})
	if err != nil {
		var rpcErr *RPCError
		if errors.As(err, &rpcErr) && rpcErr.Code == rpcNotFoundCode {
			return false, ErrTxNotFound
		}
		return false, err
	}
	var out struct {
		Txid          string `json:"txid"`
		Address       string `json:"address"`
		Amount        uint64 `json:"amount"`
		Confirmations uint64 `json:"confirmations"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, fmt.Errorf("dero: decode get_transaction: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(out.Address), strings.TrimSpace(address)) {
		return false, nil
	}
	if out.Amount < minAmount {
		return false, nil
	}
	if out.Confirmations < MinConfirmations {
		return false, nil
	}
	return true, nil
}
