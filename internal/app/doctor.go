package app

import (
	"bytes"
	"context"
	"database/sql"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Check is one doctor probe result.
type Check struct {
	Name   string
	OK     bool
	Detail string
	Hint   string
}

// Doctor runs CONFIG/DATABASE/CRYPTO/DERO/WALLET/STORAGE/NETWORK/RELAY probes.
// It never logs secrets.
func (a *App) Doctor(ctx context.Context) []Check {
	return []Check{
		a.checkConfig(ctx),
		a.checkDatabase(ctx),
		a.checkCrypto(ctx),
		a.checkDero(ctx),
		a.checkWallet(ctx),
		a.checkStorage(ctx),
		a.checkNetwork(ctx),
		a.checkRelay(ctx),
	}
}

func (a *App) checkConfig(_ context.Context) Check {
	if err := os.MkdirAll(a.dataDir, 0o755); err != nil {
		return Check{"CONFIG", false, "data dir not writable", "set GHOSTDROP_DATA_DIR to a writable path"}
	}
	probe := filepath.Join(a.dataDir, ".write-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return Check{"CONFIG", false, "data dir not writable", "set GHOSTDROP_DATA_DIR to a writable path"}
	}
	os.Remove(probe)
	return Check{"CONFIG", true, "data dir " + a.dataDir, ""}
}

func (a *App) checkDatabase(ctx context.Context) Check {
	tmp, err := os.CreateTemp("", "ghostdrop-doc-*.db")
	if err != nil {
		return Check{"DATABASE", false, "temp db failed", "check disk space and temp dir permissions"}
	}
	name := tmp.Name()
	tmp.Close()
	defer os.Remove(name)
	db, err := sql.Open("sqlite", name)
	if err != nil {
		return Check{"DATABASE", false, "sqlite open failed", "ensure modernc.org/sqlite builds on this platform"}
	}
	defer db.Close()
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS drops (id TEXT PRIMARY KEY, created_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, action TEXT)`,
		`CREATE TABLE IF NOT EXISTS contacts (id TEXT PRIMARY KEY, address TEXT)`,
		`INSERT INTO drops(id, created_at) VALUES('doctor-probe', 'now')`,
	} {
		if _, err := db.ExecContext(qctx, q); err != nil {
			return Check{"DATABASE", false, "migrate failed: " + shortErr(err), "delete the corrupt db file to re-migrate"}
		}
	}
	var n int
	if err := db.QueryRowContext(qctx, `SELECT COUNT(*) FROM drops`).Scan(&n); err != nil || n < 1 {
		return Check{"DATABASE", false, "verify query failed", "delete the corrupt db file to re-migrate"}
	}
	return Check{"DATABASE", true, "sqlite backup/migrate/verify ok", ""}
}

func (a *App) checkCrypto(_ context.Context) Check {
	k, err := GenerateFileKey()
	if err != nil {
		return Check{"CRYPTO", false, "rand failed", "check OS entropy source"}
	}
	nonce, sealed, err := SealBytes([]byte("doctor"), k[:])
	if err != nil {
		return Check{"CRYPTO", false, "seal failed", "reinstall ghostdrop binary"}
	}
	if _, err := OpenBytes(nonce, sealed, k[:]); err != nil {
		return Check{"CRYPTO", false, "open failed", "reinstall ghostdrop binary"}
	}
	salt, err := NewSalt()
	if err != nil {
		return Check{"CRYPTO", false, "salt failed", "check OS entropy source"}
	}
	_ = DeriveKeyFromPassphrase("doctor", salt)
	pub, priv, err := GenerateSignKeypair()
	if err != nil {
		return Check{"CRYPTO", false, "sign keygen failed", "reinstall ghostdrop binary"}
	}
	sig, err := Sign(priv, []byte("doctor"))
	if err != nil || !Verify(pub, []byte("doctor"), sig) {
		return Check{"CRYPTO", false, "sign/verify failed", "reinstall ghostdrop binary"}
	}
	Wipe(k[:])
	return Check{"CRYPTO", true, "xchacha20/argon2id/ed25519/x25519 ok", ""}
}

func httpProbe(url string, timeout time.Duration) error {
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func (a *App) checkDero(_ context.Context) Check {
	ep := envOr("GHOSTDROP_DAEMON", "http://127.0.0.1:10102/json_rpc")
	if err := httpProbe(ep, 3*time.Second); err != nil {
		return Check{"DERO", false, "daemon unreachable", "start derod or set GHOSTDROP_DAEMON=http://host:10102/json_rpc"}
	}
	return Check{"DERO", true, "daemon reachable", ""}
}

func (a *App) checkWallet(_ context.Context) Check {
	ep := envOr("GHOSTDROP_WALLET", "http://127.0.0.1:10103")
	if err := httpProbe(ep, 3*time.Second); err != nil {
		return Check{"WALLET", false, "wallet rpc unreachable", "start dero-wallet-cli --rpc-server or set GHOSTDROP_WALLET"}
	}
	return Check{"WALLET", true, "wallet rpc reachable", ""}
}

func (a *App) checkStorage(ctx context.Context) Check {
	if err := a.store.Health(ctx); err != nil {
		return Check{"STORAGE", false, "local store unhealthy", "check disk space and GHOSTDROP_DATA_DIR permissions"}
	}
	id := "GD-DOCTOR0000"
	payload := []byte("doctor")
	if err := a.store.Put(ctx, id, bytes.NewReader(payload), int64(len(payload)), time.Now().Add(time.Minute)); err != nil {
		return Check{"STORAGE", false, "write probe failed", "check disk space and permissions"}
	}
	defer a.store.Delete(ctx, id)
	rc, err := a.store.Get(ctx, id, 2)
	if err != nil {
		return Check{"STORAGE", false, "resume read failed", "check disk health"}
	}
	defer rc.Close()
	return Check{"STORAGE", true, "local put/get(offset)/delete ok", ""}
}

func (a *App) checkNetwork(_ context.Context) Check {
	d := net.Dialer{Timeout: 4 * time.Second}
	c, err := d.Dial("tcp", "1.1.1.1:443")
	if err != nil {
		return Check{"NETWORK", false, "no outbound tcp", "check firewall / connectivity"}
	}
	c.Close()
	return Check{"NETWORK", true, "outbound tcp ok", ""}
}

func (a *App) checkRelay(ctx context.Context) Check {
	relay := a.relayURL
	if relay == "" {
		relay = envOr("GHOSTDROP_RELAY", "")
	}
	if relay == "" {
		return Check{"RELAY", false, "no relay configured", "pass --relay http://host:port or set GHOSTDROP_RELAY"}
	}
	if err := NewRelayClient(relay, "").Health(ctx); err != nil {
		return Check{"RELAY", false, "relay unhealthy", "start ghostdrop-relay or fix --relay URL"}
	}
	return Check{"RELAY", true, "relay " + relay + " healthy", ""}
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

