// Package p2p implements Ghostdrop V1 direct peer transfers (DirectDrop).
//
// Two peers open a TCP connection; the dialer sends, the listener receives.
// Handshake: both sides contribute an X25519 ephemeral and authenticate with
// an Ed25519 identity signature over the handshake bytes (TOFU on first
// contact). The session key is SHA256(ecdh || senderEphem || receiverEphem).
//
// The file then streams in chunks of at most 1MiB, each sealed with
// XChaCha20-Poly1305 under the session key. The chunk nonce is a random
// 24-byte base (exchanged in the signed handshake) with the last 8 bytes
// XORed by the big-endian chunk index — the same convention as the GD01
// file format. Every chunk is ACKed (stop-and-wait); the receiver hashes
// the plaintext stream and verifies size + SHA-256 at FIN.
//
// Resume: the receiver keeps the partial file at dstPath and reports the
// last fully-received chunk boundary as acceptedOffset; the sender seeks
// its source there and continues. Any tamper fails the Poly1305 open or
// the final hash check.
package p2p

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Magic identifies the DirectDrop handshake.
const Magic = "GDP1"

// Version is the handshake version.
const Version byte = 1

// ChunkSize is the 1MiB chunk size.
const ChunkSize = 1 << 20

// MaxChunkSize caps a negotiated chunk size (8MiB).
const MaxChunkSize = 8 << 20

// MinChunkSize floors a negotiated chunk size (1KiB).
const MinChunkSize = 1 << 10

var (
	// ErrHashMismatch means the received stream failed size/SHA-256 verify.
	ErrHashMismatch = errors.New("p2p: hash mismatch")
	// ErrProtocol means a framing/handshake violation.
	ErrProtocol = errors.New("p2p: protocol violation")
)

// GenerateIdentity returns a fresh Ed25519 (pub, priv) identity pair.
func GenerateIdentity() (pub, priv []byte, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

// SendOptions tunes Send/SendFile.
type SendOptions struct {
	// OffsetHint suggests where to resume. The receiver is authoritative;
	// the handshake response carries the accepted offset. 0 = from start.
	OffsetHint int64
	// ChunkSize overrides the 1MiB default. Clamped to [1KiB, 8MiB].
	ChunkSize int
	// Progress, if non-nil, fires after each ACKed chunk with (sent, total).
	Progress func(sent, total int64)
}

// RecvOptions tunes Receive/ServeOnce.
type RecvOptions struct {
	// Progress, if non-nil, fires after each received chunk with (recv, total).
	Progress func(recv, total int64)
}

func chunkSizeOf(o int) int {
	if o <= 0 {
		return ChunkSize
	}
	if o < MinChunkSize {
		return MinChunkSize
	}
	if o > MaxChunkSize {
		return MaxChunkSize
	}
	return o
}

// --- handshake framing ---
// sender HS: magic(4) ver(1) idPub(32) ephemPub(32) baseNonce(24)
// offset(8) fileSize(8) fileHash(32) chunkSize(4) sig(64)
// receiver RSP: magic(4) ver(1) idPub(32) ephemPub(32) acceptedOff(8) sig(64)

const (
	hsLen  = 4 + 1 + 32 + 32 + 24 + 8 + 8 + 32 + 4 + 64
	rspLen = 4 + 1 + 32 + 32 + 8 + 64
	sigLen = 64
)

type handshake struct {
	idPub     []byte
	ephemPub  []byte
	baseNonce [24]byte
	offset    int64
	fileSize  int64
	fileHash  [32]byte
	chunkSize int
}

func generateEphemeral() (priv, pub []byte, err error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey.Bytes(), privKey.PublicKey().Bytes(), nil
}

func ecdhShared(privBytes, pubBytes []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}
func sessionKey(shared, senderEphem, receiverEphem []byte) [32]byte {
	h := sha256.New()
	h.Write(shared)
	h.Write(senderEphem)
	h.Write(receiverEphem)
	var k [32]byte
	copy(k[:], h.Sum(nil))
	return k
}

func chunkNonce(base [24]byte, idx uint64) [24]byte {
	var n [24]byte
	copy(n[:], base[:])
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], idx)
	for i := 0; i < 8; i++ {
		n[16+i] ^= b[i]
	}
	return n
}

// Send streams srcPath over conn to a waiting Receive peer.
func Send(ctx context.Context, conn net.Conn, srcPath string, priv []byte, opts SendOptions) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("p2p: bad identity key size %d", len(priv))
	}
	cs := chunkSizeOf(opts.ChunkSize)
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	fileSize := fi.Size()

	// Hash the plaintext stream before the handshake so the receiver can
	// verify. Streaming; never fully buffered.
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 32*1024)); err != nil {
		return err
	}
	var fileHash [32]byte
	copy(fileHash[:], h.Sum(nil))

	ephPriv, ephPub, err := generateEphemeral()
	if err != nil {
		return err
	}
	var base [24]byte
	if _, err := rand.Read(base[:]); err != nil {
		return err
	}
	idPub := []byte(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey))

	hs := &bytes.Buffer{}
	hs.WriteString(Magic)
	hs.WriteByte(Version)
	hs.Write(idPub)
	hs.Write(ephPub)
	hs.Write(base[:])
	var tmp [8]byte
	off := opts.OffsetHint
	if off < 0 {
		off = 0
	}
	binary.BigEndian.PutUint64(tmp[:], uint64(off))
	hs.Write(tmp[:])
	binary.BigEndian.PutUint64(tmp[:], uint64(fileSize))
	hs.Write(tmp[:])
	hs.Write(fileHash[:])
	var c4 [4]byte
	binary.BigEndian.PutUint32(c4[:], uint32(cs))
	hs.Write(c4[:])
	unsigned := hs.Bytes()
	sig := ed25519.Sign(ed25519.PrivateKey(priv), unsigned)
	hs.Write(sig)

	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if _, err := conn.Write(hs.Bytes()); err != nil {
		return ctxOr(err, ctx)
	}
	rsp := make([]byte, rspLen)
	if _, err := io.ReadFull(conn, rsp); err != nil {
		return ctxOr(err, ctx)
	}
	if string(rsp[:4]) != Magic || rsp[4] != Version {
		return fmt.Errorf("%w: bad response magic", ErrProtocol)
	}
	peerID := rsp[5 : 5+32]
	peerEphem := rsp[5+32 : 5+64]
	accepted := int64(binary.BigEndian.Uint64(rsp[5+64 : 5+72]))
	peerSig := rsp[5+72 : 5+72+64]
	if !ed25519.Verify(ed25519.PublicKey(peerID), rsp[:5+72], peerSig) {
		return fmt.Errorf("%w: bad receiver signature", ErrProtocol)
	}
	if accepted < 0 || accepted > fileSize {
		return fmt.Errorf("%w: bad accepted offset", ErrProtocol)
	}
	if accepted%int64(cs) != 0 {
		return fmt.Errorf("%w: unaligned accepted offset", ErrProtocol)
	}

	shared, err := ecdhShared(ephPriv, peerEphem)
	if err != nil {
		return err
	}
	key := sessionKey(shared, ephPub, peerEphem)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return err
	}

	if _, err := f.Seek(accepted, io.SeekStart); err != nil {
		return err
	}
	sent := accepted
	startIdx := uint64(accepted / int64(cs))
	plain := make([]byte, cs)
	ack := make([]byte, 8)
	var hdr [4]byte
	emit := opts.Progress
	if emit != nil {
		emit(sent, fileSize)
	}
	for idx := startIdx; ; idx++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := io.ReadFull(f, plain)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return rerr
		}
		if n == 0 {
			break
		}
		nonce := chunkNonce(base, idx)
		sealed := aead.Seal(nil, nonce[:], plain[:n], nil)
		binary.BigEndian.PutUint32(hdr[:], uint32(len(sealed)))
		if _, err := conn.Write(hdr[:]); err != nil {
			return ctxOr(err, ctx)
		}
		if _, err := conn.Write(sealed); err != nil {
			return ctxOr(err, ctx)
		}
		if _, err := io.ReadFull(conn, ack); err != nil {
			return ctxOr(err, ctx)
		}
		want := sent + int64(n)
		got := int64(binary.BigEndian.Uint64(ack[:]))
		if got == -1 {
			return fmt.Errorf("%w: chunk rejected by peer", ErrProtocol)
		}
		if got != want {
			return fmt.Errorf("%w: ack mismatch want %d got %d", ErrProtocol, want, got)
		}
		sent = want
		if emit != nil {
			emit(sent, fileSize)
		}
		if rerr != nil { // EOF/UnexpectedEOF after a short final chunk
			break
		}
	}
	// FIN.
	binary.BigEndian.PutUint32(hdr[:], 0)
	if _, err := conn.Write(hdr[:]); err != nil {
		return ctxOr(err, ctx)
	}
	final := make([]byte, 9)
	if _, err := io.ReadFull(conn, final); err != nil {
		return ctxOr(err, ctx)
	}
	if final[0] != 0 {
		return ErrHashMismatch
	}
	return nil
}

// Receive accepts one Send stream on conn and writes the plaintext to dstPath.
func Receive(ctx context.Context, conn net.Conn, dstPath string, priv []byte, opts RecvOptions) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("p2p: bad identity key size %d", len(priv))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	hs := make([]byte, hsLen)
	if _, err := io.ReadFull(conn, hs); err != nil {
		return ctxOr(err, ctx)
	}
	if string(hs[:4]) != Magic || hs[4] != Version {
		return fmt.Errorf("%w: bad handshake magic", ErrProtocol)
	}
	p := hs[5:]
	peerID := p[:32]
	peerEphem := p[32:64]
	var base [24]byte
	copy(base[:], p[64:88])
	_ = int64(binary.BigEndian.Uint64(p[88:96])) // offset hint; receiver is authoritative
	fileSize := int64(binary.BigEndian.Uint64(p[96:104]))
	var fileHash [32]byte
	copy(fileHash[:], p[104:136])
	cs := int(binary.BigEndian.Uint32(p[136:140]))
	if cs < MinChunkSize || cs > MaxChunkSize {
		return fmt.Errorf("%w: bad chunk size %d", ErrProtocol, cs)
	}
	if fileSize < 0 {
		return fmt.Errorf("%w: bad file size", ErrProtocol)
	}
	peerSig := p[140:204]
	if !ed25519.Verify(ed25519.PublicKey(peerID), hs[:hsLen-sigLen], peerSig) {
		return fmt.Errorf("%w: bad sender signature", ErrProtocol)
	}

	// Resume: keep the partial file, truncate any torn tail to a boundary.
	var accepted int64
	if fi, err := os.Stat(dstPath); err == nil {
		accepted = fi.Size()
		if accepted > fileSize {
			accepted = 0
		}
		accepted -= accepted % int64(cs)
	}
	ephPriv, ephPub, err := generateEphemeral()
	if err != nil {
		return err
	}
	idPub := []byte(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey))
	rsp := &bytes.Buffer{}
	rsp.WriteString(Magic)
	rsp.WriteByte(Version)
	rsp.Write(idPub)
	rsp.Write(ephPub)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(accepted))
	rsp.Write(tmp[:])
	unsigned := rsp.Bytes()
	rsp.Write(ed25519.Sign(ed25519.PrivateKey(priv), unsigned))
	if _, err := conn.Write(rsp.Bytes()); err != nil {
		return ctxOr(err, ctx)
	}

	shared, err := ecdhShared(ephPriv, peerEphem)
	if err != nil {
		return err
	}
	key := sessionKey(shared, peerEphem, ephPub)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return err
	}

	flag := os.O_CREATE | os.O_WRONLY
	f, err := os.OpenFile(dstPath, flag, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if accepted > 0 {
		if err := f.Truncate(accepted); err != nil {
			return err
		}
	}
	if _, err := f.Seek(accepted, io.SeekStart); err != nil {
		return err
	}

	h := sha256.New()
	if accepted > 0 {
		// Re-hash the kept prefix so the final digest covers the whole file.
		rf, err := os.Open(dstPath)
		if err != nil {
			return err
		}
		if _, err := io.CopyN(h, rf, accepted); err != nil {
			_ = rf.Close()
			return err
		}
		_ = rf.Close()
		if _, err := f.Seek(accepted, io.SeekStart); err != nil {
			return err
		}
	}
	recv := accepted
	idx := uint64(accepted / int64(cs))
	var hdr [4]byte
	ack := make([]byte, 8)
	emit := opts.Progress
	if emit != nil {
		emit(recv, fileSize)
	}
	fail := func() error {
		var fin [9]byte
		fin[0] = 1
		binary.BigEndian.PutUint64(fin[1:], uint64(recv))
		_, _ = conn.Write(fin[:])
		return ErrHashMismatch
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return ctxOr(err, ctx)
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 {
			break // FIN
		}
		if n > uint32(cs+aead.Overhead()+16) {
			return fmt.Errorf("%w: oversize frame %d", ErrProtocol, n)
		}
		sealed := make([]byte, n)
		if _, err := io.ReadFull(conn, sealed); err != nil {
			return ctxOr(err, ctx)
		}
		nonce := chunkNonce(base, idx)
		plain, err := aead.Open(nil, nonce[:], sealed, nil)
		if err != nil {
			// NACK: all-ones ACK so the sender fails fast instead of
			// blocking until its context times out.
			var nack [8]byte
			binary.BigEndian.PutUint64(nack[:], ^uint64(0))
			_, _ = conn.Write(nack[:])
			return fmt.Errorf("%w: chunk %d undecryptable", ErrProtocol, idx)
		}
		if _, err := f.Write(plain); err != nil {
			return err
		}
		h.Write(plain)
		recv += int64(len(plain))
		if recv > fileSize {
			_ = fail()
			return fmt.Errorf("%w: overlong stream", ErrProtocol)
		}
		idx++
		binary.BigEndian.PutUint64(ack[:], uint64(recv))
		if _, err := conn.Write(ack[:]); err != nil {
			return ctxOr(err, ctx)
		}
		if emit != nil {
			emit(recv, fileSize)
		}
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	var fin [9]byte
	if recv != fileSize || digest != fileHash {
		binary.BigEndian.PutUint64(fin[1:], uint64(recv))
		fin[0] = 1
		_, _ = conn.Write(fin[:])
		return ErrHashMismatch
	}
	binary.BigEndian.PutUint64(fin[1:], uint64(recv))
	if _, err := conn.Write(fin[:]); err != nil {
		return ctxOr(err, ctx)
	}
	return nil
}

func ctxOr(err error, ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Listen opens a TCP listener for DirectDrop receives.
func Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// SendFile dials addr and sends srcPath in one connection.
func SendFile(ctx context.Context, addr, srcPath string, priv []byte, opts SendOptions) error {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return Send(ctx, conn, srcPath, priv, opts)
}

// ServeOnce accepts a single connection and receives into dstPath.
func ServeOnce(ctx context.Context, ln net.Listener, dstPath string, priv []byte, opts RecvOptions) error {
	type res struct {
		conn net.Conn
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		defer r.conn.Close()
		return Receive(ctx, r.conn, dstPath, priv, opts)
	}
}
