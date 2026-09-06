package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mkFile(t *testing.T, size int) string {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "src.bin")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func shaFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// loopbackTransfer runs one SendFile->ServeOnce exchange over 127.0.0.1.
func loopbackTransfer(ctx context.Context, t *testing.T, src, dst string, senderPriv, recvPriv []byte, sendOpts SendOptions, recvOpts RecvOptions) (sendErr, recvErr error) {
	t.Helper()
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	recvDone := make(chan error, 1)
	go func() {
		recvDone <- ServeOnce(ctx, ln, dst, recvPriv, recvOpts)
	}()
	sendErr = SendFile(ctx, ln.Addr().String(), src, senderPriv, sendOpts)
	recvErr = <-recvDone
	return sendErr, recvErr
}

func TestLoopbackSmall(t *testing.T) {
	ctx := context.Background()
	sPub, sPriv, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, rPriv, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_ = sPub
	src := mkFile(t, 100*1024+37) // non-multiple of chunk size
	dst := filepath.Join(t.TempDir(), "dst.bin")
	var sentFinal, recvFinal int64
	var total int64 = 100*1024 + 37
	if serr, rerr := loopbackTransfer(ctx, t, src, dst, sPriv, rPriv,
		SendOptions{Progress: func(s, tot int64) { sentFinal = s }},
		RecvOptions{Progress: func(r, tot int64) { recvFinal = r }}); serr != nil || rerr != nil {
		t.Fatalf("send=%v recv=%v", serr, rerr)
	}
	if shaFile(t, src) != shaFile(t, dst) {
		t.Fatal("hash mismatch")
	}
	if sentFinal != total || recvFinal != total {
		t.Fatalf("progress finals %d/%d want %d", sentFinal, recvFinal, total)
	}
}

func TestLoopbackEmpty(t *testing.T) {
	ctx := context.Background()
	_, sPriv, _ := GenerateIdentity()
	_, rPriv, _ := GenerateIdentity()
	src := mkFile(t, 0)
	dst := filepath.Join(t.TempDir(), "dst.bin")
	if serr, rerr := loopbackTransfer(ctx, t, src, dst, sPriv, rPriv, SendOptions{}, RecvOptions{}); serr != nil || rerr != nil {
		t.Fatalf("send=%v recv=%v", serr, rerr)
	}
	if shaFile(t, src) != shaFile(t, dst) {
		t.Fatal("hash mismatch")
	}
}

func TestInterruptResume32MiB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 32MiB resume in short mode")
	}
	const size = 32 << 20
	src := mkFile(t, size)
	want := shaFile(t, src)
	dst := filepath.Join(t.TempDir(), "dst.bin")
	_, sPriv, _ := GenerateIdentity()
	_, rPriv, _ := GenerateIdentity()

	// Round 1: cancel mid-transfer from the sender progress callback.
	ctx1, cancel1 := context.WithCancel(context.Background())
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	recvDone := make(chan error, 1)
	go func() { recvDone <- ServeOnce(ctx1, ln, dst, rPriv, RecvOptions{}) }()
	serr := SendFile(ctx1, ln.Addr().String(), src, sPriv, SendOptions{
		Progress: func(sent, total int64) {
			if sent >= 5<<20 {
				cancel1()
			}
		},
	})
	rerr := <-recvDone
	if serr == nil || rerr == nil {
		t.Fatalf("expected both sides to abort, send=%v recv=%v", serr, rerr)
	}
	part, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("no partial file kept: %v", err)
	}
	if part.Size() == 0 || part.Size() >= size {
		t.Fatalf("bad partial size %d", part.Size())
	}

	// Round 2: resume to completion with fresh contexts.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel2()
	recvDone2 := make(chan error, 1)
	go func() { recvDone2 <- ServeOnce(ctx2, ln, dst, rPriv, RecvOptions{}) }()
	if serr := SendFile(ctx2, ln.Addr().String(), src, sPriv, SendOptions{}); serr != nil {
		t.Fatalf("resume send: %v", serr)
	}
	if rerr := <-recvDone2; rerr != nil {
		t.Fatalf("resume recv: %v", rerr)
	}
	if got := shaFile(t, dst); got != want {
		t.Fatal("hash mismatch after resume")
	}
}

// flipConn flips one bit at absolute write-offset skip on the sender side.
type flipConn struct {
	net.Conn
	skip    int
	flipped bool
}

func (c *flipConn) Write(p []byte) (int, error) {
	if c.flipped || c.skip >= len(p) {
		if !c.flipped {
			c.skip -= len(p)
		}
		return c.Conn.Write(p)
	}
	q := bytes.Clone(p)
	q[c.skip] ^= 0xFF
	c.flipped = true
	c.skip = 0
	return c.Conn.Write(q)
}

func TestTamperFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, sPriv, _ := GenerateIdentity()
	_, rPriv, _ := GenerateIdentity()
	src := mkFile(t, 3*1024+11)
	dst := filepath.Join(t.TempDir(), "dst.bin")

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	recvDone := make(chan error, 1)
	go func() { recvDone <- Receive(ctx, c2, dst, rPriv, RecvOptions{}); cancel() }()
	// Flip a bit inside the first sealed chunk (past HS + 4-byte length).
	// Receiver NACKs; cancel() above unblocks the sender immediately.
	serr := Send(ctx, &flipConn{Conn: c1, skip: hsLen + 4 + 5}, src, sPriv, SendOptions{})
	rerr := <-recvDone
	if serr == nil && rerr == nil {
		t.Fatal("expected tamper to fail the transfer")
	}
}

func TestBadHandshakeSigFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, sPriv, _ := GenerateIdentity()
	_, rPriv, _ := GenerateIdentity()
	src := mkFile(t, 1024)
	dst := filepath.Join(t.TempDir(), "dst.bin")

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	recvDone := make(chan error, 1)
	go func() { recvDone <- Receive(ctx, c2, dst, rPriv, RecvOptions{}); cancel() }()
	// Corrupt the handshake signature. Receiver rejects; cancel() above
	// unblocks the sender immediately.
	serr := Send(ctx, &flipConn{Conn: c1, skip: hsLen - 10}, src, sPriv, SendOptions{})
	rerr := <-recvDone
	if rerr == nil {
		t.Fatalf("expected receiver to reject bad signature (send=%v)", serr)
	}
}
