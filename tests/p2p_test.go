// End-to-end p2p DirectDrop tests over localhost TCP.
package tests_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ghostdrop/internal/p2p"
)

func gdP2PFile(t *testing.T, size int) string {
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

func gdP2PHash(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestP2P_LoopbackHashMatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, senderPriv, err := p2p.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, recvPriv, err := p2p.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	src := gdP2PFile(t, 2<<20+123)
	want := gdP2PHash(t, src)
	dst := filepath.Join(t.TempDir(), "dst.bin")

	ln, err := p2p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	recvDone := make(chan error, 1)
	go func() { recvDone <- p2p.ServeOnce(ctx, ln, dst, recvPriv, p2p.RecvOptions{}) }()
	var sentFinal int64
	if err := p2p.SendFile(ctx, ln.Addr().String(), src, senderPriv, p2p.SendOptions{
		Progress: func(sent, total int64) { sentFinal = sent },
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := <-recvDone; err != nil {
		t.Fatalf("recv: %v", err)
	}
	if got := gdP2PHash(t, dst); got != want {
		t.Fatal("hash mismatch")
	}
	if sentFinal != 2<<20+123 {
		t.Fatalf("bad progress final %d", sentFinal)
	}
}
