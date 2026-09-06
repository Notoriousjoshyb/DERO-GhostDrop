package tests_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghostdrop/internal/app"
)

func cliTContext() context.Context {
	return context.Background()
}

func cliTApp(t *testing.T) *app.App {
	t.Helper()
	a, err := app.New(app.Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func cliTFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func cliTHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestCliSendReceiveRoundtrip(t *testing.T) {
	a := cliTApp(t)
	ctx := cliTContext()
	srcDir := t.TempDir()
	content := strings.Repeat("ghostdrop payload line\n", 5000)
	in := cliTFile(t, srcDir, "note.txt", content)
	res, err := a.Send(ctx, app.SendOpts{Paths: []string{in}, Expire: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.DropID, "GD-") {
		t.Fatalf("bad drop id %q", res.DropID)
	}
	if !strings.HasPrefix(res.Link, "ghostdrop://drop/"+res.DropID) {
		t.Fatalf("bad link %q", res.Link)
	}
	if len(res.QRpng) == 0 {
		t.Fatal("empty QR png")
	}
	if err := a.Verify(ctx, res.DropID); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := a.Receive(ctx, res.Link, "", out, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(out, "note.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if cliTHex(got) != cliTHex([]byte(content)) {
		t.Fatal("hash mismatch after roundtrip")
	}
}

func TestAppPasswordDrop(t *testing.T) {
	a := cliTApp(t)
	ctx := cliTContext()
	in := cliTFile(t, t.TempDir(), "secret.txt", "top secret bytes")
	res, err := a.Send(ctx, app.SendOpts{Paths: []string{in}, Password: "s3cr3t-pass", Expire: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest.Mode != "password" {
		t.Fatalf("mode = %q, want password", res.Manifest.Mode)
	}
	out := t.TempDir()
	if err := a.Receive(ctx, res.Link, "s3cr3t-pass", out, nil); err != nil {
		t.Fatalf("correct password failed: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(out, "secret.txt"))
	if string(got) != "top secret bytes" {
		t.Fatal("wrong content")
	}
	if err := a.Receive(ctx, res.Link, "wrong-pass", t.TempDir(), nil); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := a.Receive(ctx, res.Link, "", t.TempDir(), nil); err == nil {
		t.Fatal("missing password accepted")
	}
}

func TestAppCryptoRoundtrip(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "p.bin")
	sealed := filepath.Join(dir, "p.gd")
	back := filepath.Join(dir, "p.out")
	msg := []byte(strings.Repeat("0123456789abcdef", 70000)) // >1 chunk
	if err := os.WriteFile(plain, msg, 0o644); err != nil {
		t.Fatal(err)
	}
	var k [32]byte
	copy(k[:], []byte(strings.Repeat("k", 32)))
	ch, ph, n, err := app.SealFile(plain, sealed, k)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(msg)) || len(ch) != 64 || len(ph) != 64 {
		t.Fatalf("seal meta bad: %d %q %q", n, ch, ph)
	}
	if err := app.OpenFile(sealed, back, k); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(back)
	if cliTHex(got) != cliTHex(msg) {
		t.Fatal("file roundtrip mismatch")
	}
	k[0] ^= 1
	if err := app.OpenFile(sealed, back, k); err == nil {
		t.Fatal("tampered key accepted")
	}
}

func TestAppExpiry(t *testing.T) {
	if _, err := app.ParseExpiry("10m"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ParseExpiry("7d"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ParseExpiry("bogus"); err == nil {
		t.Fatal("bad expiry accepted")
	}
	if _, err := app.ParseExpiry(time.Now().Add(-time.Hour).Format(time.RFC3339)); err == nil {
		t.Fatal("past expiry accepted")
	}
	a := cliTApp(t)
	ctx := cliTContext()
	in := cliTFile(t, t.TempDir(), "e.txt", "expiring")
	res, err := a.Send(ctx, app.SendOpts{Paths: []string{in}, Expire: "10m"})
	if err != nil {
		t.Fatal(err)
	}
	// Force expiry by editing the stored manifest.
	mp := filepath.Join(a.DataDir(), "drops", res.DropID, "manifest.json")
	raw, _ := os.ReadFile(mp)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["expires_at"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	raw, _ = json.Marshal(m)
	if err := os.WriteFile(mp, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.Receive(ctx, res.Link, "", t.TempDir(), nil); err == nil {
		t.Fatal("expired drop received")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestAppRevoke(t *testing.T) {
	a := cliTApp(t)
	ctx := cliTContext()
	in := cliTFile(t, t.TempDir(), "r.txt", "revoke me")
	res, err := a.Send(ctx, app.SendOpts{Paths: []string{in}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Revoke(ctx, res.DropID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Inspect(ctx, res.DropID); err == nil {
		t.Fatal("revoked drop still inspectable")
	}
	if err := a.Receive(ctx, res.Link, "", t.TempDir(), nil); err == nil {
		t.Fatal("revoked drop still receivable")
	}
	drops, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range drops {
		if m.DropID == res.DropID {
			t.Fatal("revoked drop still listed")
		}
	}
}

func TestUriParse(t *testing.T) {
	id := "GD-0123456789AB"
	u := app.FormatDropURI(id, "http://127.0.0.1:8080", "tok123")
	ref, err := app.ParseDropURI(u)
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID != id || ref.Relay != "http://127.0.0.1:8080" || ref.Token != "tok123" {
		t.Fatalf("bad parse: %+v", ref)
	}
	bare, err := app.ParseDropURI(id)
	if err != nil || bare.ID != id {
		t.Fatalf("bare id failed: %+v %v", bare, err)
	}
	for _, bad := range []string{"http://x/y", "ghostdrop://file/abc", "GD-xyz", "GD-0123", ""} {
		if _, err := app.ParseDropURI(bad); err == nil {
			t.Fatalf("bad uri accepted: %q", bad)
		}
	}
	if got := app.GenerateDropID(); len(got) != 15 || !strings.HasPrefix(got, "GD-") {
		t.Fatalf("bad generated id %q", got)
	}
}

func TestFolderZipRoundtrip(t *testing.T) {
	a := cliTApp(t)
	ctx := cliTContext()
	root := t.TempDir()
	want := map[string]string{}
	for name, body := range map[string]string{
		"a.txt":          "alpha",
		"sub/b.txt":      "beta beta",
		"sub/deep/c.bin": strings.Repeat("z", 100000),
	} {
		cliTFile(t, root, name, body)
		want[name] = body
	}
	res, err := a.Send(ctx, app.SendOpts{Paths: []string{root}, Expire: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(root)
	if res.Manifest.FileCount != len(want) {
		t.Fatalf("file_count = %d, want %d", res.Manifest.FileCount, len(want))
	}
	out := t.TempDir()
	if err := a.Receive(ctx, res.Link, "", out, nil); err != nil {
		t.Fatal(err)
	}
	for name, body := range want {
		got, err := os.ReadFile(filepath.Join(out, base, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != body {
			t.Fatalf("content mismatch for %s", name)
		}
	}
	// Traversal safety: malicious names never extract.
	if _, err := app.ParseDropURI(res.Link); err != nil {
		t.Fatal(err)
	}
}

func TestResumeStoreRead(t *testing.T) {
	dir := t.TempDir()
	s, err := app.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := cliTContext()
	payload := []byte(strings.Repeat("chunk-data-", 5000))
	id := "GD-AAAAAAAAAAAA"
	if err := s.Put(ctx, id, strings.NewReader(string(payload)), int64(len(payload)), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rc, err := s.Get(ctx, id, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	rest := new(strings.Builder)
	buf := make([]byte, 8192)
	for {
		n, err := rc.Read(buf)
		rest.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if rest.String() != string(payload)[100:] {
		t.Fatal("resumed bytes mismatch")
	}
	if _, _, err := s.Stat(ctx, id); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorChecks(t *testing.T) {
	a := cliTApp(t)
	checks := a.Doctor(cliTContext())
	if len(checks) != 8 {
		t.Fatalf("got %d checks, want 8", len(checks))
	}
	byName := map[string]app.Check{}
	for _, c := range checks {
		byName[c.Name] = c
	}
	for _, name := range []string{"CONFIG", "DATABASE", "CRYPTO", "DERO", "WALLET", "STORAGE", "NETWORK", "RELAY"} {
		c, ok := byName[name]
		if !ok {
			t.Fatalf("missing check %s", name)
		}
		if !c.OK && c.Hint == "" {
			t.Fatalf("failing check %s has no fix hint", name)
		}
	}
	for _, name := range []string{"CONFIG", "DATABASE", "CRYPTO", "STORAGE"} {
		if !byName[name].OK {
			t.Fatalf("check %s failed in sandbox: %s", name, byName[name].Detail)
		}
	}
}
