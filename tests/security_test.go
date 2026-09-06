package tests

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"ghostdrop/internal/security"
)

func TestSecuritySanitizeAndExec(t *testing.T) {
	if security.SanitizeFilename("../evil.txt") == "../evil.txt" {
		t.Fatal("traversal survived sanitize")
	}
	if !security.ExecutableWarn("payload.exe") {
		t.Fatal("exe should warn")
	}
	if security.ExecutableWarn("readme.txt") {
		t.Fatal("txt should not warn")
	}
	if err := security.CheckPasswordStrength("abc"); err == nil {
		t.Fatal("weak password accepted")
	}
}

func TestSecurityZipSlipGuard(t *testing.T) {
	dir := t.TempDir()
	zpath := filepath.Join(dir, "z.zip")
	f, _ := os.Create(zpath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("../evil.txt")
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	_ = f.Close()
	if err := security.ExtractZipSafe(zpath, filepath.Join(dir, "out")); err == nil {
		t.Fatal("zip-slip accepted")
	}
	if _, err := security.TokenGen(); err != nil {
		t.Fatal(err)
	}
}
