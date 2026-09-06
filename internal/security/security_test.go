package security

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityTraversalBlocked(t *testing.T) {
	dir := t.TempDir()
	for _, evil := range []string{"../evil", "..\\evil", "../../etc/passwd", "/abs/path"} {
		if _, err := SafeJoin(dir, evil); err != nil {
			continue
		} else {
			// SafeJoin sanitizes to a basename; ensure result stays inside dir.
			out, _ := SafeJoin(dir, evil)
			rel, _ := filepath.Rel(dir, out)
			if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("traversal escaped: %q -> %q", evil, out)
			}
		}
	}
	// Raw ".." must sanitize, never escape.
	got, err := SafeJoin(dir, "../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(got) != dir {
		t.Fatalf("escaped dir: %q", got)
	}
	if SanitizeFilename("../x") == "../x" {
		t.Fatal("sanitize kept traversal")
	}
}

func TestSecurityManifestCap(t *testing.T) {
	if err := ValidateManifestSize(MaxManifestSize); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestSize(MaxManifestSize + 1); err == nil {
		t.Fatal("oversized manifest accepted")
	}
	if err := ValidateManifest(make([]byte, MaxManifestSize+1)); err == nil {
		t.Fatal("oversized manifest bytes accepted")
	}
}

func TestSecurityZipSlipBlocked(t *testing.T) {
	dir := t.TempDir()
	zpath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zpath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("../../evil.txt")
	_, _ = w.Write([]byte("pwn"))
	_ = zw.Close()
	_ = f.Close()
	dest := filepath.Join(dir, "out")
	if err := ExtractZipSafe(zpath, dest); err == nil {
		t.Fatal("zip-slip not blocked")
	}
}

func TestSecurityTokenUnique(t *testing.T) {
	a, err := TokenGen()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 64 || len(b) != 64 || a == b {
		t.Fatalf("bad tokens %q %q", a, b)
	}
}

func TestSecurityPasswordAndExec(t *testing.T) {
	if err := PasswordStrength("weak"); err == nil {
		t.Fatal("weak password accepted")
	}
	if err := CheckPasswordStrength("Str0ng!Passphrase#9"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"run.exe", "install.msi", "s.ps1", "x.jar", "m.docm", "a.JS"} {
		if !ExecutableWarn(name) {
			t.Fatalf("%q should warn", name)
		}
	}
	if ExecutableWarn("notes.txt") {
		t.Fatal("txt should not warn")
	}
}
