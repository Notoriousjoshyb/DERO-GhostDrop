// Package security guards filenames, archives, tokens, and size caps.
package security

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxManifestSize caps a serialized manifest at 1MiB.
	MaxManifestSize = 1 << 20
	// MaxFilenameBytes caps a single filename at 255 bytes.
	MaxFilenameBytes = 255
	// TokenBytes is the entropy size for GenerateToken/TokenGen (32B → 64 hex).
	TokenBytes = 32
)

// ExecutableExts lists extensions that trigger an executable warning.
var ExecutableExts = map[string]bool{
	".exe": true, ".msi": true, ".ps1": true, ".bat": true,
	".cmd": true, ".sh": true, ".app": true, ".pkg": true,
	".dmg": true, ".scr": true, ".com": true, ".jar": true,
	".vbs": true, ".js": true,
}

// MacroOfficeExts are office formats that may carry macros.
var MacroOfficeExts = map[string]bool{
	".docm": true, ".xlsm": true, ".pptm": true, ".dotm": true,
	".xltm": true, ".potm": true,
}

// SanitizeFilename strips directories, control characters, and traversal,
// returning a safe base name. Empty or fully-stripped input yields "file".
func SanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	var b strings.Builder
	b.Grow(len(base))
	for _, r := range base {
		if r < 0x20 || r == 0x7f {
			continue
		}
		switch r {
		case '/', ':', '*', '?', '"', '<', '>', '|':
			b.WriteRune('_')
		default:
			if unicode.IsPrint(r) || r == ' ' {
				b.WriteRune(r)
			} else {
				b.WriteRune('_')
			}
		}
	}
	out := strings.TrimSpace(b.String())
	out = strings.Trim(out, ".")
	if out == "" || out == "." || out == ".." {
		return "file"
	}
	// Enforce byte cap.
	for len(out) > MaxFilenameBytes {
		// Trim a full rune at the end.
		_, size := utf8.DecodeLastRuneInString(out)
		if size <= 0 {
			out = out[:MaxFilenameBytes]
			break
		}
		out = out[:len(out)-size]
		out = strings.TrimRight(out, ". ")
		if out == "" {
			return "file"
		}
	}
	return out
}

// ValidateFilename rejects over-long or empty names.
func ValidateFilename(name string) error {
	if name == "" {
		return fmt.Errorf("security: empty filename")
	}
	if len(name) > MaxFilenameBytes {
		return fmt.Errorf("security: filename exceeds %d bytes", MaxFilenameBytes)
	}
	if name != SanitizeFilename(name) {
		return fmt.Errorf("security: filename %q is not sanitized", name)
	}
	return nil
}

// SafeJoin joins destDir with an untrusted name, blocking traversal.
// The result is guaranteed to stay inside destDir.
func SafeJoin(destDir, name string) (string, error) {
	if destDir == "" {
		return "", fmt.Errorf("security: empty destination")
	}
	clean := SanitizeFilename(name)
	if err := ValidateFilename(clean); err != nil {
		return "", err
	}
	joined := filepath.Join(destDir, clean)
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return "", err
	}
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absDest, absJoined)
	if err != nil {
		return "", fmt.Errorf("security: traversal blocked: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("security: traversal blocked: %q", name)
	}
	return absJoined, nil
}

// ValidateManifestSize rejects manifests larger than MaxManifestSize.
func ValidateManifestSize(size int64) error {
	if size < 0 {
		return fmt.Errorf("security: negative manifest size")
	}
	if size > MaxManifestSize {
		return fmt.Errorf("security: manifest %d bytes exceeds %d cap", size, MaxManifestSize)
	}
	return nil
}

// ValidateManifest validates raw manifest bytes against the size cap.
func ValidateManifest(data []byte) error {
	return ValidateManifestSize(int64(len(data)))
}

// ExtractZipSafe extracts zipPath into destDir, blocking zip-slip entries,
// absolute paths, symlinks, and oversized members. Streams file contents.
func ExtractZipSafe(zipPath, destDir string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	var totalUncompressed uint64
	for _, f := range zr.File {
		// Block absolute paths and traversal before joining.
		if filepath.IsAbs(f.Name) {
			return fmt.Errorf("security: zip-slip blocked: %q", f.Name)
		}
		// zip uses forward slashes; reject ".." segments.
		parts := strings.Split(filepath.ToSlash(f.Name), "/")
		for _, p := range parts {
			if p == ".." {
				return fmt.Errorf("security: zip-slip blocked: %q", f.Name)
			}
		}
		// Reject symlinks.
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("security: symlink blocked: %q", f.Name)
		}
		target := filepath.Join(absDest, filepath.FromSlash(f.Name))
		rel, err := filepath.Rel(absDest, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("security: zip-slip blocked: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		totalUncompressed += f.UncompressedSize64
		if totalUncompressed > 1<<31 { // 2GiB bomb guard
			return fmt.Errorf("security: zip bomb suspected")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			_ = rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(rc, 1<<31))
		closeErr1 := out.Close()
		closeErr2 := rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr1 != nil {
			return closeErr1
		}
		if closeErr2 != nil {
			return closeErr2
		}
	}
	return nil
}

// GenerateToken returns 32 random bytes as 64 lowercase hex chars.
func GenerateToken() (string, error) {
	var b [TokenBytes]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("security: rand: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// TokenGen is an alias of GenerateToken.
func TokenGen() (string, error) { return GenerateToken() }

// NewToken is an alias of GenerateToken.
func NewToken() (string, error) { return GenerateToken() }

// CheckPasswordStrength rejects weak passphrases.
// Rules: ≥8 chars, and at least 3 of {lower, upper, digit, symbol}.
func CheckPasswordStrength(pw string) error {
	if utf8.RuneCountInString(pw) < 8 {
		return fmt.Errorf("security: password too short (min 8 chars)")
	}
	var lower, upper, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			if unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.IsSpace(r) {
				symbol = true
			} else {
				symbol = true
			}
		}
	}
	classes := 0
	for _, ok := range []bool{lower, upper, digit, symbol} {
		if ok {
			classes++
		}
	}
	if classes < 3 {
		return fmt.Errorf("security: password needs 3 of 4 classes (lower, upper, digit, symbol)")
	}
	return nil
}

// PasswordStrength is an alias of CheckPasswordStrength.
func PasswordStrength(pw string) error { return CheckPasswordStrength(pw) }

// ExecutableWarn reports whether name has a risky executable extension,
// including macro-capable office formats. Case-insensitive.
func ExecutableWarn(name string) bool {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(name)))
	if ExecutableExts[ext] {
		return true
	}
	if MacroOfficeExts[ext] {
		return true
	}
	// Trailing-dot / trailing-space Windows quirk: "file.exe." trims to exe.
	trimmed := strings.TrimRight(strings.ToLower(name), ". ")
	if trimmed != strings.ToLower(name) {
		if ExecutableExts[strings.ToLower(filepath.Ext(trimmed))] {
			return true
		}
	}
	return false
}

// IsExecutableRisk is an alias of ExecutableWarn.
func IsExecutableRisk(name string) bool { return ExecutableWarn(name) }
