package app

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ZipEntry records one archived file.
type ZipEntry struct {
	Name string
	Size int64
	Hash string
}

// ZipSources streams paths (files or dirs) into a zip at dstPath without
// holding file contents in RAM. Returns per-file entries and the hex
// SHA-256 of the zip plaintext.
func ZipSources(paths []string, dstPath string) ([]ZipEntry, string, error) {
	out, err := os.Create(dstPath)
	if err != nil {
		return nil, "", err
	}
	defer out.Close()
	zipH := sha256.New()
	zw := zip.NewWriter(io.MultiWriter(out, zipH))
	var entries []ZipEntry
	addFile := func(full, arc string, fi os.FileInfo) error {
		h := sha256.New()
		f, err := os.Open(full)
		if err != nil {
			return err
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: arc, Method: zip.Deflate})
		if err != nil {
			f.Close()
			return err
		}
		n, err := io.Copy(io.MultiWriter(w, h), f)
		f.Close()
		if err != nil {
			return err
		}
		entries = append(entries, ZipEntry{Name: arc, Size: n, Hash: hex.EncodeToString(h.Sum(nil))})
		return nil
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			zw.Close()
			return nil, "", err
		}
		if !fi.IsDir() {
			if err := addFile(p, filepath.Base(p), fi); err != nil {
				zw.Close()
				return nil, "", err
			}
			continue
		}
		base := filepath.Base(p)
		err = filepath.WalkDir(p, func(full string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(p, full)
			if err != nil {
				return err
			}
			arc := filepath.ToSlash(filepath.Join(base, rel))
			fi, err := d.Info()
			if err != nil {
				return err
			}
			return addFile(full, arc, fi)
		})
		if err != nil {
			zw.Close()
			return nil, "", err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return entries, hex.EncodeToString(zipH.Sum(nil)), nil
}

// UnzipSafe extracts a zip stream into dir, rejecting absolute paths,
// ".." escapes, and symlinks. Verifies nothing leaves dir.
func UnzipSafe(r io.ReaderAt, size int64, dir string) ([]string, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, f := range zr.File {
		if !safeZipPath(f.Name) {
			return nil, fmt.Errorf("unsafe zip entry %q", f.Name)
		}
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("zip symlink refused %q", f.Name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(f.Name))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return nil, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		w, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return nil, err
		}
		_, err = io.Copy(w, rc)
		rc.Close()
		w.Close()
		if err != nil {
			return nil, err
		}
		names = append(names, dst)
	}
	return names, nil
}

// safeZipPath reports whether a zip entry name stays inside the target dir.
func safeZipPath(name string) bool {
	if name == "" || filepath.IsAbs(name) || strings.HasPrefix(name, `\\`) {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return false
	}
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == ".." {
			return false
		}
	}
	return true
}

// IsZipStream reports whether r starts with the zip local-file magic.
func IsZipStream(r io.ReadSeeker) bool {
	var magic [4]byte
	n, _ := r.Read(magic[:])
	_, _ = r.Seek(0, io.SeekStart)
	return n == 4 && magic[0] == 'P' && magic[1] == 'K' && magic[2] == 3 && magic[3] == 4
}
