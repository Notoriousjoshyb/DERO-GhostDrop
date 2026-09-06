// Package platform resolves OS-native filesystem locations for Ghostdrop.
//
// One Go codebase targets Windows 11, Linux, and macOS; all OS path
// differences stay behind the adapters in this package.
package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// AppName is the human-facing application directory name on Windows/macOS.
const AppName = "Ghostdrop"

// ConfigDir returns the OS-native directory for user configuration:
// Windows %AppData%/Ghostdrop, macOS ~/Library/Application Support/Ghostdrop,
// Linux $XDG_CONFIG_HOME/ghostdrop or ~/.config/ghostdrop.
func ConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, AppName)
		}
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "AppData", "Roaming", AppName)
		}
	case "darwin":
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "Library", "Application Support", AppName)
		}
	default:
		if v := os.Getenv("XDG_CONFIG_HOME"); v != "" && filepath.IsAbs(v) {
			return filepath.Join(v, "ghostdrop")
		}
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, ".config", "ghostdrop")
		}
	}
	return filepath.Join(".", "ghostdrop-config")
}

// DataDir returns the OS-native directory for application data (database,
// local drop payloads, manifests).
func DataDir() string {
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, AppName)
		}
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "AppData", "Roaming", AppName)
		}
	case "darwin":
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "Library", "Application Support", AppName)
		}
	default:
		if v := os.Getenv("XDG_DATA_HOME"); v != "" && filepath.IsAbs(v) {
			return filepath.Join(v, "ghostdrop")
		}
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, ".local", "share", "ghostdrop")
		}
	}
	return filepath.Join(".", "ghostdrop-data")
}

// DownloadDir returns the OS-native user downloads directory.
func DownloadDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return filepath.Join(h, "Downloads")
	}
	return filepath.Join(".", "downloads")
}

// ConfigFile returns the default config.json path.
func ConfigFile() string { return filepath.Join(ConfigDir(), "config.json") }

// DBFile returns the default SQLite database path.
func DBFile() string { return filepath.Join(DataDir(), "ghostdrop.db") }

// ManifestDir returns the default directory for persisted manifests.
func ManifestDir() string { return filepath.Join(DataDir(), "manifests") }

// EnsureDir creates dir (and parents) if missing.
func EnsureDir(dir string) error { return os.MkdirAll(dir, 0o700) }
