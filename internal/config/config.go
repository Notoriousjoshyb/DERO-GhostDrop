// Package config loads Ghostdrop configuration from OS-native paths with
// GHOSTDROP_* environment overrides.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"ghostdrop/internal/platform"
)

// Config is the user-tunable Ghostdrop configuration.
type Config struct {
	RelayEndpoint   string `json:"relay_endpoint"`
	DefaultExpiry   string `json:"default_expiry"`
	StorageProvider string `json:"storage_provider"`
	DeroEndpoint    string `json:"dero_endpoint"`
	WalletEndpoint  string `json:"wallet_endpoint"`
	Privacy         string `json:"privacy"`
	GhostDefault    bool   `json:"ghost_default"`
	DownloadDir     string `json:"download_dir"`
	Notifications   bool   `json:"notifications"`
	Theme           string `json:"theme"`
	AutoDelete      bool   `json:"auto_delete"`
}

// Defaults returns the default configuration.
func Defaults() Config {
	return Config{
		RelayEndpoint:   "http://127.0.0.1:8080",
		DefaultExpiry:   "72h",
		StorageProvider: "local",
		DeroEndpoint:    "http://127.0.0.1:10102",
		WalletEndpoint:  "http://127.0.0.1:10103",
		Privacy:         "standard",
		GhostDefault:    false,
		DownloadDir:     platform.DownloadDir(),
		Notifications:   true,
		Theme:           "dark",
		AutoDelete:      true,
	}
}

// ExpiryDuration parses DefaultExpiry ("72h", "7d", "30m", ...).
// A trailing "d" means days; otherwise time.ParseDuration syntax applies.
func (c Config) ExpiryDuration() (time.Duration, error) {
	s := c.DefaultExpiry
	if len(s) > 1 && (s[len(s)-1] == 'd' || s[len(s)-1] == 'D') {
		n, err := strconv.Atoi(s[:len(s)-1])
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Load reads the OS-native config file (if present) over defaults, then
// applies GHOSTDROP_* environment overrides.
func Load() (Config, error) { return LoadFrom(platform.ConfigFile()) }

// LoadFrom reads path over defaults plus environment overrides.
// A missing file is not an error.
func LoadFrom(path string) (Config, error) {
	cfg := Defaults()
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		var file Config
		if err := json.Unmarshal(raw, &file); err != nil {
			return Config{}, err
		}
		merge(&cfg, file)
	} else if err != nil && !os.IsNotExist(err) {
		return Config{}, err
	}
	applyEnv(&cfg)
	return cfg, nil
}

// Save writes the config to the OS-native config file.
func (c Config) Save() error { return c.SaveTo(platform.ConfigFile()) }

// SaveTo writes the config to path atomically (0600).
func (c Config) SaveTo(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// merge overlays non-zero file values onto cfg.
func merge(cfg *Config, file Config) {
	if file.RelayEndpoint != "" {
		cfg.RelayEndpoint = file.RelayEndpoint
	}
	if file.DefaultExpiry != "" {
		cfg.DefaultExpiry = file.DefaultExpiry
	}
	if file.StorageProvider != "" {
		cfg.StorageProvider = file.StorageProvider
	}
	if file.DeroEndpoint != "" {
		cfg.DeroEndpoint = file.DeroEndpoint
	}
	if file.WalletEndpoint != "" {
		cfg.WalletEndpoint = file.WalletEndpoint
	}
	if file.Privacy != "" {
		cfg.Privacy = file.Privacy
	}
	cfg.GhostDefault = file.GhostDefault
	if file.DownloadDir != "" {
		cfg.DownloadDir = file.DownloadDir
	}
	cfg.Notifications = file.Notifications
	if file.Theme != "" {
		cfg.Theme = file.Theme
	}
	cfg.AutoDelete = file.AutoDelete
}

// applyEnv overlays GHOSTDROP_* variables. Booleans parse via ParseBool.
func applyEnv(cfg *Config) {
	if v := os.Getenv("GHOSTDROP_RELAY_ENDPOINT"); v != "" {
		cfg.RelayEndpoint = v
	}
	if v := os.Getenv("GHOSTDROP_DEFAULT_EXPIRY"); v != "" {
		cfg.DefaultExpiry = v
	}
	if v := os.Getenv("GHOSTDROP_STORAGE_PROVIDER"); v != "" {
		cfg.StorageProvider = v
	}
	if v := os.Getenv("GHOSTDROP_DERO_ENDPOINT"); v != "" {
		cfg.DeroEndpoint = v
	}
	if v := os.Getenv("GHOSTDROP_WALLET_ENDPOINT"); v != "" {
		cfg.WalletEndpoint = v
	}
	if v := os.Getenv("GHOSTDROP_PRIVACY"); v != "" {
		cfg.Privacy = v
	}
	if v := os.Getenv("GHOSTDROP_GHOST_DEFAULT"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.GhostDefault = b
		}
	}
	if v := os.Getenv("GHOSTDROP_DOWNLOAD_DIR"); v != "" {
		cfg.DownloadDir = v
	}
	if v := os.Getenv("GHOSTDROP_NOTIFICATIONS"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Notifications = b
		}
	}
	if v := os.Getenv("GHOSTDROP_THEME"); v != "" {
		cfg.Theme = v
	}
	if v := os.Getenv("GHOSTDROP_AUTO_DELETE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.AutoDelete = b
		}
	}
}
