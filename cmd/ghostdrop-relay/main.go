// Command ghostdrop-relay runs and inspects the Ghostdrop relay server.
//
// Usage:
//
//	ghostdrop-relay start [--addr 127.0.0.1:8080] [--data-dir DIR] [--quota 10GB] [--rate-limit 100] [--json]
//	ghostdrop-relay status [--relay http://127.0.0.1:8080] [--json]
//	ghostdrop-relay config [--addr ...] [--data-dir ...] [--quota ...] [--json]
//	ghostdrop-relay stats [--relay http://127.0.0.1:8080] [--json]
//
// The relay stores opaque ciphertext blobs only; it never logs content,
// keys, or tokens.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"ghostdrop/internal/platform"
	"ghostdrop/internal/relay"
)

const usage = `ghostdrop-relay — Ghostdrop relay server

Usage:
  ghostdrop-relay start [--addr ADDR] [--data-dir DIR] [--quota BYTES] [--rate-limit RPS] [--json]
  ghostdrop-relay status [--relay URL] [--json]
  ghostdrop-relay config [--addr ADDR] [--data-dir DIR] [--quota BYTES] [--json]
  ghostdrop-relay stats [--relay URL] [--json]

Env overrides: GHOSTDROP_RELAY_ADDR, GHOSTDROP_DATA_DIR, GHOSTDROP_QUOTA, GHOSTDROP_RELAY_URL
`

type options struct {
	addr      string
	dataDir   string
	quota     int64
	quotaSet  bool
	rateLimit float64
	relayURL  string
	jsonOut   bool
}

func defaultOptions() options {
	return options{
		addr:     getenv("GHOSTDROP_RELAY_ADDR", "127.0.0.1:8080"),
		dataDir:  getenv("GHOSTDROP_DATA_DIR", platform.DataDir()),
		relayURL: getenv("GHOSTDROP_RELAY_URL", "http://127.0.0.1:8080"),
		quota:    parseBytes(getenv("GHOSTDROP_QUOTA", "0")),
	}
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "start":
		runStart(parseStart(os.Args[2:]))
	case "status":
		runStatus(parseCommon(os.Args[2:]))
	case "config":
		runConfig(parseStart(os.Args[2:]))
	case "stats":
		runStats(parseCommon(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func parseStart(args []string) options {
	o := defaultOptions()
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			o.addr = nextArg(args, &i, "--addr")
		case "--data-dir":
			o.dataDir = nextArg(args, &i, "--data-dir")
		case "--quota":
			o.quota = parseBytes(nextArg(args, &i, "--quota"))
			o.quotaSet = true
		case "--rate-limit":
			v, err := strconv.ParseFloat(nextArg(args, &i, "--rate-limit"), 64)
			if err != nil || v < 0 {
				fatal("invalid --rate-limit")
			}
			o.rateLimit = v
		case "--json":
			o.jsonOut = true
		default:
			fatal("unknown flag " + args[i])
		}
	}
	return o
}

func parseCommon(args []string) options {
	o := defaultOptions()
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--relay":
			o.relayURL = nextArg(args, &i, "--relay")
		case "--json":
			o.jsonOut = true
		default:
			fatal("unknown flag " + args[i])
		}
	}
	return o
}

func nextArg(args []string, i *int, flag string) string {
	*i++
	if *i >= len(args) {
		fatal("missing value for " + flag)
	}
	return args[*i]
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "ghostdrop-relay: "+msg)
	os.Exit(2)
}

// parseBytes accepts plain integers plus B/KB/MB/GB/TB suffixes.
func parseBytes(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := int64(1)
	up := strings.ToUpper(s)
	for _, suf := range []struct {
		s string
		m int64
	}{{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(up, suf.s) {
			mult = suf.m
			s = s[:len(s)-len(suf.s)]
			break
		}
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v < 0 {
		fatal("invalid byte size " + strconv.Quote(s))
	}
	return v * mult
}

func humanBytes(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	u := ""
	for _, u2 := range units {
		u = u2
		v /= 1024
		if v < 1024 {
			break
		}
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + " " + u
}

func emitJSON(v any) {
	raw, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(raw))
}

// --- subcommands ---

func runStart(o options) {
	cfg := relay.Config{Addr: o.addr, DataDir: o.dataDir, QuotaBytes: o.quota, RateLimit: o.rateLimit}
	srv, err := relay.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ghostdrop-relay: "+err.Error())
		os.Exit(1)
	}
	if o.jsonOut {
		emitJSON(map[string]any{
			"ok": true, "online": true, "addr": o.addr,
			"data_dir": o.dataDir, "quota_bytes": o.quota,
		})
	} else {
		fmt.Println("Ghostdrop Relay — ONLINE")
		fmt.Println("  listening:  " + o.addr)
		fmt.Println("  data dir:   " + o.dataDir)
		if o.quota > 0 {
			fmt.Println("  quota:      " + humanBytes(o.quota))
		} else {
			fmt.Println("  quota:      unlimited")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()
	if err := srv.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "ghostdrop-relay: "+err.Error())
		os.Exit(1)
	}
}

func runConfig(o options) {
	if o.jsonOut {
		emitJSON(map[string]any{
			"ok": true, "addr": o.addr, "data_dir": o.dataDir,
			"quota_bytes": o.quota, "rate_limit": o.rateLimit,
			"relay_url": o.relayURL,
		})
		return
	}
	fmt.Println("Ghostdrop Relay config")
	fmt.Println("  addr:       " + o.addr)
	fmt.Println("  data dir:   " + o.dataDir)
	if o.quota > 0 {
		fmt.Println("  quota:      " + humanBytes(o.quota))
	} else {
		fmt.Println("  quota:      unlimited")
	}
	if o.rateLimit > 0 {
		fmt.Println("  rate limit: " + strconv.FormatFloat(o.rateLimit, 'f', -1, 64) + " req/s")
	} else {
		fmt.Println("  rate limit: unlimited")
	}
	fmt.Println("  relay url:  " + o.relayURL)
}

// fetchJSON GETs path and decodes a JSON object.
func fetchJSON(base, path string) (map[string]any, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+path, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(raw, &out)
	return out, resp.StatusCode, nil
}

func num(m map[string]any, k string) int64 {
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}

func runStatus(o options) {
	health, code, err := fetchJSON(o.relayURL, "/api/v1/health")
	if err != nil || code != http.StatusOK {
		if o.jsonOut {
			emitJSON(map[string]any{"ok": false, "online": false, "relay_url": o.relayURL})
			return
		}
		fmt.Println("Ghostdrop Relay — OFFLINE")
		fmt.Println("  relay url:  " + o.relayURL)
		fmt.Println("  hint:       run `ghostdrop-relay start` to launch a relay")
		return
	}
	stats, _, _ := fetchJSON(o.relayURL, "/api/v1/stats")
	if stats == nil {
		stats = map[string]any{}
	}
	online, _ := health["ok"].(bool)
	if !online {
		online = code == http.StatusOK
	}
	if o.jsonOut {
		emitJSON(map[string]any{
			"ok": true, "online": true, "relay_url": o.relayURL,
			"drops": num(stats, "drops"), "bytes_stored": num(stats, "bytes_stored"),
			"bytes_received": num(stats, "bytes_received"), "bytes_served": num(stats, "bytes_served"),
			"uptime_seconds": num(stats, "uptime_seconds"),
		})
		return
	}
	printBanner(o.relayURL, stats)
}

func runStats(o options) {
	stats, code, err := fetchJSON(o.relayURL, "/api/v1/stats")
	if err != nil || code != http.StatusOK || stats == nil {
		if o.jsonOut {
			emitJSON(map[string]any{"ok": false, "online": false, "relay_url": o.relayURL})
			return
		}
		fmt.Println("Ghostdrop Relay — OFFLINE")
		fmt.Println("  relay url:  " + o.relayURL)
		return
	}
	if o.jsonOut {
		stats["ok"] = true
		stats["relay_url"] = o.relayURL
		emitJSON(stats)
		return
	}
	printBanner(o.relayURL, stats)
}

// printBanner renders the ONLINE banner with stored-drops/storage/transfer/uptime.
func printBanner(relayURL string, stats map[string]any) {
	drops := num(stats, "drops")
	stored := num(stats, "bytes_stored")
	up := num(stats, "bytes_received")
	down := num(stats, "bytes_served")
	uptime := time.Duration(num(stats, "uptime_seconds")) * time.Second
	fmt.Println("Ghostdrop Relay — ONLINE")
	fmt.Println("  relay url:    " + relayURL)
	fmt.Println("  stored drops: " + strconv.FormatInt(drops, 10))
	fmt.Println("  storage:      " + humanBytes(stored))
	fmt.Println("  transfer:     up " + humanBytes(up) + " / down " + humanBytes(down))
	fmt.Println("  uptime:       " + uptime.String())
}
