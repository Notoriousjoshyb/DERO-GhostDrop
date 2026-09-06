// Command ghostdrop-cli is the Ghostdrop file-transfer CLI.
//
// Verbs: send receive inspect verify revoke list status doctor.
// Secrets (passwords, keys) are never printed or logged.
package main

import (
	"context"
	"errors"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghostdrop/internal/app"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	verb, args := os.Args[1], os.Args[2:]
	var err error
	switch verb {
	case "send":
		err = cmdSend(ctx, args)
	case "receive":
		err = cmdReceive(ctx, args)
	case "inspect":
		err = cmdInspect(ctx, args)
	case "verify":
		err = cmdVerify(ctx, args)
	case "revoke":
		err = cmdRevoke(ctx, args)
	case "list":
		err = cmdList(ctx, args)
	case "status":
		err = cmdStatus(ctx, args)
	case "doctor":
		err = cmdDoctor(ctx, args)
	case "-h", "-help", "--help", "help":
		usage()
	}
	if err != nil {
		var fe *flagError
		switch {
		case errors.As(err, &fe):
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(exitUsage)
		case errors.Is(err, flag.ErrHelp):
			os.Exit(exitOK)
		default:
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(exitFail)
		}
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ghostdrop-cli — privacy-first file transfer

Usage:
  ghostdrop-cli send [flags] <path>...        seal paths into a drop
  ghostdrop-cli receive [flags] <drop-url>     open a drop into a directory
  ghostdrop-cli inspect [--json] <id|url>      show drop manifest
  ghostdrop-cli verify <id|url>                re-verify hashes + signature
  ghostdrop-cli revoke <id|url>                delete a drop
  ghostdrop-cli list [--json]                  list known drops
  ghostdrop-cli status [--json] <id|url>       one-line drop health
  ghostdrop-cli doctor [--json]                environment health checks

Send flags: --to --expire 10m/1h/24h/7d/RFC3339/date --anonymous --password
  --price --paid-to --relay --one-time --demo --json
Receive flags: --out --password
Env: GHOSTDROP_DATA_DIR GHOSTDROP_RELAY GHOSTDROP_DAEMON GHOSTDROP_WALLET
`)
}

func openApp(relayOverride string) (*app.App, error) {
	relay := relayOverride
	if relay == "" {
		relay = os.Getenv("GHOSTDROP_RELAY")
	}
	return app.New(app.Options{DataDir: os.Getenv("GHOSTDROP_DATA_DIR"), RelayURL: relay})
}

func stderrProgress(prefix string) func(written, total int64) {
	return func(written, total int64) {
		if total > 0 {
			fmt.Fprintf(os.Stderr, "\r%s %d/%d bytes (%.1f%%)", prefix, written, total, 100*float64(written)/float64(total))
		} else {
			fmt.Fprintf(os.Stderr, "\r%s %d bytes", prefix, written)
		}
	}
}

func cmdSend(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	to := fs.String("to", "", "recipient (DERO name/address or 64-hex X25519 pubkey)")
	expire := fs.String("expire", "", "expiry: 10m/1h/24h/7d, RFC3339, or YYYY-MM-DD (default 24h)")
	anon := fs.Bool("anonymous", false, "hide sender identity")
	password := fs.String("password", "", "password-lock the drop (or GHOSTDROP_PASSWORD)")
	price := fs.Uint64("price", 0, "payment amount required")
	paidTo := fs.String("paid-to", "", "payment address for --price")
	relay := fs.String("relay", "", "relay URL (default local storage)")
	oneTime := fs.Bool("one-time", false, "burn after first receive")
	demo := fs.Bool("demo", false, "simulated drop flagged DEMO")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths := fs.Args()
	if len(paths) == 0 {
		return flagErr("send needs at least one <path>")
	}
	pw := *password
	if pw == "" {
		pw = os.Getenv("GHOSTDROP_PASSWORD")
	}
	a, err := openApp(*relay)
	if err != nil {
		return err
	}
	res, err := a.Send(ctx, app.SendOpts{
		Paths: paths, To: *to, Expire: *expire, Anonymous: *anon,
		Password: pw, Price: *price, PaidTo: *paidTo, Relay: *relay,
		OneTime: *oneTime, Demo: *demo, Progress: stderrProgress("seal"),
	})
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	qrPath := filepath.Join(a.DataDir(), "drops", res.DropID, "qr.png")
	_ = os.WriteFile(qrPath, res.QRpng, 0o644)
	if *asJSON {
		return printJSON(map[string]any{
			"drop_id": res.DropID, "link": res.Link,
			"size": res.Size, "mode": res.Manifest.Mode, "qr": qrPath,
		})
	}
	fmt.Printf("Drop: %s\nLink: %s\nSize: %d bytes\nQR:   %s\n", res.DropID, res.Link, res.Size, qrPath)
	if *demo {
		fmt.Println("Mode: DEMO (simulated drop)")
	}
	return nil
}

func cmdReceive(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("receive", flag.ContinueOnError)
	out := fs.String("out", "", "output directory (default ./downloads)")
	password := fs.String("password", "", "drop password / recipient privkey (or GHOSTDROP_PASSWORD)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return flagErr("receive needs exactly one <drop-url>")
	}
	pw := *password
	if pw == "" {
		pw = os.Getenv("GHOSTDROP_PASSWORD")
	}
	dir := *out
	if dir == "" {
		dir = defaultDownloadDir()
	}
	a, err := openApp("")
	if err != nil {
		return err
	}
	if err := a.Receive(ctx, fs.Arg(0), pw, dir, stderrProgress("recv")); err != nil {
		fmt.Fprintln(os.Stderr)
		return err
	}
	fmt.Fprintln(os.Stderr)
	fmt.Printf("Received into %s\n", dir)
	return nil
}

func cmdInspect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return flagErr("inspect needs one <id|url>")
	}
	a, err := openApp("")
	if err != nil {
		return err
	}
	m, err := a.Inspect(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(m)
	}
	raw, _ := json.MarshalIndent(m.Metadata(), "", "  ")
	fmt.Println(string(raw))
	return nil
}

func cmdVerify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return flagErr("verify needs one <id|url>")
	}
	a, err := openApp("")
	if err != nil {
		return err
	}
	if err := a.Verify(ctx, fs.Arg(0)); err != nil {
		return err
	}
	fmt.Println("OK: manifest, signature, and payload hashes verify")
	return nil
}

func cmdRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return flagErr("revoke needs one <id|url>")
	}
	a, err := openApp("")
	if err != nil {
		return err
	}
	if err := a.Revoke(ctx, fs.Arg(0)); err != nil {
		return err
	}
	fmt.Println("Revoked")
	return nil
}

func cmdList(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := openApp("")
	if err != nil {
		return err
	}
	drops, err := a.List()
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(drops)
	}
	if len(drops) == 0 {
		fmt.Println("No drops")
		return nil
	}
	for _, m := range drops {
		fmt.Printf("%s  mode=%-9s files=%d size=%d expires=%s\n",
			m.DropID, m.Mode, m.FileCount, m.PayloadSize, m.ExpiresAt)
	}
	return nil
}

func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return flagErr("status needs one <id|url>")
	}
	a, err := openApp("")
	if err != nil {
		return err
	}
	s, err := a.Status(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(map[string]any{"status": s})
	}
	fmt.Println(s)
	return nil
}

func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := openApp("")
	if err != nil {
		return err
	}
	checks := a.Doctor(ctx)
	if *asJSON {
		return printJSON(checks)
	}
	failed := 0
	for _, c := range checks {
		mark := "✓"
		if !c.OK {
			mark = "✗"
			failed++
		}
		fmt.Printf("%s %-8s %s\n", mark, c.Name, c.Detail)
		if !c.OK && c.Hint != "" {
			fmt.Printf("    fix: %s\n", c.Hint)
		}
	}
	if failed > 0 {
		return doctorErr(failed)
	}
	return nil
}

type doctorError struct{ n int }

func (e *doctorError) Error() string { return fmt.Sprintf("%d check(s) failed", e.n) }

func doctorErr(n int) error { return &doctorError{n} }

type flagError struct{ s string }

func (e *flagError) Error() string { return e.s }

func flagErr(s string) error { return &flagError{s} }

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func defaultDownloadDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "downloads"
	}
	dl := filepath.Join(home, "Downloads")
	if st, err := os.Stat(dl); err == nil && st.IsDir() {
		out := filepath.Join(dl, "ghostdrop")
		_ = os.MkdirAll(out, 0o755)
		return out
	}
	if strings.HasPrefix(strings.ToLower(os.Getenv("OS")), "windows") {
		_ = home
	}
	return "downloads"
}
