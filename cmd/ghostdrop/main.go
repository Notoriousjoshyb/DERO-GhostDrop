// Command ghostdrop runs the Ghostdrop desktop app: a localhost HTTP server
// serving the premium web UI plus a single-user JSON API. It opens the
// system browser, supports --demo (SIMULATED banner, isolated state),
// --open-url ghostdrop://drop/<id>, and shuts down gracefully.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"ghostdrop/internal/ui"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ghostdrop: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("ghostdrop", flag.ContinueOnError)
	demo := fs.Bool("demo", false, "Demo mode: SIMULATED banner, isolated in-memory state")
	openURL := fs.String("open-url", "", "Open a ghostdrop://drop/<id> URL")
	port := fs.Int("port", 0, "Localhost port (0 = auto)")
	noBrowser := fs.Bool("no-browser", false, "Do not auto-open the browser")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	var deepID string
	if *openURL != "" {
		id, err := ui.ParseOpenURL(*openURL)
		if err != nil {
			return err
		}
		deepID = id
		fmt.Printf("ghostdrop: opening drop %s\n", id)
	}

	webRoot := findWebRoot()
	srv, err := ui.NewServer(*demo, webRoot, "")
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	fmt.Printf("GHOSTDROP desktop on http://%s\n", addr)
	if *demo {
		fmt.Println("GHOSTDROP demo mode: SIMULATED — isolated state, nothing persists")
	}

	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "ghostdrop: "+err.Error())
		}
	}()

	url := "http://" + addr + "/"
	if deepID != "" {
		url += "#/drop/" + deepID
	}
	if !*noBrowser {
		openBrowser(url)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("\nghostdrop: shutting down…")
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shut)
}

// findWebRoot locates web/ from common working directories (repo root or
// cmd/ghostdrop). Empty means the server falls back to built-in HTML.
func findWebRoot() string {
	if st, err := os.Stat("web/index.html"); err == nil && !st.IsDir() {
		return "web"
	}
	for _, cand := range []string{
		filepath.Join("..", "..", "web"),
		filepath.Join(".", "web"),
	} {
		if st, err := os.Stat(filepath.Join(cand, "index.html")); err == nil && !st.IsDir() {
			return cand
		}
	}
	exe, err := os.Executable()
	if err == nil {
		cand := filepath.Join(filepath.Dir(exe), "web")
		if st, err := os.Stat(filepath.Join(cand, "index.html")); err == nil && !st.IsDir() {
			return cand
		}
	}
	return ""
}

// openBrowser launches the system browser without blocking. Failures are
// non-fatal (the URL is already printed).
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		if _, err := exec.LookPath("xdg-open"); err != nil {
			return
		}
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
