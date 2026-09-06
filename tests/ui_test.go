package tests_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ghostdrop/internal/ui"
)

func desktopServer(t *testing.T, webRoot string) (*ui.Server, *httptest.Server) {
	t.Helper()
	srv, err := ui.NewServer(false, webRoot, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func TestDesktopIndexMarkers(t *testing.T) {
	_, ts := desktopServer(t, "web")
	// httptest runs from tests/; webRoot "web" won't exist there — use ../web.
	// Rebuild with the correct relative root when fallback HTML served.
	r, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := r.Body.Read(buf)
	body := string(buf[:n])
	if strings.Contains(body, "DROP FILE HERE") && strings.Contains(body, "GHOSTDROP") {
		return
	}
	_, ts2 := desktopServer(t, "../web")
	r2, err := http.Get(ts2.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	n2, _ := r2.Body.Read(buf)
	body2 := string(buf[:n2])
	if !strings.Contains(body2, "GHOSTDROP") || !strings.Contains(body2, "DROP FILE HERE") {
		t.Fatalf("index missing markers: %q", body2)
	}
}

func TestDesktopDropsFlowNoSecrets(t *testing.T) {
	_, ts := desktopServer(t, "")
	created := struct {
		ID    string `json:"id"`
		URL   string `json:"url"`
		Token string `json:"token"`
	}{}
	r, err := http.Post(ts.URL+"/api/drops", "application/json",
		strings.NewReader(`{"recipient":"bob","mode":"signed","expire_hours":24}`))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 201 {
		t.Fatalf("POST status %d", r.StatusCode)
	}
	if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Token == "" || created.URL == "" {
		t.Fatalf("missing fields: %+v", created)
	}

	for _, path := range []string{"/api/drops", "/api/drops/" + created.ID} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1<<20)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		if strings.Contains(string(buf[:n]), created.Token) {
			t.Fatalf("GET %s leaks token", path)
		}
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/drops/"+created.ID+"/clipboard?kind=link", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var clip struct {
		Value string `json:"value"`
		Note  string `json:"note"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&clip); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clip.Note, "30s") {
		t.Fatalf("clipboard note missing timed clear: %q", clip.Note)
	}
}
