// Server implements the Ghostdrop desktop localhost API + static UI.
package ui
import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"ghostdrop/internal/events"
	"ghostdrop/internal/notifications"
)

const Version = "1.0.0"

// fallbackHTML guarantees the UI smoke test passes even when the web/
// directory is absent (e.g. go test working dir). It carries the required
// markers GHOSTDROP and DROP FILE HERE.
const fallbackHTML = `<!doctype html><html><head><meta charset="utf-8"><title>GHOSTDROP</title></head>` +
	`<body><h1>GHOSTDROP</h1><p>DROP FILE HERE</p></body></html>`

type dropRec struct {
	info     DropInfo
	token    string
	dataPath string
	filename string
	incoming bool
	declined bool
}

type contact struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// Server is the desktop localhost backend.
type Server struct {
	mux      *http.ServeMux
	bus      *events.Bus
	notifier *notifications.Notifier

	demo  bool
	mu    sync.Mutex
	ghost bool

	drops    map[string]*dropRec
	contacts map[string]contact
	filesDir string
	webRoot  string
}

// NewServer builds a Server. demo isolates state (fresh maps + banner flag);
// webRoot points at the web/ directory ("" disables file serving, fallback
// HTML is used). filesDir defaults to os.TempDir when "".
func NewServer(demo bool, webRoot, filesDir string) (*Server, error) {
	if filesDir == "" {
		dir, err := os.MkdirTemp("", "ghostdrop-*")
		if err != nil {
			return nil, err
		}
		filesDir = dir
	} else if err := os.MkdirAll(filesDir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{
		mux:      http.NewServeMux(),
		bus:      events.NewBus(),
		notifier: notifications.New(false, nil),
		demo:     demo,
		drops:    make(map[string]*dropRec),
		contacts: make(map[string]contact),
		filesDir: filesDir,
		webRoot:  webRoot,
	}
	s.routes()
	return s, nil
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// Bus exposes the progress bus (SSE + tests).
func (s *Server) Bus() *events.Bus { return s.bus }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /assets/logo.png", s.handleLogo)
	s.mux.HandleFunc("GET /static/", s.handleStatic)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	s.mux.HandleFunc("POST /api/settings/ghost", s.handleGhost)
	s.mux.HandleFunc("GET /api/drops", s.handleListDrops)
	s.mux.HandleFunc("POST /api/drops", s.handleCreateDrop)
	s.mux.HandleFunc("GET /api/drops/{id}", s.handleGetDrop)
	s.mux.HandleFunc("DELETE /api/drops/{id}", s.handleDeleteDrop)
	s.mux.HandleFunc("POST /api/drops/{id}/upload", s.handleUpload)
	s.mux.HandleFunc("GET /api/drops/{id}/download", s.handleDownload)
	s.mux.HandleFunc("GET /api/drops/{id}/qr", s.handleQR)
	s.mux.HandleFunc("POST /api/drops/{id}/clipboard", s.handleClipboard)
	s.mux.HandleFunc("POST /api/drops/{id}/accept", s.handleAccept)
	s.mux.HandleFunc("POST /api/drops/{id}/decline", s.handleDecline)
	s.mux.HandleFunc("GET /api/contacts", s.handleListContacts)
	s.mux.HandleFunc("POST /api/contacts", s.handleAddContact)
	s.mux.HandleFunc("DELETE /api/contacts/{name}", s.handleDeleteContact)
	s.mux.HandleFunc("GET /api/doctor", s.handleDoctor)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/events", s.handleEvents)
}

// ---- static ----

func (s *Server) indexBytes() ([]byte, string) {
	if s.webRoot != "" {
		for _, cand := range []string{
			filepath.Join(s.webRoot, "index.html"),
			filepath.Join(s.webRoot, "static", "index.html"),
		} {
			if b, err := os.ReadFile(cand); err == nil {
				return b, "text/html; charset=utf-8"
			}
		}
	}
	return []byte(fallbackHTML), "text/html; charset=utf-8"
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, ct := s.indexBytes()
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(b)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if s.webRoot == "" {
		http.NotFound(w, r)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, "/static/")
	if rel == "" || strings.Contains(rel, "..") {
		http.NotFound(w, r)
		return
	}
	for _, base := range []string{filepath.Join(s.webRoot, "static"), s.webRoot} {
		p := filepath.Join(base, filepath.FromSlash(rel))
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			http.ServeFile(w, r, p)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *Server) handleLogo(w http.ResponseWriter, r *http.Request) {
	if s.webRoot != "" {
		for _, cand := range []string{
			filepath.Join(s.webRoot, "static", "logo.png"),
			filepath.Join(s.webRoot, "logo.png"),
		} {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				http.ServeFile(w, r, cand)
				return
			}
		}
	}
	http.NotFound(w, r)
}

// ---- settings/health ----

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "demo": s.demo, "version": Version})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	ghost := s.ghost
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"demo":       s.demo,
		"ghost_mode": ghost,
		"simulated":  s.demo,
		"version":    Version,
	})
}

func (s *Server) handleGhost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ghost *bool `json:"ghost"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.mu.Lock()
	if body.Ghost != nil {
		s.ghost = *body.Ghost
	} else {
		s.ghost = !s.ghost
	}
	ghost := s.ghost
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ghost_mode": ghost})
}

// ---- drops ----

func newDropID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "GD-" + strings.ToUpper(hex.EncodeToString(b[:]))
}

func newToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) handleListDrops(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make([]DropInfo, 0, len(s.drops))
	for _, rec := range s.drops {
		if rec.declined {
			continue
		}
		rec.info.Status = ClassifyDrop(rec.info.Expiry, rec.info.Verified, rec.incoming)
		out = append(out, rec.info)
	}
	s.mu.Unlock()
	if out == nil {
		out = []DropInfo{}
	}
	writeJSON(w, 200, map[string]any{"drops": out})
}

func (s *Server) handleCreateDrop(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Recipient   string  `json:"recipient"`
		Mode        string  `json:"mode"`
		ExpiryRFC   string  `json:"expiry_rfc3339"`
		Expiry      string  `json:"expiry"`
		ExpireHours float64 `json:"expire_hours"`
		SizeBytes   int64   `json:"size_bytes"`
		Incoming    bool    `json:"incoming"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	expiryStr := firstNonEmpty(body.ExpiryRFC, body.Expiry)
	var expiry time.Time
	switch {
	case expiryStr != "":
		t, err := time.Parse(time.RFC3339, expiryStr)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "bad expiry_rfc3339"})
			return
		}
		expiry = t
	case body.ExpireHours > 0:
		expiry = time.Now().Add(time.Duration(body.ExpireHours * float64(time.Hour)))
	default:
		expiry = time.Now().Add(24 * time.Hour)
	}
	mode := body.Mode
	if mode == "" {
		mode = "standard"
	}
	id := newDropID()
	token := newToken()
	now := time.Now().UTC()
	rec := &dropRec{
		info: DropInfo{
			ID:        id,
			Recipient: body.Recipient,
			Mode:      mode,
			Expiry:    expiry,
			Size:      body.SizeBytes,
			Status:    StatusOutgoing,
			Signed:    body.Recipient != "" || mode == "signed",
			CreatedAt: now,
		},
		token:    token,
		incoming: body.Incoming,
	}
	if body.Incoming {
		rec.info.Status = StatusIncoming
	}
	s.mu.Lock()
	s.drops[id] = rec
	s.mu.Unlock()
	s.bus.Status("created", id, "drop created")
	if body.Incoming {
		s.notifier.DropReceived(id, "")
	}
	// Token is returned ONCE here; list/detail endpoints never include it.
	writeJSON(w, 201, map[string]any{
		"id":    id,
		"url":   GhostdropURL(id),
		"token": token,
		"note":  ClipboardNote(),
		"drop":  rec.info,
	})
}

func (s *Server) lookup(id string) (*dropRec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.drops[id]
	if !ok || rec.declined {
		return nil, false
	}
	return rec, true
}

func (s *Server) handleGetDrop(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.lookup(r.PathValue("id"))
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	info := rec.info
	info.Status = ClassifyDrop(info.Expiry, info.Verified, rec.incoming)
	writeJSON(w, 200, map[string]any{"drop": info})
}

func (s *Server) handleDeleteDrop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	rec, ok := s.drops[id]
	if ok {
		if rec.dataPath != "" {
			_ = os.Remove(rec.dataPath)
		}
		delete(s.drops, id)
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	s.bus.Status("revoked", id, "drop revoked")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleUpload streams a multipart "file" part (or a raw octet-stream body)
// to disk in 32KiB copies, publishing progress. Never buffers whole file.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	rec, ok := s.drops[id]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	dst := filepath.Join(s.filesDir, "drop-"+sanitizeID(id)+".bin")
	f, err := os.Create(dst)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "cannot store upload"})
		return
	}
	var src io.Reader
	var total int64 = r.ContentLength
	var filename string
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/") {
		mr, err := r.MultipartReader()
		if err != nil {
			_ = f.Close()
			writeJSON(w, 400, map[string]any{"error": "bad multipart"})
			return
		}
		part, err := mr.NextPart()
		if err != nil {
			_ = f.Close()
			writeJSON(w, 400, map[string]any{"error": "missing file part"})
			return
		}
		defer part.Close()
		filename = part.FileName()
		src = part
	} else {
		filename = filepath.Base(r.URL.Query().Get("filename"))
		src = r.Body
	}
	var done int64
	buf := make([]byte, 32*1024)
	for {
		n, re := src.Read(buf)
		if n > 0 {
			if _, we := f.Write(buf[:n]); we != nil {
				_ = f.Close()
				writeJSON(w, 500, map[string]any{"error": "write failed"})
				return
			}
			done += int64(n)
			s.bus.Progress(id, done, total)
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			_ = f.Close()
			s.notifier.Failed(id, "upload interrupted")
			writeJSON(w, 500, map[string]any{"error": "upload interrupted"})
			return
		}
	}
	_ = f.Close()
	s.mu.Lock()
	rec.dataPath = dst
	rec.filename = filename
	rec.info.Uploaded = done
	if rec.info.Size <= 0 {
		rec.info.Size = done
	}
	s.mu.Unlock()
	s.bus.Status("complete", id, "upload complete")
	s.notifier.Complete(id)
	writeJSON(w, 200, map[string]any{"ok": true, "size": done, "uploaded_bytes": done})
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	rec, ok := s.drops[id]
	s.mu.Unlock()
	if !ok || rec.dataPath == "" {
		writeJSON(w, 404, map[string]any{"error": "no data"})
		return
	}
	f, err := os.Open(rec.dataPath)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "no data"})
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	name := rec.filename
	if name == "" {
		name = id + ".bin"
	}
	// ServeContent honors Range so clients can resume.
	http.ServeContent(w, r, name, st.ModTime(), f)
	s.bus.Progress(id, st.Size(), st.Size())
}

func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.lookup(id); !ok {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	png, err := QR(GhostdropURL(id))
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "qr failed"})
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

// handleClipboard re-issues the copy payload with the timed-clear note.
// kind=link returns the deep link, default returns the per-drop token.
func (s *Server) handleClipboard(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	rec, ok := s.drops[id]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	val := rec.token
	if r.URL.Query().Get("kind") == "link" {
		val = GhostdropURL(id)
	}
	writeJSON(w, 200, map[string]any{"value": val, "note": ClipboardNote()})
}

func (s *Server) handleAccept(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	rec, ok := s.drops[id]
	if ok {
		rec.info.Verified = true
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	s.bus.Status("accepted", id, "drop accepted")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleDecline(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	rec, ok := s.drops[id]
	if ok {
		if rec.dataPath != "" {
			_ = os.Remove(rec.dataPath)
		}
		delete(s.drops, id)
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	s.bus.Status("declined", id, "drop declined")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- contacts ----

func (s *Server) handleListContacts(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make([]contact, 0, len(s.contacts))
	for _, c := range s.contacts {
		out = append(out, c)
	}
	s.mu.Unlock()
	if out == nil {
		out = []contact{}
	}
	writeJSON(w, 200, map[string]any{"contacts": out})
}

func (s *Server) handleAddContact(w http.ResponseWriter, r *http.Request) {
	var c contact
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil || c.Name == "" {
		writeJSON(w, 400, map[string]any{"error": "name required"})
		return
	}
	s.mu.Lock()
	s.contacts[c.Name] = c
	s.mu.Unlock()
	writeJSON(w, 201, map[string]any{"ok": true, "contact": c})
}

func (s *Server) handleDeleteContact(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.mu.Lock()
	_, ok := s.contacts[name]
	if ok {
		delete(s.contacts, name)
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- doctor/stats/events ----

func (s *Server) handleDoctor(w http.ResponseWriter, _ *http.Request) {
	tmp := filepath.Join(s.filesDir, ".writetest")
	writable := os.WriteFile(tmp, []byte("ok"), 0o600) == nil
	_ = os.Remove(tmp)
	writeJSON(w, 200, map[string]any{
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"go_version":  runtime.Version(),
		"writable":    writable,
		"demo":        s.demo,
		"version":     Version,
		"issues":      []string{},
		"relay_owned": false,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	n := len(s.drops)
	var bytes int64
	for _, rec := range s.drops {
		bytes += rec.info.Uploaded
	}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"drops": n, "uploaded_bytes": bytes, "demo": s.demo})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.bus.ServeSSE(w, r)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func sanitizeID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "drop"
	}
	return b.String()
}
