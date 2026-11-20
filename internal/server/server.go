package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"historyscrub/internal/gitx"
	"historyscrub/internal/rules"
	"historyscrub/internal/scrub"
)

// Config configures the operator UI server.
type Config struct {
	// Root is the directory the repo browser may look in. Requests cannot
	// escape it.
	Root string
	// AllowRun enables the mutating endpoints. The UI still requires an explicit
	// confirmation token, but this is the kill switch.
	AllowRun bool
	// Addr is the listen address.
	Addr string
}

// Server is the HTTP API behind the React UI.
type Server struct {
	cfg   Config
	mux   *http.ServeMux
	mu    sync.Mutex
	jobs  map[string]*job
	plans map[string]*planRecord
}

// planRecord is a completed plan that a run can execute.
type planRecord struct {
	ID        string
	RepoPath  string
	Spec      *rules.Spec
	Report    *scrub.Report
	CreatedAt time.Time
}

// job is a long-running run/verify/prune.
type job struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	State    string    `json:"state"` // running, done, failed
	Message  string    `json:"message"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	Report   any       `json:"report,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// New builds the server.
func New(cfg Config) (*Server, error) {
	if cfg.Root == "" {
		cfg.Root = "."
	}
	abs, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, err
	}
	cfg.Root = abs
	s := &Server{cfg: cfg, mux: http.NewServeMux(), jobs: map[string]*job{}, plans: map[string]*planRecord{}}
	s.routes()
	return s, nil
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// Addr returns the configured address.
func (s *Server) Addr() string { return s.cfg.Addr }

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/health", s.handleHealth)
	m.HandleFunc("GET /api/presets", s.handlePresets)
	m.HandleFunc("GET /api/repos", s.handleListRepos)
	m.HandleFunc("POST /api/repo/open", s.handleOpenRepo)
	m.HandleFunc("POST /api/plan", s.handlePlan)
	m.HandleFunc("POST /api/run", s.handleRun)
	m.HandleFunc("POST /api/verify", s.handleVerify)
	m.HandleFunc("POST /api/prune", s.handlePrune)
	m.HandleFunc("POST /api/notify", s.handleNotify)
	m.HandleFunc("GET /api/jobs/{id}", s.handleJob)
	m.HandleFunc("GET /api/files/{name}", s.handleFiles)
	m.HandleFunc("GET /api/report/{id}", s.handleReport)
	m.HandleFunc("GET /api/tips/{id}", s.handleTips)
	m.HandleFunc("/", s.handleStatic)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"ok":        true,
		"root":      s.cfg.Root,
		"allow_run": s.cfg.AllowRun,
		"time":      time.Now().UTC(),
	})
}

func (s *Server) handlePresets(w http.ResponseWriter, r *http.Request) {
	type preset struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	var out []preset
	for _, n := range rules.PresetNames() {
		p, _ := rules.PresetByName(n)
		out = append(out, preset{Name: p.Name, Description: p.Description})
	}
	writeJSON(w, 200, map[string]any{"presets": out})
}

// --- repository discovery -------------------------------------------------

type repoInfo struct {
	Path    string `json:"path"`
	Rel     string `json:"rel"`
	Full    string `json:"full_path"`
	Name    string `json:"name"`
	Bare    bool   `json:"bare"`
	HEAD    string `json:"head,omitempty"`
	Dirty   int    `json:"dirty_files"`
	Commits int    `json:"commits,omitempty"`
	Refs    int    `json:"refs,omitempty"`
}

func (s *Server) handleListRepos(w http.ResponseWriter, r *http.Request) {
	var out []repoInfo
	entries, err := os.ReadDir(s.cfg.Root)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	candidates := []string{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || e.Name() == "node_modules" {
			continue
		}
		full := filepath.Join(s.cfg.Root, e.Name())
		if _, err := os.Stat(filepath.Join(full, ".git")); err == nil {
			candidates = append(candidates, full)
		}
	}
	// The root itself may be a repository.
	if _, err := os.Stat(filepath.Join(s.cfg.Root, ".git")); err == nil {
		candidates = append([]string{s.cfg.Root}, candidates...)
	}
	for _, c := range candidates {
		info, err := inspectRepo(c)
		if err != nil {
			continue
		}
		out = append(out, info)
	}
	writeJSON(w, 200, map[string]any{"root": s.cfg.Root, "repos": out})
}

func inspectRepo(path string) (repoInfo, error) {
	repo, err := gitx.Open(path)
	if err != nil {
		return repoInfo{}, err
	}
	rel, _ := filepath.Rel(filepath.Dir(path), path)
	info := repoInfo{Path: path, Full: path, Name: filepath.Base(path), Rel: rel, Bare: repo.Bare}
	if head, err := repo.Head(); err == nil {
		info.HEAD = head.Symbolic
		if info.HEAD == "" {
			info.HEAD = "detached"
		}
	}
	if dirty, err := repo.DirtyFiles(); err == nil {
		info.Dirty = len(dirty)
	}
	if refs, err := repo.ListRefs("refs"); err == nil {
		info.Refs = len(refs)
	}
	if out, err := repo.Output("rev-list", "--count", "--all"); err == nil {
		fmt.Sscanf(strings.TrimSpace(out), "%d", &info.Commits)
	}
	return info, nil
}

func (s *Server) resolveRepo(w http.ResponseWriter, reqPath string) (string, bool) {
	full, err := s.safePath(reqPath)
	if err != nil {
		writeErr(w, 400, err.Error())
		return "", false
	}
	if _, err := gitx.Open(full); err != nil {
		writeErr(w, 400, "not a git repository: "+err.Error())
		return "", false
	}
	return full, true
}

// safePath resolves a user-supplied path and refuses anything outside Root.
func (s *Server) safePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("path is required")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.cfg.Root, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	root := filepath.Clean(s.cfg.Root)
	if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q is outside the allowed root %q", abs, root)
	}
	return abs, nil
}

func (s *Server) handleOpenRepo(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request: "+err.Error())
		return
	}
	full, ok := s.resolveRepo(w, req.Path)
	if !ok {
		return
	}
	info, err := inspectRepo(full)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	repo, _ := gitx.Open(full)
	var refs []map[string]any
	if all, err := repo.ListRefs("refs/heads", "refs/tags"); err == nil {
		for _, x := range all {
			refs = append(refs, map[string]any{
				"name": x.Name, "short": x.Short, "oid": x.OID, "type": x.Type,
				"peeled": x.Peeled, "signed": len(x.Signature) > 0,
			})
		}
	}
	warnings := []string{}
	if repo.Shallow {
		warnings = append(warnings, "repository is shallow: history behind the shallow boundary cannot be scrubbed")
	}
	writeJSON(w, 200, map[string]any{
		"repo":          info,
		"refs":          refs,
		"warnings":      warnings,
		"object_format": repo.ObjectFormat,
	})
}

// --- plan / run -----------------------------------------------------------

type specRequest struct {
	Repo string     `json:"repo"`
	Spec rules.Spec `json:"spec"`
}

func (s *Server) decodeSpec(w http.ResponseWriter, r *http.Request) (string, *rules.Spec, bool) {
	var req specRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, 400, "bad request: "+err.Error())
		return "", nil, false
	}
	full, ok := s.resolveRepo(w, req.Repo)
	if !ok {
		return "", nil, false
	}
	if err := req.Spec.Validate(); err != nil {
		writeErr(w, 400, "invalid spec: "+err.Error())
		return "", nil, false
	}
	spec := req.Spec
	return full, &spec, true
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	full, spec, ok := s.decodeSpec(w, r)
	if !ok {
		return
	}
	repo, err := gitx.Open(full)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	rep, err := scrub.Plan(scrub.Options{Repo: repo, Spec: spec})
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	id := randomID()
	s.mu.Lock()
	s.plans[id] = &planRecord{ID: id, RepoPath: full, Spec: spec, Report: rep, CreatedAt: time.Now()}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"plan_id":    id,
		"report":     rep,
		"stats":      rep.Stats(),
		"sensitive":  rep.SensitiveObjects(),
		"expires_at": time.Now().Add(2 * time.Hour),
	})
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowRun {
		writeErr(w, 403, "run is disabled on this server (start it with -allow-run)")
		return
	}
	var req struct {
		PlanID        string `json:"plan_id"`
		Confirm       string `json:"confirm"`
		ResetWorktree bool   `json:"reset_worktree"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request: "+err.Error())
		return
	}
	if req.Confirm != "REWRITE" {
		writeErr(w, 400, `explicit confirmation is required: send "confirm": "REWRITE"`)
		return
	}
	s.mu.Lock()
	p, ok := s.plans[req.PlanID]
	s.mu.Unlock()
	if !ok {
		writeErr(w, 404, "unknown or expired plan; run the plan step again")
		return
	}
	repo, err := gitx.Open(p.RepoPath)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	rep, err := scrub.Run(scrub.Options{Repo: repo, Spec: p.Spec, ResetWorktree: req.ResetWorktree})
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"report": rep, "stats": rep.Stats(), "sensitive": rep.SensitiveObjects()})
}

// --- verify ---------------------------------------------------------------

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo      string                  `json:"repo"`
		Spec      *rules.Spec             `json:"spec"`
		ReportID  string                  `json:"plan_id"`
		Sensitive []scrub.SensitiveObject `json:"sensitive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request: "+err.Error())
		return
	}
	full, ok := s.resolveRepo(w, req.Repo)
	if !ok {
		return
	}
	repo, err := gitx.Open(full)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	opts := scrub.VerifyOptions{Repo: repo, Sensitive: req.Sensitive}
	if req.Spec != nil {
		if err := req.Spec.Validate(); err != nil {
			writeErr(w, 400, "invalid spec: "+err.Error())
			return
		}
		opts.Spec = req.Spec
	} else if req.ReportID != "" {
		s.mu.Lock()
		p := s.plans[req.ReportID]
		s.mu.Unlock()
		if p == nil {
			writeErr(w, 404, "unknown plan")
			return
		}
		opts.Spec = p.Spec
	}
	v, err := scrub.Verify(opts)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) handlePrune(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowRun {
		writeErr(w, 403, "prune is disabled on this server (start it with -allow-run)")
		return
	}
	var req struct {
		Repo    string `json:"repo"`
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request: "+err.Error())
		return
	}
	if req.Confirm != "PRUNE" {
		writeErr(w, 400, `explicit confirmation is required: send "confirm": "PRUNE"`)
		return
	}
	full, ok := s.resolveRepo(w, req.Repo)
	if !ok {
		return
	}
	repo, err := gitx.Open(full)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	res, err := scrub.Prune(scrub.PruneOptions{Repo: repo, DeleteBackups: true, ExpireReflogs: true})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// --- notification ---------------------------------------------------------

func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo   string `json:"repo"`
		Remote string `json:"remote"`
		Name   string `json:"name"`
		PlanID string `json:"plan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad request: "+err.Error())
		return
	}
	full, ok := s.resolveRepo(w, req.Repo)
	if !ok {
		return
	}
	repo, err := gitx.Open(full)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var rep scrub.Report
	s.mu.Lock()
	if p := s.plans[req.PlanID]; p != nil {
		rep = *p.Report
	}
	s.mu.Unlock()

	remote := req.Remote
	if remote == "" {
		remote = repo.GitConfig("remote.origin.url")
	}
	name := req.Name
	if name == "" {
		name = filepath.Base(full)
	}
	in := scrub.NotificationInput{
		RepoName: name, RemoteURL: remote,
		OldTips: map[string]string{}, NewTips: map[string]string{},
		RewrittenAt: rep.FinishedAt, Counts: rep.Stats(),
	}
	seen := map[string]bool{}
	for _, u := range rep.Refs {
		if u.Type != "commit" || !u.Changed {
			continue
		}
		in.OldTips[u.Name] = u.Old
		in.NewTips[u.Name] = u.New
		if strings.HasPrefix(u.Name, "refs/heads/") {
			in.Branches = append(in.Branches, u.Name)
		}
	}
	for _, f := range rep.Findings {
		if f.Path != "" && !seen[f.Path] {
			seen[f.Path] = true
			in.RemovedPaths = append(in.RemovedPaths, f.Path)
		}
	}
	n := scrub.BuildNotification(in)
	writeJSON(w, 200, n)
}

// --- jobs -----------------------------------------------------------------

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	j, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		writeErr(w, 404, "unknown job")
		return
	}
	writeJSON(w, 200, j)
}

// --- static files ---------------------------------------------------------

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// Only ever serve names that exist in the embedded map; never join a path.
	if !strings.Contains(name, ".") || strings.ContainsAny(name, "/\\") {
		http.NotFound(w, r)
		return
	}
	data, ok := assets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	serveAsset(w, name, data)
}

func serveAsset(w http.ResponseWriter, name string, data []byte) {
	switch {
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Write(data)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path != "/" {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if data, ok := assets[name]; ok {
			serveAsset(w, name, data)
			return
		}
		http.NotFound(w, r)
		return
	}
	if _, ok := assets["index.html"]; !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>historyscrub</title><p>The web UI is not embedded in this build. Build it with <code>npm run build</code> in web/ and rebuild the server, or talk to the JSON API at <code>/api/health</code>.")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(assets["index.html"])
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	p := s.plans[id]
	s.mu.Unlock()
	if p == nil {
		writeErr(w, 404, "unknown plan")
		return
	}
	writeJSON(w, 200, p.Report)
}

func (s *Server) handleTips(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	p := s.plans[id]
	s.mu.Unlock()
	if p == nil {
		writeErr(w, 404, "unknown plan")
		return
	}
	out := map[string]string{}
	for _, u := range p.Report.Refs {
		if u.Changed {
			out[u.Name] = u.New
		}
	}
	writeJSON(w, 200, out)
}

// --- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func randomID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// Listen starts the server and blocks.
func (s *Server) Listen() error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	fmt.Printf("historyscrub UI listening on http://%s (repo root: %s, mutations: %v)\n", ln.Addr(), s.cfg.Root, s.cfg.AllowRun)
	return srv.Serve(ln)
}

// Shutdown stops the server.
func (s *Server) Shutdown(ctx context.Context) error { return nil }
