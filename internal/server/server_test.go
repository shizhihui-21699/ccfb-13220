package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func makeRepo(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "repo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"HOME="+root, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o644)
	run("add", "-A")
	run("commit", "-qm", "one")
	os.WriteFile(filepath.Join(dir, "secret.csv"), []byte("id,email\n1,a@b\n"), 0o644)
	run("add", "-A")
	run("commit", "-qm", "two")
	return dir
}

func do(t *testing.T, h http.Handler, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestPlanAndRunFlow(t *testing.T) {
	root := t.TempDir()
	repoDir := makeRepo(t, root)
	srv, err := New(Config{Root: root, AllowRun: true})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	rec, out := do(t, h, "GET", "/api/health", nil)
	if rec.Code != 200 || out["allow_run"] != true {
		t.Fatalf("health: %d %v", rec.Code, out)
	}

	rec, out = do(t, h, "GET", "/api/repos", nil)
	if rec.Code != 200 {
		t.Fatalf("repos: %d %v", rec.Code, out)
	}
	if len(out["repos"].([]any)) != 1 {
		t.Fatalf("expected one repo, got %v", out["repos"])
	}

	spec := map[string]any{"rules": []any{map[string]any{"kind": "path", "value": "*.csv"}}}
	rec, out = do(t, h, "POST", "/api/plan", map[string]any{"repo": repoDir, "spec": spec})
	if rec.Code != 200 {
		t.Fatalf("plan: %d %v", rec.Code, out)
	}
	planID, _ := out["plan_id"].(string)
	if planID == "" {
		t.Fatal("no plan id")
	}
	stats := out["stats"].(map[string]any)
	if stats["findings"].(float64) == 0 {
		t.Fatal("expected findings")
	}

	// Run without confirmation must be refused.
	rec, _ = do(t, h, "POST", "/api/run", map[string]any{"plan_id": planID})
	if rec.Code != 400 {
		t.Fatalf("run without confirm: expected 400, got %d", rec.Code)
	}
	rec, out = do(t, h, "POST", "/api/run", map[string]any{"plan_id": planID, "confirm": "REWRITE"})
	if rec.Code != 200 {
		t.Fatalf("run: %d %v", rec.Code, out)
	}
	if strings.Contains(mustJSON(t, out["report"]), `"signature_losses": null`) {
		t.Log("no signature losses, expected for unsigned demo")
	}

	// Verify afterwards: the report's sensitive objects must be reachable only
	// via backups, so it should pass with backup-only entries.
	sensitive := out["sensitive"]
	rec, out = do(t, h, "POST", "/api/verify", map[string]any{"repo": repoDir, "spec": spec, "sensitive": sensitive})
	if rec.Code != 200 {
		t.Fatalf("verify: %d %v", rec.Code, out)
	}
	if out["still_reachable"].(float64) != 0 {
		t.Fatalf("objects still reachable: %v", out["objects"])
	}
}

func TestPathEscapeIsRefused(t *testing.T) {
	root := t.TempDir()
	srv, _ := New(Config{Root: root, AllowRun: true})
	h := srv.Handler()
	rec, out := do(t, h, "POST", "/api/plan", map[string]any{
		"repo": "/etc",
		"spec": map[string]any{"rules": []any{map[string]any{"kind": "path", "value": "*"}}},
	})
	if rec.Code != 400 {
		t.Fatalf("expected 400 for escaping path, got %d %v", rec.Code, out)
	}
	if !strings.Contains(out["error"].(string), "outside the allowed root") {
		t.Fatalf("unexpected error: %v", out["error"])
	}
}

func TestRunDisabledByDefault(t *testing.T) {
	root := t.TempDir()
	makeRepo(t, root)
	srv, _ := New(Config{Root: root})
	h := srv.Handler()
	rec, out := do(t, h, "POST", "/api/run", map[string]any{"plan_id": "x", "confirm": "REWRITE"})
	if rec.Code != 403 {
		t.Fatalf("expected 403, got %d %v", rec.Code, out)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEmbeddedUIAssetsAreServed(t *testing.T) {
	srv, err := New(Config{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	for _, name := range []string{"/", "/app.js", "/app.css"} {
		req := httptest.NewRequest("GET", name, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", name, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("%s: empty body", name)
		}
	}
	// A traversal attempt must not read outside the embedded set.
	req := httptest.NewRequest("GET", "/../go.mod", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatal("path traversal served a file")
	}
}
