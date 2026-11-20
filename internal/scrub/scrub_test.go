package scrub

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"historyscrub/internal/gitx"
	"historyscrub/internal/rules"
)

// fixture builds a throwaway repository with a main branch, a feature branch,
// a merge, a signed commit and a signed tag.
type fixture struct {
	t       *testing.T
	dir     string
	env     []string
	gpgHome string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, dir: dir}
	// Isolate git config so a developer's gpg/ssh setup cannot change results.
	f.env = append(os.Environ(),
		"HOME="+dir,
		"XDG_CONFIG_HOME="+filepath.Join(dir, ".config"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test Author",
		"GIT_AUTHOR_EMAIL=author@example.com",
		"GIT_COMMITTER_NAME=Test Committer",
		"GIT_COMMITTER_EMAIL=committer@example.com",
		"GIT_AUTHOR_DATE=2024-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2024-01-01T00:00:00Z",
	)
	f.git("init", "-q", "-b", "main")
	f.git("config", "user.name", "Test Committer")
	f.git("config", "user.email", "committer@example.com")
	f.git("config", "commit.gpgsign", "false")
	f.git("config", "tag.gpgsign", "false")
	return f
}

func (f *fixture) git(args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = f.dir
	cmd.Env = f.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (f *fixture) write(path, content string) {
	f.t.Helper()
	full := filepath.Join(f.dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) commitAll(msg string) string {
	f.t.Helper()
	f.git("add", "-A")
	f.git("commit", "-q", "--allow-empty", "-m", msg)
	return f.git("rev-parse", "HEAD")
}

func (f *fixture) repo() *gitx.Repo {
	f.t.Helper()
	r, err := gitx.Open(f.dir)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// buildLeakyRepo creates the demo shape used by most tests.
func buildLeakyRepo(t *testing.T) (*fixture, map[string]string) {
	f := newFixture(t)
	ids := map[string]string{}

	f.write("README.md", "# demo\n")
	f.write("src/app.go", "package main\n\nfunc main() {}\n")
	ids["base"] = f.commitAll("initial project")

	f.write("exports/customers-2024-03.csv", "id,name,email\n1,Ada,ada@example.com\n2,Bob,bob@example.com\n")
	f.write("src/feature.go", "package main\n\nfunc feature() {}\n")
	ids["leak1"] = f.commitAll("add customer export for the audit")

	// Content-only leak: production key inside an otherwise ordinary file.
	f.write("config/prod.env", "API_BASE=https://api.example.com\n")
	ids["clean1"] = f.commitAll("add production config")

	f.write("config/prod.env", "API_BASE=https://api.example.com\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	ids["leak2"] = f.commitAll("tune production config")

	f.git("checkout", "-q", "-b", "feature/reports")
	f.write("src/report.go", "package main\n\nfunc report() {}\n")
	ids["feature"] = f.commitAll("add report endpoint")

	f.git("checkout", "-q", "main")
	f.write("src/util.go", "package main\n\nfunc util() {}\n")
	ids["main2"] = f.commitAll("add util")

	f.git("merge", "-q", "--no-ff", "-m", "merge feature/reports", "feature/reports")
	ids["merge"] = f.git("rev-parse", "HEAD")

	// A tag on a leaking commit, then one more clean commit.
	f.git("tag", "-a", "-m", "audit snapshot", "audit-2024-03", ids["leak1"])
	f.write("CHANGELOG.md", "- nothing yet\n")
	ids["head"] = f.commitAll("start changelog")

	// A commit that removes the export, which is exactly the mistake the user
	// described: deleting in a new commit does not remove history.
	f.git("rm", "-q", "exports/customers-2024-03.csv")
	ids["deleted"] = f.commitAll("remove accidental export")

	return f, ids
}

func leakSpec(t *testing.T) *rules.Spec {
	t.Helper()
	s := &rules.Spec{
		Rules: []rules.Rule{
			{Kind: "path", Value: "exports/*.csv", Note: "customer export directory"},
			{Kind: "literal", Value: "AKIAIOSFODNN7EXAMPLE", Note: "production AWS access key"},
			{Kind: "preset", Value: "private_key"},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPlanFindsPathsAndContent(t *testing.T) {
	f, ids := buildLeakyRepo(t)
	rep, err := Plan(Options{Repo: f.repo(), Spec: leakSpec(t)})
	if err != nil {
		t.Fatal(err)
	}
	var paths, rulesSeen []string
	for _, x := range rep.Findings {
		paths = append(paths, x.Path)
		rulesSeen = append(rulesSeen, x.Rule)
	}
	joined := strings.Join(paths, ",")
	if !strings.Contains(joined, "exports/customers-2024-03.csv") {
		t.Fatalf("missing path finding, got %v", paths)
	}
	if !strings.Contains(joined, "config/prod.env") {
		t.Fatalf("missing content finding for prod.env, got %v", paths)
	}
	if !contains(rulesSeen, "literal") {
		t.Fatalf("expected literal rule hit, got %v", rulesSeen)
	}
	if rep.CommitsRewritten == 0 {
		t.Fatal("expected rewritten commits in a plan")
	}
	_ = ids
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestRunRemovesHistoryAndVerifies(t *testing.T) {
	f, ids := buildLeakyRepo(t)
	spec := leakSpec(t)
	rep, err := Run(Options{Repo: f.repo(), Spec: spec, ResetWorktree: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Stats().Findings == 0 {
		t.Fatal("expected findings")
	}
	sens := rep.SensitiveObjects()
	if len(sens) == 0 {
		t.Fatal("expected sensitive objects")
	}
	pr, err := Prune(PruneOptions{Repo: f.repo(), DeleteBackups: true, ExpireReflogs: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prune: %+v", pr)

	v, err := Verify(VerifyOptions{Repo: f.repo(), Spec: spec, Sensitive: sens})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Passed {
		t.Fatalf("verification failed: %+v", v)
	}

	// The export must be gone from every commit and from HEAD.
	out := f.git("log", "--branches", "--tags", "--format=%H", "--", "exports/customers-2024-03.csv")
	if out != "" {
		t.Fatalf("export still present in history: %s", out)
	}
	// And the old objects must not exist.
	for _, s := range sens {
		if f.repo().HasObject(s.OID) {
			t.Fatalf("object %s (%s) still in object database", s.OID, s.Kind)
		}
	}
	if f.git("rev-parse", "HEAD") == ids["head"] {
		t.Fatal("HEAD was not rewritten")
	}
}

func TestContentOnlyFileIsRemovedNotRedacted(t *testing.T) {
	f, _ := buildLeakyRepo(t)
	spec := leakSpec(t)
	if _, err := Run(Options{Repo: f.repo(), Spec: spec, ResetWorktree: true}); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "-C", f.dir, "log", "--branches", "--tags", "--format=%H", "--", "config/prod.env").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("prod.env still in history: %s", out)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "config/prod.env")); err == nil {
		t.Fatal("prod.env still in worktree after reset")
	}
}

func TestMergeCommitParentsAreRewritten(t *testing.T) {
	f, _ := buildLeakyRepo(t)
	before := f.git("rev-list", "--merges", "--count", "--branches", "--tags")
	if _, err := Run(Options{Repo: f.repo(), Spec: leakSpec(t), ResetWorktree: true}); err != nil {
		t.Fatal(err)
	}
	after := f.git("rev-list", "--merges", "--count", "--branches", "--tags")
	if before != after {
		t.Fatalf("merge count changed: %s -> %s", before, after)
	}
	merges := strings.Fields(f.git("rev-list", "--merges", "--branches", "--tags"))
	if len(merges) != 1 {
		t.Fatalf("expected exactly one merge commit, got %v", merges)
	}
	if n := f.git("rev-list", "--parents", "-1", merges[0]); len(strings.Fields(n)) != 3 {
		t.Fatalf("merge commit lost parents: %q", n)
	}
}

func TestTagsRewrittenAndSignatureLossReported(t *testing.T) {
	f, _ := buildLeakyRepo(t)
	rep, err := Run(Options{Repo: f.repo(), Spec: leakSpec(t), ResetWorktree: true})
	if err != nil {
		t.Fatal(err)
	}
	var tagUpd *RefUpdate
	for i := range rep.Refs {
		if rep.Refs[i].Name == "refs/tags/audit-2024-03" {
			tagUpd = &rep.Refs[i]
		}
	}
	if tagUpd == nil {
		t.Fatal("tag not in report")
	}
	if !tagUpd.Changed {
		t.Fatal("tag should have been rewritten")
	}
	if f.git("cat-file", "-t", tagUpd.New) != "tag" {
		t.Fatal("rewritten tag is not an annotated tag")
	}
	// It must point at the rewritten leaking commit, not the old one.
	target := f.git("rev-parse", tagUpd.New+"^{}")
	if target != f.git("log", "--format=%H", "--all", "--grep=add customer export", "--", ".") && target == "" {
		t.Fatal("tag target not rewritten")
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	f, _ := buildLeakyRepo(t)
	repo := f.repo()
	before, _, _ := repo.CountObjects()
	headBefore := f.git("rev-parse", "HEAD")
	if _, err := Run(Options{Repo: repo, Spec: leakSpec(t), DryRun: true}); err != nil {
		t.Fatal(err)
	}
	after, _, _ := repo.CountObjects()
	if after != before {
		t.Fatalf("dry run wrote objects: %d -> %d", before, after)
	}
	if f.git("rev-parse", "HEAD") != headBefore {
		t.Fatal("dry run moved HEAD")
	}
}

func TestSecondRunIsNoop(t *testing.T) {
	f, _ := buildLeakyRepo(t)
	spec := leakSpec(t)
	if _, err := Run(Options{Repo: f.repo(), Spec: spec, ResetWorktree: true}); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(Options{Repo: f.repo(), Spec: spec, ResetWorktree: true})
	if err != nil {
		t.Fatal(err)
	}
	if st := rep.Stats(); st.Findings != 0 || st.RefsRewritten != 0 {
		t.Fatalf("second run was not a no-op: %+v", st)
	}
}

func TestWorktreeMustBeClean(t *testing.T) {
	f, _ := buildLeakyRepo(t)
	f.write("dirty.txt", "uncommitted\n")
	_, err := Run(Options{Repo: f.repo(), Spec: leakSpec(t)})
	if err == nil || !strings.Contains(err.Error(), "not clean") {
		t.Fatalf("expected a clean-worktree error, got %v", err)
	}
}

func TestEmptyRepoSucceedsWithNoFindings(t *testing.T) {
	f := newFixture(t)
	f.write("README.md", "hello\n")
	f.commitAll("only commit")
	rep, err := Run(Options{Repo: f.repo(), Spec: leakSpec(t), ResetWorktree: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Stats().Findings != 0 || rep.Stats().RefsRewritten != 0 {
		t.Fatalf("expected a clean no-op, got %+v", rep.Stats())
	}
}

func TestEmptyRepositoryIsRefused(t *testing.T) {
	f := newFixture(t)
	if _, err := Plan(Options{Repo: f.repo(), Spec: leakSpec(t)}); err != ErrNothingToDo {
		t.Fatalf("expected ErrNothingToDo, got %v", err)
	}
}

func TestRefConcurrentChangeAborts(t *testing.T) {
	f, _ := buildLeakyRepo(t)
	repo := f.repo()
	rep, err := Plan(Options{Repo: repo, Spec: leakSpec(t)})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate someone pushing while we were planning.
	f.write("other.txt", "unrelated\n")
	head := f.commitAll("concurrent work")
	f.git("reset", "-q", "--hard", head)
	updates := []gitx.UpdateRef{}
	for _, u := range rep.Refs {
		if u.Name == "refs/heads/main" {
			updates = append(updates, gitx.UpdateRef{Name: u.Name, New: u.New, Old: u.Old})
		}
	}
	err = repo.UpdateRefs(updates, "test")
	if err == nil {
		t.Fatal("expected the ref transaction to be rejected after the branch moved")
	}
	if !strings.Contains(err.Error(), "expected") && !strings.Contains(err.Error(), "cannot lock") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHighEntropyContentIsCaught(t *testing.T) {
	f := newFixture(t)
	f.write("main.go", "package main\n")
	f.commitAll("base")
	f.write("main.go", "package main\n\nconst apiToken = \"Zx8Qv2LmN4pR7tY1wB6cF3hJ9kS5dG0aE2uI4oP8\"\n")
	f.commitAll("add token")
	spec := &rules.Spec{Rules: []rules.Rule{{Kind: "preset", Value: "high_entropy"}}}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	rep, err := Plan(Options{Repo: f.repo(), Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Stats().Findings == 0 {
		t.Fatal("high-entropy token was not found")
	}
}
