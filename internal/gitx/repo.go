// Package gitx is a small, strict wrapper around the git plumbing commands
// used by the history scrubber. It deliberately shells out to git for
// reachability, packing and signature verification (those are hard to get
// right), but reads and writes loose objects by format so that history can be
// rebuilt object-by-object without fast-export's limitations around signed
// tags.
package gitx

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrMissingObject is returned when an object is not in the object database.
var ErrMissingObject = errors.New("object not found")

// Repo is an opened git repository.
type Repo struct {
	Dir          string // working directory passed to git -C (or bare repo path)
	GitDir       string
	ObjectDir    string
	Bare         bool
	Shallow      bool
	ObjectFormat string // "sha1" or "sha256"
	HashLen      int    // 20 or 32
}

// Open resolves repository metadata.
func Open(dir string) (*Repo, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	r := &Repo{Dir: abs}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("open repo: %w", err)
	}
	out, err := r.Output("rev-parse", "--absolute-git-dir")
	if err != nil {
		return nil, fmt.Errorf("not a git repository: %w", err)
	}
	r.GitDir = strings.TrimSpace(out)
	if out, err = r.Output("rev-parse", "--show-object-format"); err == nil {
		r.ObjectFormat = strings.TrimSpace(out)
	}
	if r.ObjectFormat == "" {
		r.ObjectFormat = "sha1"
	}
	switch r.ObjectFormat {
	case "sha1":
		r.HashLen = 20
	case "sha256":
		r.HashLen = 32
	default:
		return nil, fmt.Errorf("unsupported object format %q", r.ObjectFormat)
	}
	if out, err = r.Output("rev-parse", "--path-format=absolute", "--git-path", "objects"); err == nil {
		r.ObjectDir = strings.TrimSpace(out)
	}
	if r.ObjectDir == "" {
		return nil, errors.New("cannot resolve object directory")
	}
	if out, err = r.Output("rev-parse", "--is-bare-repository"); err == nil {
		r.Bare = strings.TrimSpace(out) == "true"
	}
	if out, err = r.Output("rev-parse", "--is-shallow-repository"); err == nil {
		r.Shallow = strings.TrimSpace(out) == "true"
	}
	return r, nil
}

func (r *Repo) command(args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.Dir
	none := true
	env := os.Environ()
	env = append(env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LITERAL_PATHSPECS=1", // never interpret user paths as magic pathspecs
		"LC_ALL=C",
		"LANG=C",
	)
	if none {
		env = append(env, "GIT_OPTIONAL_LOCKS=0")
	}
	cmd.Env = env
	return cmd
}

// Output runs git and returns stdout, with stderr attached to the error.
func (r *Repo) Output(args ...string) (string, error) {
	cmd := r.command(args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}

// OutputBoth runs git and returns stdout and stderr together. Signature
// verification writes its verdict to stderr, so callers that parse it need this.
func (r *Repo) OutputBoth(args ...string) (string, string, error) {
	cmd := r.command(args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), stderr.String(), fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), stderr.String(), nil
}

// Run runs git and discards output.
func (r *Repo) Run(args ...string) error {
	_, err := r.Output(args...)
	return err
}

// RunInput runs git feeding stdin and returns stdout.
func (r *Repo) RunInput(stdin []byte, args ...string) (string, error) {
	cmd := r.command(args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}

// Ref is a reference and its target.
type Ref struct {
	Name       string // full ref name
	Short      string
	OID        string
	Type       string // commit, tag, tree, blob
	Peeled     string // for annotated tags: the commit/tree/blob it peels to
	PeeledType string
	Size       int64
	Signature  string // tag signature body, if any
}

// IsTag reports whether this ref is an annotated tag object.
func (x Ref) IsTag() bool { return x.Type == "tag" }

// Target returns the object that should be rewritten for this ref.
func (x Ref) Target() (string, string) {
	if x.Type == "tag" {
		return x.Peeled, x.PeeledType
	}
	return x.OID, x.Type
}

// ListRefs returns refs matching the given prefixes (full names).
func (r *Repo) ListRefs(prefixes ...string) ([]Ref, error) {
	out, err := r.Output(append([]string{"for-each-ref",
		"--format=%(refname)%00%(objectname)%00%(objecttype)%00%(*objectname)%00%(*objecttype)%00%(objectsize)%00%(contents:signature)%00"},
		prefixes...)...)
	if err != nil {
		return nil, err
	}
	var refs []Ref
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x00")
		if len(f) < 7 {
			continue
		}
		ref := Ref{Name: f[0], OID: f[1], Type: f[2], Peeled: f[3], PeeledType: f[4], Signature: f[6]}
		ref.Short = strings.TrimPrefix(strings.TrimPrefix(ref.Name, "refs/heads/"), "refs/tags/")
		ref.Size, _ = strconv.ParseInt(f[5], 10, 64)
		refs = append(refs, ref)
	}
	return refs, nil
}

// WorktreeRefs are the refs the scrubber rewrites by default.
func (r *Repo) WorktreeRefs() ([]Ref, error) { return r.ListRefs("refs/heads", "refs/tags") }

// OtherRefs returns refs outside the rewrite scope that could keep the old
// history alive (remotes, stash, notes, replace, custom refs).
func (r *Repo) OtherRefs() ([]Ref, error) {
	all, err := r.ListRefs("refs")
	if err != nil {
		return nil, err
	}
	var out []Ref
	for _, ref := range all {
		if strings.HasPrefix(ref.Name, "refs/heads/") || strings.HasPrefix(ref.Name, "refs/tags/") {
			continue
		}
		out = append(out, ref)
	}
	return out, nil
}

// CommitLine is one commit with its parent list.
type CommitLine struct {
	OID     string
	Parents []string
}

// Commits returns commits reachable from the given tips in parents-first order.
func (r *Repo) Commits(tips []string) ([]CommitLine, error) {
	args := append([]string{"rev-list", "--topo-order", "--reverse", "--parents"}, tips...)
	out, err := r.Output(args...)
	if err != nil {
		return nil, err
	}
	var commits []CommitLine
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		commits = append(commits, CommitLine{OID: f[0], Parents: f[1:]})
	}
	return commits, nil
}

// ObjectPath is an object id with an example path from rev-list --objects.
type ObjectPath struct {
	OID  string
	Path string
}

// AllObjects lists objects reachable from all refs (plus HEAD when detached).
func (r *Repo) AllObjects(extraTips ...string) ([]ObjectPath, error) {
	args := []string{"rev-list", "--objects", "--all"}
	args = append(args, extraTips...)
	out, err := r.Output(args...)
	if err != nil {
		return nil, err
	}
	var objs []ObjectPath
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		oid := line
		path := ""
		if i := strings.IndexByte(line, ' '); i > 0 {
			oid, path = line[:i], line[i+1:]
		}
		objs = append(objs, ObjectPath{OID: oid, Path: path})
	}
	return objs, nil
}

// HashObject computes the object id without writing anything.
func (r *Repo) HashObject(typ string, data []byte) string {
	h := r.newHash()
	fmt.Fprintf(h, "%s %d\x00", typ, len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func (r *Repo) newHash() hashWriter {
	if r.HashLen == 32 {
		return sha256.New()
	}
	return sha1.New()
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

// WriteObject writes a loose object and returns its id.
func (r *Repo) WriteObject(typ string, data []byte) (string, error) {
	oid := r.HashObject(typ, data)
	path := r.objectPath(oid)
	if _, err := os.Stat(path); err == nil {
		return oid, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "scrub-tmp-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	zw := zlib.NewWriter(tmp)
	fmt.Fprintf(zw, "%s %d\x00", typ, len(data))
	if _, err := zw.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmpName, 0o444); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", err
	}
	return oid, nil
}

func (r *Repo) objectPath(oid string) string {
	if len(oid) < 3 {
		return filepath.Join(r.ObjectDir, oid)
	}
	return filepath.Join(r.ObjectDir, oid[:2], oid[2:])
}

// HasObject reports whether an object exists locally.
func (r *Repo) HasObject(oid string) bool {
	cmd := r.command("cat-file", "-e", oid)
	return cmd.Run() == nil
}

// ReadObject reads one object (for small objects; prefer BatchReader in loops).
func (r *Repo) ReadObject(oid string) (string, []byte, error) {
	br, err := r.NewBatchReader()
	if err != nil {
		return "", nil, err
	}
	defer br.Close()
	return br.Read(oid)
}

// EmptyTree returns the empty tree id for this repo's hash format.
func (r *Repo) EmptyTree() string {
	return r.HashObject("tree", nil)
}

// HeadInfo describes HEAD.
type HeadInfo struct {
	Symbolic string // e.g. refs/heads/main, empty when detached
	OID      string // resolved commit, empty on unborn branch
}

// Head reads HEAD.
func (r *Repo) Head() (HeadInfo, error) {
	var h HeadInfo
	if out, err := r.Output("symbolic-ref", "-q", "HEAD"); err == nil {
		h.Symbolic = strings.TrimSpace(out)
	}
	if out, err := r.Output("rev-parse", "--verify", "-q", "HEAD"); err == nil {
		h.OID = strings.TrimSpace(out)
	}
	return h, nil
}

// StatusEntry reports whether the worktree is clean.
func (r *Repo) DirtyFiles() ([]string, error) {
	if r.Bare {
		return nil, nil
	}
	out, err := r.Output("status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return nil, err
	}
	var f []string
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line != "" {
			f = append(f, line)
		}
	}
	return f, nil
}

// State detects in-progress operations that would interfere with a rewrite.
func (r *Repo) State() []string {
	var states []string
	for _, name := range []string{"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD", "rebase-merge", "rebase-apply", "BISECT_LOG"} {
		if _, err := os.Stat(filepath.Join(r.GitDir, name)); err == nil {
			states = append(states, name)
		}
	}
	return states
}

// UpdateRef is a single atomic ref update with an expected old value.
type UpdateRef struct {
	Name string
	New  string
	Old  string // empty means "must not exist"
}

// UpdateRefs applies all updates in one transaction.
func (r *Repo) UpdateRefs(updates []UpdateRef, message string) error {
	var buf bytes.Buffer
	buf.WriteString("start\x00")
	for _, u := range updates {
		buf.WriteString("update ")
		buf.WriteString(u.Name)
		buf.WriteByte(0)
		buf.WriteString(u.New)
		buf.WriteByte(0)
		buf.WriteString(u.Old)
		buf.WriteByte(0)
	}
	buf.WriteString("prepare\x00")
	buf.WriteString("commit\x00")
	_, err := r.RunInput(buf.Bytes(), "update-ref", "--stdin", "-z", "-m", message)
	return err
}

// SetDetachedHead points HEAD directly at a commit.
func (r *Repo) SetDetachedHead(oid string) error {
	return r.Run("update-ref", "--no-deref", "HEAD", oid)
}

// GitConfig reads one config value.
func (r *Repo) GitConfig(key string) string {
	out, err := r.Output("config", "--get", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// CountObjects returns loose+packed object counts.
func (r *Repo) CountObjects() (count int64, sizeBytes int64, err error) {
	out, err := r.Output("count-objects", "-v")
	if err != nil {
		return 0, 0, err
	}
	var loose, inPack, sizePack, sizeLoose int64
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "count":
			loose = n
		case "in-pack":
			inPack = n
		case "size":
			sizeLoose = n
		case "size-pack":
			sizePack = n
		}
	}
	return loose + inPack, (sizeLoose + sizePack) * 1024, nil
}
