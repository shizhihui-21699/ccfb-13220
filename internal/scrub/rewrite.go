package scrub

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"historyscrub/internal/gitx"
	"historyscrub/internal/rules"
)

// Options controls a rewrite.
type Options struct {
	Spec   *rules.Spec
	Repo   *gitx.Repo
	DryRun bool
	// BackupDir is where the backup manifest is written (default
	// <gitdir>/historyscrub).
	BackupDir string
	// Message is the reflog message used for the ref transaction.
	Message string
	// ResetWorktree checks out the rewritten HEAD so removed files stop
	// lingering in the working tree.
	ResetWorktree bool
	// Staged writes only the backup refs and leaves heads/tags untouched.
	// Used by the two-step API: stage, review, then apply.
	Staged bool
}

// Finding is one hit in one commit.
type Finding struct {
	Commit  string `json:"commit"`
	Path    string `json:"path"`
	Rule    string `json:"rule"`
	Kind    string `json:"kind"`
	Note    string `json:"note,omitempty"`
	Preview string `json:"preview,omitempty"`
	Line    int    `json:"line,omitempty"`
	Blob    string `json:"blob,omitempty"`
	Action  string `json:"action"` // delete-path, delete-content, message-redact, skipped
}

// SignatureLoss records a signature that cannot survive the rewrite.
type SignatureLoss struct {
	Kind     string `json:"kind"` // commit or tag
	Ref      string `json:"ref,omitempty"`
	OldOID   string `json:"old_oid"`
	NewOID   string `json:"new_oid"`
	OldSig   string `json:"old_signature_status"`
	Identity string `json:"identity,omitempty"`
	Key      string `json:"key,omitempty"`
	Reason   string `json:"reason"`
}

// RefUpdate describes a ref whose target changed.
type RefUpdate struct {
	Name    string `json:"name"`
	Old     string `json:"old"`
	New     string `json:"new"`
	Type    string `json:"type"`
	Changed bool   `json:"changed"`
}

// Report is the result of a Run or Plan.
type Report struct {
	DryRun           bool            `json:"dry_run"`
	Staged           bool            `json:"staged"`
	Repo             string          `json:"repo"`
	StartedAt        time.Time       `json:"started_at"`
	FinishedAt       time.Time       `json:"finished_at"`
	CommitsScanned   int             `json:"commits_scanned"`
	CommitsUnchanged int             `json:"commits_unchanged"`
	CommitsRewritten int             `json:"commits_rewritten"`
	Findings         []Finding       `json:"findings"`
	Refs             []RefUpdate     `json:"refs"`
	SignatureLosses  []SignatureLoss `json:"signature_losses"`
	BackupDir        string          `json:"backup_dir,omitempty"`
	BackupManifest   string          `json:"backup_manifest,omitempty"`
	Warnings         []string        `json:"warnings"`
	Verification     *Verification   `json:"verification,omitempty"`
	Prune            *PruneResult    `json:"prune,omitempty"`
}

// Stats summarizes a report.
type Stats struct {
	Findings        int `json:"findings"`
	CommitsAffected int `json:"commits_affected"`
	RefsRewritten   int `json:"refs_rewritten"`
	SignatureLosses int `json:"signature_losses"`
}

// Stats summarizes a report.
func (r *Report) Stats() Stats {
	affected := map[string]bool{}
	for _, f := range r.Findings {
		if f.Commit != "" {
			affected[f.Commit] = true
		}
	}
	refs := 0
	for _, u := range r.Refs {
		if u.Changed {
			refs++
		}
	}
	return Stats{
		Findings:        len(r.Findings),
		CommitsAffected: len(affected),
		RefsRewritten:   refs,
		SignatureLosses: len(r.SignatureLosses),
	}
}

// SensitiveObjects lists the objects the scrub must make unreachable: every
// matched blob, plus the pre-rewrite target of every ref that will change.
func (r *Report) SensitiveObjects() []SensitiveObject {
	byOID := map[string]*SensitiveObject{}
	add := func(oid, kind, path string) {
		if oid == "" {
			return
		}
		s, ok := byOID[oid]
		if !ok {
			s = &SensitiveObject{OID: oid, Kind: kind}
			byOID[oid] = s
		}
		if path != "" {
			for _, p := range s.Paths {
				if p == path {
					return
				}
			}
			s.Paths = append(s.Paths, path)
		}
	}
	for _, f := range r.Findings {
		if f.Blob != "" && (f.Action == "delete-path" || f.Action == "delete-content") {
			add(f.Blob, "blob", f.Path)
		}
	}
	for _, u := range r.Refs {
		if u.Changed {
			add(u.Old, u.Type, "")
		}
	}
	out := make([]SensitiveObject, 0, len(byOID))
	for _, s := range byOID {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OID < out[j].OID })
	return out
}

var (
	// ErrNothingToDo is returned when no refs match the rewrite scope.
	ErrNothingToDo = errors.New("no refs to rewrite (refs/heads and refs/tags are both empty)")
	// ErrNotClean is returned when the worktree has uncommitted changes.
	ErrNotClean = errors.New("worktree is not clean")
)

// planner holds the state of one analysis.
type planner struct {
	repo     *gitx.Repo
	reader   *gitx.BatchReader
	rw       *treeRewriter
	rep      *Report
	compiled *rules.Compiled
	refs     []gitx.Ref // heads + tags, as read at the start
	commits  []gitx.CommitLine
	objs     map[string]*gitx.Commit
	newTree  map[string]string
	newCmt   map[string]string
	newTag   map[string]string
	head     gitx.HeadInfo
	detached bool
	preCSig  map[string]gitx.SignatureStatus
	preTSig  map[string]gitx.SignatureStatus
}

// Plan analyses the repository without changing anything.
func Plan(opts Options) (*Report, error) {
	p, err := newPlanner(opts, true)
	if err != nil {
		return nil, err
	}
	defer p.close()
	return p.run()
}

// Run analyses and then applies the rewrite.
func Run(opts Options) (*Report, error) {
	if opts.DryRun {
		return Plan(opts)
	}
	p, err := newPlanner(opts, false)
	if err != nil {
		return nil, err
	}
	defer p.close()
	rep, err := p.run()
	if err != nil {
		return nil, err
	}
	if err := p.apply(opts); err != nil {
		return nil, err
	}
	return rep, nil
}

func newPlanner(opts Options, dry bool) (*planner, error) {
	if opts.Repo == nil || opts.Spec == nil {
		return nil, errors.New("scrub: repo and spec are required")
	}
	compiled, err := rules.Compile(opts.Spec)
	if err != nil {
		return nil, err
	}
	repo := opts.Repo
	rep := &Report{DryRun: dry, Repo: repo.Dir, StartedAt: time.Now().UTC(), CommitsUnchanged: 0}
	if repo.Shallow {
		rep.Warnings = append(rep.Warnings, "repository is shallow: history behind the shallow boundary is absent and cannot be scrubbed. Run `git fetch --unshallow` on a mirror used for cleanup.")
	}
	if states := repo.State(); len(states) > 0 {
		return nil, fmt.Errorf("repository has an operation in progress (%s); finish or abort it first", strings.Join(states, ", "))
	}
	dirty, err := repo.DirtyFiles()
	if err != nil {
		return nil, err
	}
	if len(dirty) > 0 {
		if !dry {
			return nil, fmt.Errorf("%w: commit, stash or discard %d change(s) first (e.g. %q)", ErrNotClean, len(dirty), firstLine(dirty[0]))
		}
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("worktree has %d uncommitted change(s); a real run refuses until they are resolved", len(dirty)))
	}

	refs, err := repo.WorktreeRefs()
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, ErrNothingToDo
	}
	p := &planner{
		repo: repo, rep: rep, compiled: compiled, refs: refs,
		objs:    map[string]*gitx.Commit{},
		newTree: map[string]string{},
		newCmt:  map[string]string{},
		newTag:  map[string]string{},
		preCSig: map[string]gitx.SignatureStatus{},
		preTSig: map[string]gitx.SignatureStatus{},
	}

	otherRefs, err := repo.OtherRefs()
	if err != nil {
		return nil, err
	}
	for _, r := range otherRefs {
		if strings.HasPrefix(r.Name, backupRefPrefix) {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("backup ref %s keeps pre-rewrite objects reachable on purpose; delete refs/historyscrub/* and prune once you are satisfied", r.Name))
			continue
		}
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s (%s) is outside the rewrite scope and keeps pre-rewrite objects reachable; delete it (and any remote-tracking copy) before pruning", r.Name, shortOID(r.OID)))
	}

	p.head, err = repo.Head()
	if err != nil {
		return nil, err
	}
	p.detached = p.head.Symbolic == "" && p.head.OID != ""

	tips := []string{}
	tipSet := map[string]bool{}
	for _, r := range refs {
		if r.Type == "commit" {
			if !tipSet[r.OID] {
				tipSet[r.OID] = true
				tips = append(tips, r.OID)
			}
			continue
		}
		if r.PeeledType == "commit" && r.Peeled != "" && !tipSet[r.Peeled] {
			tipSet[r.Peeled] = true
			tips = append(tips, r.Peeled)
		}
	}
	if p.detached && !tipSet[p.head.OID] {
		tips = append(tips, p.head.OID)
	}
	if len(tips) == 0 {
		return nil, ErrNothingToDo
	}

	p.commits, err = repo.Commits(tips)
	if err != nil {
		return nil, err
	}
	rep.CommitsScanned = len(p.commits)

	p.reader, err = repo.NewBatchReader()
	if err != nil {
		return nil, err
	}
	for _, cl := range p.commits {
		typ, raw, err := p.reader.Read(cl.OID)
		if err != nil {
			return nil, fmt.Errorf("read commit %s: %w", cl.OID, err)
		}
		if typ != "commit" {
			return nil, fmt.Errorf("object %s walked as a commit is a %s", cl.OID, typ)
		}
		c, err := gitx.ParseCommit(cl.OID, raw)
		if err != nil {
			return nil, err
		}
		p.objs[cl.OID] = c
	}
	p.rw = newTreeRewriter(repo, p.reader, compiled, dry)
	return p, nil
}

func (p *planner) close() {
	if p.reader != nil {
		p.reader.Close()
	}
}

func (p *planner) run() (*Report, error) {
	rep := p.rep
	repo := p.repo
	compiled := p.compiled

	// Signatures are evidence about the original objects: verify before any
	// rewrite changes them.
	var signed []string
	for _, cl := range p.commits {
		if p.objs[cl.OID].Signed {
			signed = append(signed, cl.OID)
		}
	}
	if len(signed) > 0 {
		sigs, err := repo.VerifyCommits(signed)
		if err != nil {
			rep.Warnings = append(rep.Warnings, "could not verify commit signatures: "+err.Error())
		}
		p.preCSig = sigs
	}
	for _, r := range p.refs {
		if r.Type != "tag" || len(r.Signature) == 0 {
			continue
		}
		st, err := repo.VerifyTag(r.Name)
		if err != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("could not verify tag %s: %v", r.Name, err))
			continue
		}
		p.preTSig[r.Name] = st
	}

	// Pass 0: when whole-file purge is on, find every path that ever matched so
	// that earlier clean versions of the same file disappear too.
	rootTrees := make([]string, 0, len(p.commits))
	seenTree := map[string]bool{}
	for _, cl := range p.commits {
		t := p.objs[cl.OID].Tree
		if !seenTree[t] {
			seenTree[t] = true
			rootTrees = append(rootTrees, t)
		}
	}
	if err := p.rw.prescan(rootTrees); err != nil {
		return nil, err
	}

	// Pass 1: report findings per commit (read-only walk).
	for _, cl := range p.commits {
		c := p.objs[cl.OID]
		findings, err := p.rw.collectTree(c.Tree, "")
		if err != nil {
			return nil, fmt.Errorf("scan commit %s: %w", shortOID(cl.OID), err)
		}
		for _, f := range findings {
			f.Commit = cl.OID
			rep.Findings = append(rep.Findings, f)
		}
		if compiled.ScanCommitMessages() {
			_, hits := compiled.RedactMessage(c.Message)
			for _, h := range hits {
				rep.Findings = append(rep.Findings, Finding{
					Commit: cl.OID, Rule: rules.DescribeRule(h.Rule), Kind: h.Rule.Kind,
					Note: h.Rule.Note, Preview: rules.FormatPreview(h.Match, 3), Line: h.Line,
					Action: "message-redact",
				})
			}
		}
	}

	// Pass 2: rewrite trees.
	for _, cl := range p.commits {
		c := p.objs[cl.OID]
		nt, err := p.rw.rewriteTree(c.Tree, "")
		if err != nil {
			return nil, fmt.Errorf("tree of commit %s: %w", shortOID(cl.OID), err)
		}
		p.newTree[cl.OID] = nt
	}

	// Pass 3: rewrite commits, parents first (Commits is topo+reverse).
	for _, cl := range p.commits {
		c := p.objs[cl.OID]
		newParents := make([]string, 0, len(c.Parents))
		parentChanged := false
		for _, par := range c.Parents {
			np, ok := p.newCmt[par]
			if !ok {
				return nil, fmt.Errorf("commit %s: parent %s is outside the walked history (grafted, shallow or partial repo?)", shortOID(cl.OID), shortOID(par))
			}
			newParents = append(newParents, np)
			if np != par {
				parentChanged = true
			}
		}
		newTree := p.newTree[cl.OID]
		msg := c.Message
		msgChanged := false
		if compiled.ScanCommitMessages() {
			redacted, hits := compiled.RedactMessage(msg)
			if len(hits) > 0 {
				msg, msgChanged = redacted, true
			}
		}
		if newTree == c.Tree && !parentChanged && !msgChanged {
			p.newCmt[cl.OID] = cl.OID
			rep.CommitsUnchanged++
			continue
		}
		c2 := *c
		c2.Message = msg
		data := c2.Serialize(newTree, newParents)
		oid, err := p.rw.write("commit", data)
		if err != nil {
			return nil, fmt.Errorf("write rewritten commit for %s: %w", shortOID(cl.OID), err)
		}
		p.newCmt[cl.OID] = oid
		rep.CommitsRewritten++
	}

	// Pass 4: branch refs.
	for _, r := range p.refs {
		if r.Type == "tag" {
			continue
		}
		newOID := r.OID
		if r.Type == "commit" {
			nc, ok := p.newCmt[r.OID]
			if !ok {
				return nil, fmt.Errorf("branch %s points at %s, which was not walked", r.Name, shortOID(r.OID))
			}
			newOID = nc
		} else {
			no, err := p.rw.rewriteDetached(r.OID, r.Type, r.Name)
			if err != nil {
				return nil, err
			}
			newOID = no
		}
		rep.Refs = append(rep.Refs, RefUpdate{Name: r.Name, Old: r.OID, New: newOID, Type: r.Type, Changed: newOID != r.OID})
	}

	// Pass 5: annotated tags, with recursion for tags that point at tags.
	var rewriteTag func(oid string) (string, error)
	rewriteTag = func(oid string) (string, error) {
		if v, ok := p.newTag[oid]; ok {
			return v, nil
		}
		typ, raw, err := p.reader.Read(oid)
		if err != nil {
			return "", fmt.Errorf("read tag %s: %w", shortOID(oid), err)
		}
		if typ != "tag" {
			return "", fmt.Errorf("%s is a %s, not a tag object", shortOID(oid), typ)
		}
		t, err := gitx.ParseTag(oid, raw)
		if err != nil {
			return "", err
		}
		var newTarget string
		switch t.Type {
		case "commit":
			nc, ok := p.newCmt[t.Object]
			if !ok {
				return "", fmt.Errorf("tag %s points at commit %s, outside the walked history", shortOID(oid), shortOID(t.Object))
			}
			newTarget = nc
		case "tag":
			nt, err := rewriteTag(t.Object)
			if err != nil {
				return "", err
			}
			newTarget = nt
		default:
			nt, err := p.rw.rewriteDetached(t.Object, t.Type, shortOID(oid))
			if err != nil {
				return "", err
			}
			newTarget = nt
		}
		newOID := oid
		if newTarget != t.Object {
			// The signature covered the old target, so it cannot verify now.
			data := t.Serialize(newTarget, false)
			newOID, err = p.rw.write("tag", data)
			if err != nil {
				return "", fmt.Errorf("write rewritten tag %s: %w", shortOID(oid), err)
			}
		}
		p.newTag[oid] = newOID
		return newOID, nil
	}
	for _, r := range p.refs {
		if r.Type != "tag" {
			continue
		}
		newOID, err := rewriteTag(r.OID)
		if err != nil {
			return nil, err
		}
		rep.Refs = append(rep.Refs, RefUpdate{Name: r.Name, Old: r.OID, New: newOID, Type: "tag", Changed: newOID != r.OID})
	}
	sort.Slice(rep.Refs, func(i, j int) bool { return rep.Refs[i].Name < rep.Refs[j].Name })

	p.collectSignatureLosses()
	SortFindings(rep.Findings)
	rep.FinishedAt = time.Now().UTC()
	return rep, nil
}

func (p *planner) collectSignatureLosses() {
	rep := p.rep
	for _, cl := range p.commits {
		c := p.objs[cl.OID]
		if !c.Signed {
			continue
		}
		nc := p.newCmt[cl.OID]
		if nc == cl.OID {
			continue // untouched commit: its signature is still valid
		}
		st := p.preCSig[cl.OID]
		old := st.Human()
		if st.Status == "" {
			old = "unverified"
		}
		rep.SignatureLosses = append(rep.SignatureLosses, SignatureLoss{
			Kind: "commit", OldOID: cl.OID, NewOID: nc,
			OldSig: old, Identity: gitx.IdentityOf(c.Author), Key: st.Finger,
			Reason: "tree/parents/message changed, so the object id changed and the embedded signature no longer matches",
		})
	}
	byName := map[string]RefUpdate{}
	for _, u := range rep.Refs {
		byName[u.Name] = u
	}
	for name, st := range p.preTSig {
		u, ok := byName[name]
		if !ok || !u.Changed {
			continue
		}
		var tagger string
		if typ, raw, err := p.reader.Read(u.Old); err == nil && typ == "tag" {
			if t, err := gitx.ParseTag(u.Old, raw); err == nil {
				tagger = gitx.IdentityOf(t.Tagger)
			}
		}
		rep.SignatureLosses = append(rep.SignatureLosses, SignatureLoss{
			Kind: "tag", Ref: name, OldOID: u.Old, NewOID: u.New,
			OldSig: st.Human(), Identity: tagger, Key: st.Finger,
			Reason: "signed tag pointed at rewritten history, so its signature was dropped",
		})
	}
	sort.Slice(rep.SignatureLosses, func(i, j int) bool {
		a, b := rep.SignatureLosses[i], rep.SignatureLosses[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.OldOID != b.OldOID {
			return a.OldOID < b.OldOID
		}
		return a.Ref < b.Ref
	})
}

// apply performs the mutating half: backup refs, one ref transaction, and an
// optional worktree reset.
func (p *planner) apply(opts Options) error {
	rep := p.rep
	repo := p.repo
	msg := opts.Message
	if msg == "" {
		msg = "historyscrub: remove matched paths and content from history"
	}
	somethingToDo := false
	for _, u := range rep.Refs {
		if u.Changed {
			somethingToDo = true
			break
		}
	}
	if !somethingToDo {
		return nil
	}

	backupDir := opts.BackupDir
	if backupDir == "" {
		backupDir = repo.GitDir + "/historyscrub"
	}
	manifest, err := writeBackupRefs(repo, p.refs, backupDir)
	if err != nil {
		return err
	}
	rep.BackupDir = backupDir
	rep.BackupManifest = manifest

	var updates []gitx.UpdateRef
	for _, u := range rep.Refs {
		updates = append(updates, gitx.UpdateRef{Name: u.Name, New: u.New, Old: u.Old})
	}
	if err := repo.UpdateRefs(updates, msg); err != nil {
		return fmt.Errorf("ref transaction rejected, no ref was changed: %w", err)
	}
	if p.detached {
		if nc, ok := p.newCmt[p.head.OID]; ok && nc != p.head.OID {
			if err := repo.SetDetachedHead(nc); err != nil {
				rep.Warnings = append(rep.Warnings, "detached HEAD was not moved to the rewritten commit: "+err.Error())
			}
		}
	}
	if opts.ResetWorktree && !repo.Bare {
		if _, err := repo.Output("reset", "--hard", "HEAD"); err != nil {
			rep.Warnings = append(rep.Warnings, "refs were rewritten but the working tree could not be reset; run `git reset --hard` yourself: "+err.Error())
		}
	}
	return nil
}

func shortOID(oid string) string {
	if len(oid) > 12 {
		return oid[:12]
	}
	return oid
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
