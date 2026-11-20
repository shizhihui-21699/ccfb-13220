package scrub

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"historyscrub/internal/gitx"
	"historyscrub/internal/rules"
)

// ObjectCheck is the post-rewrite state of one sensitive object.
type ObjectCheck struct {
	OID        string   `json:"oid"`
	Kind       string   `json:"kind"` // commit, blob, tree, tag
	Paths      []string `json:"paths,omitempty"`
	InObjectDB bool     `json:"in_object_db"`
	// ReachedBy lists refs that still reach the object. A live ref here is a
	// failure; only backup refs is "recoverable, not yet pruned".
	ReachedBy []string `json:"reached_by,omitempty"`
	// Status is "removed" (not in the object database), "unreachable" (present
	// but only reachable via backups or nothing), or "reachable" (survived).
	Status string `json:"status"`
	// ViaBackupOnly marks an object kept alive solely by refs/historyscrub.
	ViaBackupOnly bool `json:"via_backup_only,omitempty"`
}

// ContentRescan is the result of re-scanning everything still reachable.
type ContentRescan struct {
	BlobsScanned   int       `json:"blobs_scanned"`
	CommitsScanned int       `json:"commits_scanned"`
	Hits           []Finding `json:"hits"`
	BackupOnlyHits []Finding `json:"backup_only_hits"`
	TooBig         []string  `json:"too_big,omitempty"`
}

// Verification is the object-level proof that the scrub worked.
type Verification struct {
	CheckedAt      time.Time     `json:"checked_at"`
	Objects        []ObjectCheck `json:"objects"`
	Removed        int           `json:"removed_from_object_db"`
	Unreachable    int           `json:"present_but_unreachable"`
	StillReachable int           `json:"still_reachable"`
	BackupOnly     int           `json:"backup_only"`
	Rescan         ContentRescan `json:"content_rescan"`
	BackupRefs     []string      `json:"backup_refs,omitempty"`
	LiveRefs       int           `json:"live_refs_checked"`
	Passed         bool          `json:"passed"`
	Notes          []string      `json:"notes,omitempty"`
}

// VerifyOptions controls Verify.
type VerifyOptions struct {
	Repo *gitx.Repo
	Spec *rules.Spec
	// Sensitive lists the objects that must be gone.
	Sensitive []SensitiveObject
}

// SensitiveObject is an object that must not survive, with the paths it lived at.
type SensitiveObject struct {
	OID   string
	Kind  string
	Paths []string
}

// refScope records which refs reach an object.
type refScope struct {
	live   bool // a ref other than our own backup namespace
	backup bool
	names  []string
}

// Verify proves, from the object database up, that the sensitive objects are
// absent or unreachable from live refs, and that nothing reachable from a live
// ref still matches the content rules.
//
// Objects kept alive only by refs/historyscrub (our own pre-rewrite backups) are
// reported separately: they are recoverable by design until Prune removes them,
// and counting them as a failure would make the tool's own safety net look like
// a leak.
func Verify(opts VerifyOptions) (*Verification, error) {
	repo := opts.Repo
	if repo == nil {
		return nil, fmt.Errorf("verify: repo is required")
	}
	v := &Verification{CheckedAt: time.Now().UTC()}

	refs, err := repo.ListRefs("refs")
	if err != nil {
		return nil, err
	}
	scope := map[string]*refScope{}
	liveRoots := []string{}
	for _, r := range refs {
		isBackup := strings.HasPrefix(r.Name, backupRefPrefix)
		if !isBackup {
			liveRoots = append(liveRoots, r.Name)
		}
		v.LiveRefs++
		// Build "oid -> refs" from each ref's own history, so a blob is
		// attributed to the exact refs that reach it.
		if err := eachObject(repo, r.Name, func(oid string) {
			s := scope[oid]
			if s == nil {
				s = &refScope{}
				scope[oid] = s
			}
			if isBackup {
				s.backup = true
			} else {
				s.live = true
			}
			s.names = append(s.names, r.Name)
		}); err != nil {
			return nil, fmt.Errorf("walk %s: %w", r.Name, err)
		}
	}
	// A detached HEAD is a reachability root too.
	if head, err := repo.Head(); err == nil && head.Symbolic == "" && head.OID != "" {
		if err := eachObject(repo, head.OID, func(oid string) {
			s := scope[oid]
			if s == nil {
				s = &refScope{}
				scope[oid] = s
			}
			s.live = true
			s.names = append(s.names, "HEAD")
		}); err != nil {
			return nil, err
		}
	}

	for _, s := range opts.Sensitive {
		oc := ObjectCheck{OID: s.OID, Kind: s.Kind, Paths: s.Paths}
		oc.InObjectDB = repo.HasObject(s.OID)
		sc := scope[s.OID]
		switch {
		case sc != nil && sc.live:
			oc.Status = "reachable"
			oc.ReachedBy = sc.names
			v.StillReachable++
		case sc != nil && sc.backup:
			oc.Status = "backup-only"
			oc.ViaBackupOnly = true
			oc.ReachedBy = sc.names
			v.BackupOnly++
		case !oc.InObjectDB:
			oc.Status = "removed"
			v.Removed++
		default:
			oc.Status = "unreachable"
			v.Unreachable++
		}
		v.Objects = append(v.Objects, oc)
	}
	sort.Slice(v.Objects, func(i, j int) bool { return v.Objects[i].OID < v.Objects[j].OID })

	if opts.Spec != nil {
		if err := rescan(repo, v, opts.Spec, liveRoots); err != nil {
			v.Notes = append(v.Notes, "content rescan incomplete: "+err.Error())
		}
	}

	for _, r := range refs {
		if strings.HasPrefix(r.Name, backupRefPrefix) {
			v.BackupRefs = append(v.BackupRefs, r.Name)
		}
	}
	if len(v.BackupRefs) > 0 {
		v.Notes = append(v.Notes, fmt.Sprintf("%d backup ref(s) under %s keep pre-rewrite objects recoverable. Run `prune` to delete them and make those objects unreachable.", len(v.BackupRefs), backupRefPrefix))
	}
	if v.Rescan.TooBig != nil {
		v.Notes = append(v.Notes, fmt.Sprintf("%d reachable blob(s) exceed the scan limit and were not inspected for content", len(v.Rescan.TooBig)))
	}

	v.Passed = v.StillReachable == 0 && len(v.Rescan.Hits) == 0
	return v, nil
}

// eachObject calls fn for every object reachable from root.
func eachObject(repo *gitx.Repo, root string, fn func(string)) error {
	out, err := repo.Output("rev-list", "--objects", root, "--")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		oid := line
		if i := strings.IndexByte(line, ' '); i > 0 {
			oid = line[:i]
		}
		fn(oid)
	}
	return nil
}

// rescan walks every blob and commit message reachable from liveRoots and
// reports anything that still matches the rules. Objects reachable only from
// backup refs are reported separately.
func rescan(repo *gitx.Repo, v *Verification, spec *rules.Spec, liveRoots []string) error {
	compiled, err := rules.Compile(spec)
	if err != nil {
		return err
	}
	live, err := objectPaths(repo, liveRoots)
	if err != nil {
		return err
	}
	backupRefs, err := repo.ListRefs(backupRefPrefix)
	if err != nil {
		return err
	}
	backup := map[string]string{}
	if len(backupRefs) > 0 {
		roots := make([]string, 0, len(backupRefs))
		for _, b := range backupRefs {
			roots = append(roots, b.Name)
		}
		backup, err = objectPaths(repo, roots)
		if err != nil {
			return err
		}
	}

	reader, err := repo.NewBatchReader()
	if err != nil {
		return err
	}
	defer reader.Close()

	const maxHits = 500
	// Live objects first: a hit here is a real failure.
	oids := make([]string, 0, len(live))
	for oid := range live {
		oids = append(oids, oid)
	}
	sort.Strings(oids)
	for _, oid := range oids {
		if len(v.Rescan.Hits) >= maxHits {
			break
		}
		typ, data, err := reader.Read(oid)
		if err != nil {
			continue
		}
		switch typ {
		case "blob":
			v.Rescan.BlobsScanned++
			if int64(len(data)) > compiled.MaxScanBytes() {
				v.Rescan.TooBig = append(v.Rescan.TooBig, live[oid])
				continue
			}
			for _, h := range compiled.ScanContent(data) {
				v.Rescan.Hits = append(v.Rescan.Hits, Finding{
					Path: live[oid], Rule: rules.DescribeRule(h.Rule), Kind: h.Rule.Kind,
					Preview: rules.FormatPreview(h.Match, 3), Line: h.Line, Blob: oid, Action: "survived",
				})
			}
		case "commit":
			v.Rescan.CommitsScanned++
			if !compiled.ScanCommitMessages() {
				continue
			}
			c, err := gitx.ParseCommit(oid, data)
			if err != nil {
				continue
			}
			if _, hits := compiled.RedactMessage(c.Message); len(hits) > 0 {
				for _, h := range hits {
					v.Rescan.Hits = append(v.Rescan.Hits, Finding{
						Commit: oid, Rule: rules.DescribeRule(h.Rule), Kind: h.Rule.Kind,
						Preview: rules.FormatPreview(h.Match, 3), Line: h.Line, Action: "survived",
					})
				}
			}
		}
	}
	// Then objects that only the backups reach: expected until pruning.
	for oid, path := range backup {
		if _, isLive := live[oid]; isLive {
			continue
		}
		typ, data, err := reader.Read(oid)
		if err != nil || typ != "blob" {
			continue
		}
		if int64(len(data)) > compiled.MaxScanBytes() {
			continue
		}
		for _, h := range compiled.ScanContent(data) {
			v.Rescan.BackupOnlyHits = append(v.Rescan.BackupOnlyHits, Finding{
				Path: path, Rule: rules.DescribeRule(h.Rule), Kind: h.Rule.Kind,
				Preview: rules.FormatPreview(h.Match, 3), Line: h.Line, Blob: oid, Action: "backup-only",
			})
		}
	}
	sort.Slice(v.Rescan.BackupOnlyHits, func(i, j int) bool {
		a, b := v.Rescan.BackupOnlyHits[i], v.Rescan.BackupOnlyHits[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Blob < b.Blob
	})
	return nil
}

// objectPaths maps every object reachable from roots to the first path rev-list
// reports for it.
func objectPaths(repo *gitx.Repo, roots []string) (map[string]string, error) {
	out, err := repo.Output(append([]string{"rev-list", "--objects"}, append(roots, "--")...)...)
	if err != nil {
		return nil, err
	}
	paths := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		oid, path := line, ""
		if i := strings.IndexByte(line, ' '); i > 0 {
			oid, path = line[:i], line[i+1:]
		}
		if _, ok := paths[oid]; !ok {
			paths[oid] = path
		}
	}
	return paths, nil
}

// PruneOptions controls Prune.
type PruneOptions struct {
	Repo *gitx.Repo
	// DeleteBackups removes refs/historyscrub/* first.
	DeleteBackups bool
	// ExpireReflogs clears reflogs so reflog entries cannot keep objects alive.
	ExpireReflogs bool
}

// PruneResult describes what pruning did.
type PruneResult struct {
	RemovedBackupRefs int      `json:"removed_backup_refs"`
	ObjectsBefore     int64    `json:"objects_before"`
	ObjectsAfter      int64    `json:"objects_after"`
	BytesBefore       int64    `json:"bytes_before"`
	BytesAfter        int64    `json:"bytes_after"`
	Commands          []string `json:"commands"`
}

// Prune makes the rewritten-away objects unreachable and then physically
// deletes them.
func Prune(opts PruneOptions) (*PruneResult, error) {
	repo := opts.Repo
	if repo == nil {
		return nil, fmt.Errorf("prune: repo is required")
	}
	res := &PruneResult{}
	res.ObjectsBefore, res.BytesBefore, _ = repo.CountObjects()

	if opts.DeleteBackups {
		n, err := DeleteBackupRefs(repo)
		if err != nil {
			return res, fmt.Errorf("delete backup refs: %w", err)
		}
		res.RemovedBackupRefs = n
	}
	if opts.ExpireReflogs {
		// Every reflog entry is a reachability root.
		if err := repo.Run("reflog", "expire", "--expire=now", "--expire-unreachable=now", "--all"); err != nil {
			return res, fmt.Errorf("expire reflogs: %w", err)
		}
		res.Commands = append(res.Commands, "git reflog expire --expire=now --expire-unreachable=now --all")
	}
	// Cruft packs keep unreachable objects around by design; disable them so
	// --prune=now really deletes.
	if err := repo.Run("-c", "gc.cruftPacks=false", "-c", "gc.pruneExpire=now",
		"-c", "gc.reflogExpire=now", "-c", "gc.reflogExpireUnreachable=now",
		"gc", "--prune=now", "--quiet"); err != nil {
		return res, fmt.Errorf("git gc: %w", err)
	}
	res.Commands = append(res.Commands, "git -c gc.cruftPacks=false -c gc.pruneExpire=now gc --prune=now")
	// A second, explicit prune catches anything gc parked in a cruft pack.
	if err := repo.Run("prune", "--expire=now"); err != nil {
		return res, fmt.Errorf("git prune: %w", err)
	}
	res.Commands = append(res.Commands, "git prune --expire=now")

	res.ObjectsAfter, res.BytesAfter, _ = repo.CountObjects()
	return res, nil
}
