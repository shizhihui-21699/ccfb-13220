package scrub

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"historyscrub/internal/gitx"
	"historyscrub/internal/rules"
)

// treeRewriter rewrites trees recursively, applying path rules and content
// rules. Tree results are memoized per (tree id, directory path) because path
// rules depend on where the subtree sits; blob results are memoized per blob
// because content rules do not.
type treeRewriter struct {
	repo     *gitx.Repo
	reader   *gitx.BatchReader
	compiled *rules.Compiled
	dry      bool
	trees    map[string]string
	blobs    map[string]blobResult
	hitCache map[string][]Finding
	depth    int
	// tainted is the set of repo-relative paths at which some version matched
	// a content rule. With PurgeWholeFile it is filled before any rewrite by
	// prescan, so earlier clean versions of the same file go too.
	tainted map[string]bool
}

type blobResult struct {
	NewOID  string
	Deleted bool
	Hits    []rules.Hit
	TooBig  bool
	Size    int
}

func newTreeRewriter(repo *gitx.Repo, reader *gitx.BatchReader, compiled *rules.Compiled, dry bool) *treeRewriter {
	return &treeRewriter{
		repo: repo, reader: reader, compiled: compiled, dry: dry,
		trees:    map[string]string{},
		blobs:    map[string]blobResult{},
		hitCache: map[string][]Finding{},
		tainted:  map[string]bool{},
	}
}

// prescan walks every tree reachable from the given root trees and records the
// path of every file that matches a content rule. Paths (not blob ids) are the
// key, so a later commit that restores a clean version of the same file is
// still removed.
func (rw *treeRewriter) prescan(rootTrees []string) error {
	if !rw.compiled.HasContentRules() || !rw.compiled.PurgesWholeFile() {
		return nil
	}
	seen := map[string]bool{}
	var walk func(oid, prefix string) error
	walk = func(oid, prefix string) error {
		if oid == rw.repo.EmptyTree() || seen[oid+"\x00"+prefix] {
			return nil
		}
		seen[oid+"\x00"+prefix] = true
		rw.depth++
		defer func() { rw.depth-- }()
		if rw.depth > 200 {
			return fmt.Errorf("tree nesting deeper than 200 at %q", prefix)
		}
		typ, raw, err := rw.reader.Read(oid)
		if err != nil {
			return fmt.Errorf("prescan tree %s: %w", shortOID(oid), err)
		}
		if typ != "tree" {
			return fmt.Errorf("prescan: %s is a %s, not a tree", shortOID(oid), typ)
		}
		entries, err := gitx.ParseTree(oid, raw, rw.repo.HashLen)
		if err != nil {
			return err
		}
		for _, e := range entries {
			path := e.Name
			if prefix != "" {
				path = prefix + "/" + e.Name
			}
			if e.IsDir() {
				if err := walk(e.OID, path); err != nil {
					return err
				}
				continue
			}
			if e.Mode == "160000" || e.Mode == "120000" {
				continue
			}
			res, err := rw.blob(e.OID)
			if err != nil {
				return err
			}
			if res.Deleted {
				rw.tainted[path] = true
			}
		}
		return nil
	}
	for _, t := range rootTrees {
		if err := walk(t, ""); err != nil {
			return err
		}
	}
	return nil
}

// write stores an object unless this is a dry run, in which case only the id is
// computed. Object ids are content addressed, so both paths agree exactly.
func (rw *treeRewriter) write(typ string, data []byte) (string, error) {
	if rw.dry {
		return rw.repo.HashObject(typ, data), nil
	}
	return rw.repo.WriteObject(typ, data)
}

// rewriteTree rewrites the tree at oid as it appears at repo-relative
// directory prefix ("" at the root).
func (rw *treeRewriter) rewriteTree(oid, prefix string) (string, error) {
	if oid == rw.repo.EmptyTree() {
		return oid, nil
	}
	key := oid + "\x00" + prefix
	if v, ok := rw.trees[key]; ok {
		return v, nil
	}
	rw.depth++
	defer func() { rw.depth-- }()
	if rw.depth > 200 {
		return "", fmt.Errorf("tree nesting deeper than 200 at %q", prefix)
	}
	typ, raw, err := rw.reader.Read(oid)
	if err != nil {
		if errors.Is(err, gitx.ErrMissingObject) {
			return "", fmt.Errorf("tree %s missing from the object database (partial clone or shallow repo?)", shortOID(oid))
		}
		return "", err
	}
	if typ != "tree" {
		return "", fmt.Errorf("expected a tree at %s, found a %s", shortOID(oid), typ)
	}
	entries, err := gitx.ParseTree(oid, raw, rw.repo.HashLen)
	if err != nil {
		return "", err
	}

	changed := false
	out := make([]gitx.TreeEntry, 0, len(entries))
	for _, e := range entries {
		path := e.Name
		if prefix != "" {
			path = prefix + "/" + e.Name
		}
		if len(rw.compiled.MatchPath(path, e.IsDir())) > 0 {
			changed = true
			continue // dropped from the new tree
		}
		if rw.tainted[path] {
			// Some version of this path matched a content rule; remove the whole
			// history of the file, not just the version that held the secret.
			changed = true
			continue
		}
		if e.IsDir() {
			newSub, err := rw.rewriteTree(e.OID, path)
			if err != nil {
				return "", err
			}
			if newSub != e.OID {
				changed = true
				e.OID = newSub
			}
			out = append(out, e)
			continue
		}
		if e.Mode == "160000" { // gitlink: the id names a commit in another repo
			out = append(out, e)
			continue
		}
		if e.Mode == "120000" { // symlink: the blob is the link target text
			out = append(out, e)
			continue
		}
		res, err := rw.blob(e.OID)
		if err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		if res.Deleted {
			changed = true
			continue
		}
		out = append(out, e)
	}
	if !changed {
		rw.trees[key] = oid
		return oid, nil
	}
	data, err := gitx.SerializeTree(out, rw.repo.HashLen)
	if err != nil {
		return "", err
	}
	newOID, err := rw.write("tree", data)
	if err != nil {
		return "", err
	}
	rw.trees[key] = newOID
	return newOID, nil
}

// blob evaluates one blob against the content rules, cached per blob id.
func (rw *treeRewriter) blob(oid string) (blobResult, error) {
	if v, ok := rw.blobs[oid]; ok {
		return v, nil
	}
	res := blobResult{NewOID: oid}
	if !rw.compiled.HasContentRules() {
		rw.blobs[oid] = res
		return res, nil
	}
	typ, data, err := rw.reader.Read(oid)
	if err != nil {
		return res, fmt.Errorf("read blob %s: %w", shortOID(oid), err)
	}
	if typ != "blob" {
		rw.blobs[oid] = res
		return res, nil
	}
	res.Size = len(data)
	if int64(len(data)) > rw.compiled.MaxScanBytes() {
		res.TooBig = true
		rw.blobs[oid] = res
		return res, nil
	}
	if hits := rw.compiled.ScanContent(data); len(hits) > 0 {
		// A match removes the file outright: a partially redacted credential
		// file is not something we can call safe.
		res.Deleted = true
		res.Hits = hits
	}
	rw.blobs[oid] = res
	return res, nil
}

// collectTree returns the findings at or below a tree, with repo-relative
// paths. It writes nothing and is used for reporting.
func (rw *treeRewriter) collectTree(oid, prefix string) ([]Finding, error) {
	if oid == rw.repo.EmptyTree() {
		return nil, nil
	}
	key := oid + "\x00" + prefix
	if v, ok := rw.hitCache[key]; ok {
		return v, nil
	}
	typ, raw, err := rw.reader.Read(oid)
	if err != nil {
		return nil, fmt.Errorf("read tree %s: %w", shortOID(oid), err)
	}
	if typ != "tree" {
		return nil, fmt.Errorf("object %s at %q is a %s, not a tree", shortOID(oid), prefix, typ)
	}
	entries, err := gitx.ParseTree(oid, raw, rw.repo.HashLen)
	if err != nil {
		return nil, err
	}
	rw.depth++
	defer func() { rw.depth-- }()
	if rw.depth > 200 {
		return nil, fmt.Errorf("tree nesting deeper than 200 at %q", prefix)
	}

	var out []Finding
	for _, e := range entries {
		path := e.Name
		if prefix != "" {
			path = prefix + "/" + e.Name
		}
		if hits := rw.compiled.MatchPath(path, e.IsDir()); len(hits) > 0 {
			for _, h := range hits {
				out = append(out, Finding{Path: path, Rule: rules.DescribeRule(h), Kind: h.Kind,
					Note: h.Note, Blob: e.OID, Action: "delete-path"})
			}
			continue
		}
		if rw.tainted[path] {
			// Report the version that actually holds the secret as a content
			// hit; the other versions are only condemned by the purge rule.
			if e.Mode != "160000" && e.Mode != "120000" {
				if res, err := rw.blob(e.OID); err == nil && res.Deleted {
					for _, h := range res.Hits {
						out = append(out, Finding{Path: path, Rule: rules.DescribeRule(h.Rule), Kind: h.Rule.Kind,
							Note: h.Rule.Note, Preview: rules.FormatPreview(h.Match, 3), Line: h.Line,
							Blob: e.OID, Action: "delete-content"})
					}
					continue
				}
			}
			out = append(out, Finding{Path: path, Rule: "purge-whole-file", Kind: "content",
				Note: "another version of this path matched a content rule; every version is removed",
				Blob: e.OID, Action: "delete-path"})
			continue
		}
		if e.IsDir() {
			sub, err := rw.collectTree(e.OID, path)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
			continue
		}
		if e.Mode == "160000" || e.Mode == "120000" {
			continue
		}
		res, err := rw.blob(e.OID)
		if err != nil {
			return nil, err
		}
		if res.Deleted {
			for _, h := range res.Hits {
				out = append(out, Finding{Path: path, Rule: rules.DescribeRule(h.Rule), Kind: h.Rule.Kind,
					Note: h.Rule.Note, Preview: rules.FormatPreview(h.Match, 3), Line: h.Line,
					Blob: e.OID, Action: "delete-content"})
			}
			continue
		}
		if res.TooBig {
			out = append(out, Finding{Path: path, Rule: "scan-limit", Kind: "warning", Blob: e.OID,
				Action: "skipped",
				Note:   fmt.Sprintf("file is %d bytes, above the %d byte scan limit; only path rules apply", res.Size, rw.compiled.MaxScanBytes())})
		}
	}
	rw.hitCache[key] = out
	return out, nil
}

// rewriteDetached applies the rules to a tree or blob named directly by a tag.
func (rw *treeRewriter) rewriteDetached(oid, typ, refName string) (string, error) {
	switch typ {
	case "tree":
		return rw.rewriteTree(oid, "")
	case "blob":
		res, err := rw.blob(oid)
		if err != nil {
			return "", err
		}
		if res.Deleted {
			return "", fmt.Errorf("tag/ref %s names blob %s directly and that blob matches a content rule; delete the ref or narrow the rules", refName, shortOID(oid))
		}
		return oid, nil
	}
	return oid, nil
}

// SortFindings orders findings for stable output.
func SortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Commit != b.Commit {
			return a.Commit < b.Commit
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Line < b.Line
	})
}

// backupRefPrefix is the namespace used for pre-rewrite backups.
const backupRefPrefix = "refs/historyscrub/backup/"

// writeBackupRefs records the pre-rewrite value of every ref in scope so the
// operator can restore, and writes a plain-text manifest next to it.
func writeBackupRefs(repo *gitx.Repo, refs []gitx.Ref, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	refDir := backupRefPrefix + stamp
	var b strings.Builder
	b.WriteString("# historyscrub backup refs, created " + time.Now().UTC().Format(time.RFC3339) + "\n")
	b.WriteString("# Restore one ref:  git update-ref <original-ref> $(git rev-parse " + refDir + "/<flat-name>)\n")
	b.WriteString("# Drop all backups:  git for-each-ref --format='delete %(refname)' " + backupRefPrefix + " | git update-ref --stdin\n\n")
	b.WriteString("# ref-in-backup\tobject\toriginal-ref\n")
	var updates []gitx.UpdateRef
	for _, r := range refs {
		flat := strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(r.Name, "refs/"), "/"), "/", "--")
		name := refDir + "/" + flat
		updates = append(updates, gitx.UpdateRef{Name: name, New: r.OID})
		b.WriteString(name + "\t" + r.OID + "\t" + r.Name + "\n")
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].Name < updates[j].Name })
	for _, batch := range chunkUpdates(updates, 500) {
		if err := repo.UpdateRefs(batch, "historyscrub: backup before rewrite"); err != nil {
			return "", fmt.Errorf("create backup refs: %w", err)
		}
	}
	manifest := filepath.Join(dir, "backup-"+stamp+".txt")
	if err := os.WriteFile(manifest, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return manifest, nil
}

func chunkUpdates(us []gitx.UpdateRef, n int) [][]gitx.UpdateRef {
	var out [][]gitx.UpdateRef
	for len(us) > n {
		out = append(out, us[:n])
		us = us[n:]
	}
	if len(us) > 0 {
		out = append(out, us)
	}
	return out
}

// DeleteBackupRefs removes the backup namespace so old objects become
// unreachable and can be pruned.
func DeleteBackupRefs(repo *gitx.Repo) (int, error) {
	refs, err := repo.ListRefs(backupRefPrefix)
	if err != nil {
		return 0, err
	}
	if len(refs) == 0 {
		return 0, nil
	}
	for _, r := range refs {
		if err := repo.Run("update-ref", "-d", r.Name); err != nil {
			return 0, err
		}
	}
	return len(refs), nil
}
