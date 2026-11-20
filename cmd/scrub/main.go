package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"historyscrub/internal/gitx"
	"historyscrub/internal/rules"
	"historyscrub/internal/scrub"
)

const usage = `historyscrub — remove sensitive paths and content from git history.

Usage:
  scrub <command> [flags]

Commands:
  plan     Analyse only: list every match, every ref that would change and
           every signature that would be lost. Writes nothing.
  run      Rewrite refs/heads and refs/tags, then print the same report.
  verify   Re-scan the repository and prove the sensitive objects are gone.
  prune    Delete backup refs, expire reflogs and physically remove the
           rewritten-away objects, then verify unreachability.
  notify   Print the collaborator notice (re-clone instructions).
  presets  List built-in content presets.

Common flags:
  -repo <path>     repository to operate on (default ".")
  -spec <path>     JSON rule spec (required for plan/run)
  -json            emit machine-readable JSON instead of text
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "plan":
		err = cmdPlan(args, false)
	case "run":
		err = cmdPlan(args, true)
	case "verify":
		err = cmdVerify(args)
	case "prune":
		err = cmdPrune(args)
	case "notify":
		err = cmdNotify(args)
	case "presets":
		err = cmdPresets(args)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		exitCode = 1
	}
	os.Exit(exitCode)
}

// exitCode lets subcommands request a non-zero exit without printing a second
// error line (verify already printed a FAIL report).
var exitCode = 0

func openRepo(path string) (*gitx.Repo, error) {
	r, err := gitx.Open(path)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func loadSpec(path string) (*rules.Spec, error) {
	if path == "" {
		return nil, fmt.Errorf("-spec is required")
	}
	s, err := rules.Load(path)
	if err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func cmdPlan(args []string, apply bool) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	repoPath := fs.String("repo", ".", "repository path")
	specPath := fs.String("spec", "", "JSON rule spec")
	asJSON := fs.Bool("json", false, "JSON output")
	outPath := fs.String("out", "", "write the report to this file")
	reset := fs.Bool("reset-worktree", false, "after a run, git reset --hard HEAD")
	if err := fs.Parse(args); err != nil {
		return err
	}
	repo, err := openRepo(*repoPath)
	if err != nil {
		return err
	}
	spec, err := loadSpec(*specPath)
	if err != nil {
		return err
	}
	opts := scrub.Options{Repo: repo, Spec: spec, ResetWorktree: *reset}
	var rep *scrub.Report
	if apply {
		rep, err = scrub.Run(opts)
	} else {
		rep, err = scrub.Plan(opts)
	}
	if err != nil {
		return err
	}
	if *outPath != "" {
		if err := writeJSON(*outPath, rep); err != nil {
			return err
		}
	}
	if *asJSON {
		return printJSON(rep)
	}
	printReport(rep, apply)
	return nil
}

func printReport(rep *scrub.Report, applied bool) {
	mode := "PLAN (nothing written)"
	if applied {
		mode = "RUN (refs rewritten)"
	}
	fmt.Printf("== historyscrub %s ==\n", mode)
	fmt.Printf("repository : %s\n", rep.Repo)
	fmt.Printf("scanned    : %d commits (%d unchanged, %d rewritten)\n", rep.CommitsScanned, rep.CommitsUnchanged, rep.CommitsRewritten)
	st := rep.Stats()
	fmt.Printf("findings   : %d (%d commits affected)\n", st.Findings, st.CommitsAffected)
	for _, f := range rep.Findings {
		loc := f.Path
		if f.Commit != "" {
			loc = short(f.Commit) + " " + f.Path
		}
		if f.Line > 0 {
			loc += fmt.Sprintf(":%d", f.Line)
		}
		if f.Preview != "" {
			loc += "  [" + f.Preview + "]"
		}
		fmt.Printf("  - %-58s %-22s %s\n", loc, f.Rule, f.Action)
	}
	fmt.Printf("refs       : %d changed\n", st.RefsRewritten)
	for _, u := range rep.Refs {
		mark := " "
		if u.Changed {
			mark = "*"
		}
		fmt.Printf("  %s %-32s %s -> %s\n", mark, u.Name, short(u.Old), short(u.New))
	}
	if len(rep.SignatureLosses) > 0 {
		fmt.Printf("signatures : %d lost (rewriting invalidates a signature; re-sign if policy requires)\n", len(rep.SignatureLosses))
		for _, s := range rep.SignatureLosses {
			ref := s.Ref
			if ref == "" {
				ref = short(s.OldOID)
			}
			fmt.Printf("  - %-7s %-32s %-14s %-22s %s\n", s.Kind, ref, s.OldSig, s.Identity, short(s.OldOID)+" -> "+short(s.NewOID))
		}
	} else {
		fmt.Printf("signatures : none lost\n")
	}
	for _, w := range rep.Warnings {
		fmt.Printf("warning    : %s\n", w)
	}
	if applied && rep.BackupManifest != "" {
		fmt.Printf("backup     : %s\n", rep.BackupManifest)
		fmt.Printf("             restore with: git update-ref <ref> $(git rev-parse refs/historyscrub/backup/<stamp>/<flat>)\n")
		fmt.Printf("next       : git push --force-with-lease --force-if-includes <remote> 'refs/heads/*' 'refs/tags/*'\n")
	}
}

func short(s string) string { return shortOID(s) }

func shortOID(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	repoPath := fs.String("repo", ".", "repository path")
	specPath := fs.String("spec", "", "JSON rule spec (re-scans all reachable blobs)")
	reportPath := fs.String("report", "", "report file written by plan/run; provides the sensitive object list")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	repo, err := openRepo(*repoPath)
	if err != nil {
		return err
	}
	opts := scrub.VerifyOptions{Repo: repo}
	if *specPath != "" {
		spec, err := loadSpec(*specPath)
		if err != nil {
			return err
		}
		opts.Spec = spec
	}
	if *reportPath != "" {
		var rep scrub.Report
		if err := readJSON(*reportPath, &rep); err != nil {
			return err
		}
		opts.Sensitive = rep.SensitiveObjects()
	} else {
		fmt.Fprintln(os.Stderr, "note: no -report given, so only a content rescan runs (no object list to check)")
	}
	v, err := scrub.Verify(opts)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(v)
	}
	fmt.Printf("== verification ==\n")
	fmt.Printf("objects checked : %d\n", len(v.Objects))
	fmt.Printf("removed from odb: %d\n", v.Removed)
	fmt.Printf("present, unreach: %d\n", v.Unreachable)
	fmt.Printf("backup-only     : %d (recoverable until prune)\n", v.BackupOnly)
	fmt.Printf("still reachable : %d\n", v.StillReachable)
	for _, o := range v.Objects {
		switch o.Status {
		case "reachable":
			fmt.Printf("  REACHABLE %s %s via %s\n", o.OID, o.Kind, strings.Join(o.ReachedBy, ", "))
		case "backup-only":
			fmt.Printf("  backup-only %s %s %s\n", shortOID(o.OID), o.Kind, strings.Join(o.Paths, ","))
		}
	}
	fmt.Printf("content rescan : %d blobs, %d commits, %d hits\n", v.Rescan.BlobsScanned, v.Rescan.CommitsScanned, len(v.Rescan.Hits))
	for _, h := range v.Rescan.Hits {
		fmt.Printf("  HIT %-40s %-20s %s\n", h.Path, h.Rule, h.Preview)
	}
	if len(v.Rescan.BackupOnlyHits) > 0 {
		fmt.Printf("backup copies  : %d blob(s) matching the rules survive only in backups (expected before prune)\n", len(v.Rescan.BackupOnlyHits))
	}
	for _, b := range v.BackupRefs {
		fmt.Printf("backup ref     : %s\n", b)
	}
	for _, n := range v.Notes {
		fmt.Printf("note           : %s\n", n)
	}
	if v.Passed {
		fmt.Printf("result         : PASS\n")
		return nil
	}
	fmt.Printf("result         : FAIL\n")
	fmt.Printf("  %d object(s) still reachable from live refs, %d content hit(s)\n", v.StillReachable, len(v.Rescan.Hits))
	exitCode = 1
	return nil
}

func cmdPrune(args []string) error {
	fs := flag.NewFlagSet("prune", flag.ExitOnError)
	repoPath := fs.String("repo", ".", "repository path")
	keepBackups := fs.Bool("keep-backups", false, "keep refs/historyscrub/* (old objects stay recoverable)")
	keepReflogs := fs.Bool("keep-reflogs", false, "do not expire reflogs")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	repo, err := openRepo(*repoPath)
	if err != nil {
		return err
	}
	if !*keepBackups {
		fmt.Fprintln(os.Stderr, "note: deleting refs/historyscrub/* — the pre-rewrite objects will be unrecoverable after this")
	}
	res, err := scrub.Prune(scrub.PruneOptions{
		Repo:          repo,
		DeleteBackups: !*keepBackups,
		ExpireReflogs: !*keepReflogs,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(res)
	}
	fmt.Printf("== prune ==\n")
	fmt.Printf("backup refs removed : %d\n", res.RemovedBackupRefs)
	fmt.Printf("objects             : %d -> %d\n", res.ObjectsBefore, res.ObjectsAfter)
	fmt.Printf("bytes               : %d -> %d\n", res.BytesBefore, res.BytesAfter)
	for _, c := range res.Commands {
		fmt.Printf("ran                 : %s\n", c)
	}
	return nil
}

func cmdNotify(args []string) error {
	fs := flag.NewFlagSet("notify", flag.ExitOnError)
	repoPath := fs.String("repo", ".", "repository path")
	reportPath := fs.String("report", "", "report file written by run")
	remote := fs.String("remote", "", "remote URL to put in the instructions")
	name := fs.String("name", "", "repository name")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	repo, err := openRepo(*repoPath)
	if err != nil {
		return err
	}
	var rep scrub.Report
	if *reportPath != "" {
		if err := readJSON(*reportPath, &rep); err != nil {
			return err
		}
	}
	url := *remote
	if url == "" {
		url = repo.GitConfig("remote.origin.url")
	}
	nm := *name
	if nm == "" {
		nm = filepath.Base(repo.Dir)
	}
	in := scrub.NotificationInput{
		RepoName:    nm,
		RemoteURL:   url,
		OldTips:     map[string]string{},
		NewTips:     map[string]string{},
		RewrittenAt: rep.FinishedAt,
		Counts:      rep.Stats(),
	}
	seen := map[string]bool{}
	for _, u := range rep.Refs {
		if u.Type != "commit" {
			continue
		}
		in.OldTips[u.Name] = u.Old
		in.NewTips[u.Name] = u.New
		if strings.HasPrefix(u.Name, "refs/heads/") {
			in.Branches = append(in.Branches, u.Name)
		}
		if strings.HasPrefix(u.Name, "refs/tags/") {
			in.Tags = append(in.Tags, u.Name)
		}
	}
	for _, f := range rep.Findings {
		if f.Path != "" && !seen[f.Path] {
			seen[f.Path] = true
			in.RemovedPaths = append(in.RemovedPaths, f.Path)
		}
	}
	backups, _ := repo.ListRefs("refs/historyscrub/")
	for _, b := range backups {
		in.BackupRefs = append(in.BackupRefs, b.Name)
	}
	n := scrub.BuildNotification(in)
	if *asJSON {
		return printJSON(n)
	}
	fmt.Printf("Subject: %s\n\n%s\n", n.Subject, n.Body)
	return nil
}

func cmdPresets(args []string) error {
	fs := flag.NewFlagSet("presets", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	for _, name := range rules.PresetNames() {
		p, _ := rules.PresetByName(name)
		fmt.Printf("%-18s %s\n", name, p.Description)
	}
	return nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

var _ = time.Now
