package scrub

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// NotificationInput is everything needed to explain the rewrite to
// collaborators.
type NotificationInput struct {
	RepoName     string
	RemoteURL    string
	Branches     []string // rewritten branches, for the "rebase or re-clone" section
	Tags         []string
	OldTip       string // pre-rewrite tip of the default branch
	NewTip       string
	OldTips      map[string]string // ref -> old oid
	NewTips      map[string]string // ref -> new oid
	RewrittenAt  time.Time
	RemovedPaths []string
	Counts       Stats
	BackupRefs   []string
}

// Notification is the rendered message plus structured pieces for the UI.
type Notification struct {
	Subject   string   `json:"subject"`
	Body      string   `json:"body"`
	Short     string   `json:"short"`
	Checklist []string `json:"checklist"`
	OldTips   []RefTip `json:"old_tips"`
	NewTips   []RefTip `json:"new_tips"`
}

// RefTip pairs a ref name with a commit id.
type RefTip struct {
	Ref string `json:"ref"`
	OID string `json:"oid"`
}

// BuildNotification renders the collaborator notice.
func BuildNotification(in NotificationInput) Notification {
	repoName := in.RepoName
	if repoName == "" {
		repoName = "the repository"
	}
	remote := in.RemoteURL
	if remote == "" {
		remote = "<remote-url>"
	}
	if in.RewrittenAt.IsZero() {
		in.RewrittenAt = time.Now().UTC()
	}

	var oldTips, newTips []RefTip
	for ref, oid := range in.OldTips {
		oldTips = append(oldTips, RefTip{Ref: ref, OID: oid})
	}
	sort.Slice(oldTips, func(i, j int) bool { return oldTips[i].Ref < oldTips[j].Ref })
	for ref, oid := range in.NewTips {
		newTips = append(newTips, RefTip{Ref: ref, OID: oid})
	}
	sort.Slice(newTips, func(i, j int) bool { return newTips[i].Ref < newTips[j].Ref })

	subject := fmt.Sprintf("Action required: %s history was rewritten — delete your clone and re-clone", repoName)

	var b strings.Builder
	fmt.Fprintf(&b, "Hi all,\n\n")
	fmt.Fprintf(&b, "We removed sensitive data from the history of %s on %s.\n", repoName, in.RewrittenAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "A data export containing customer records and a production key were committed by mistake. Deleting the files in a new commit was not enough: the objects stayed in history, so every commit that contained them has been rewritten and their content removed.\n\n")

	fmt.Fprintf(&b, "Why this affects you\n")
	fmt.Fprintf(&b, "--------------------\n")
	fmt.Fprintf(&b, "The commit ids changed. Any commit, branch, tag or review based on the old history no longer exists in the repository. Pulling or merging your existing clone will NOT fix it and can push the old objects back.\n\n")

	fmt.Fprintf(&b, "What to do (in order)\n")
	fmt.Fprintf(&b, "---------------------\n")
	fmt.Fprintf(&b, "1. Push any work you still need from your current clone to a scratch branch on the remote,\n")
	fmt.Fprintf(&b, "   e.g.  git push origin HEAD:refs/heads/scratch/<yourname>-rescued\n")
	fmt.Fprintf(&b, "2. Delete your local clone completely (the .git directory included).\n")
	fmt.Fprintf(&b, "3. Clone again:\n")
	fmt.Fprintf(&b, "        git clone %s\n", remote)
	fmt.Fprintf(&b, "4. Re-apply your unmerged work onto the new history:\n")
	fmt.Fprintf(&b, "        git fetch origin\n")
	fmt.Fprintf(&b, "        git cherry-pick <your commits>     # or: git rebase --onto origin/main <old-base>\n")
	fmt.Fprintf(&b, "   Cherry-picking is deliberate: it copies the change onto the clean history instead of dragging the old objects back in.\n")
	fmt.Fprintf(&b, "5. Delete stale local branches and tags from the old history. Do not merge or rebase them.\n")
	fmt.Fprintf(&b, "6. If you have CI caches, build caches, artifact stores or forks containing the old commit ids, delete them too.\n\n")

	fmt.Fprintf(&b, "What was removed\n")
	fmt.Fprintf(&b, "----------------\n")
	fmt.Fprintf(&b, "- %d distinct paths, across %d commits in %d refs.\n", in.Counts.Findings, in.Counts.CommitsAffected, in.Counts.RefsRewritten)
	paths := append([]string(nil), in.RemovedPaths...)
	sort.Strings(paths)
	limit := len(paths)
	if limit > 20 {
		limit = 20
	}
	for _, p := range paths[:limit] {
		fmt.Fprintf(&b, "    %s\n", p)
	}
	if len(paths) > limit {
		fmt.Fprintf(&b, "    ... and %d more\n", len(paths)-limit)
	}
	fmt.Fprintf(&b, "\n")

	if len(in.Branches) > 0 || len(in.Tags) > 0 {
		fmt.Fprintf(&b, "Refs that changed\n")
		fmt.Fprintf(&b, "-----------------\n")
		for _, x := range newTips {
			fmt.Fprintf(&b, "    %-28s %s\n", x.Ref, x.OID)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "Commit signatures\n")
	fmt.Fprintf(&b, "-----------------\n")
	if in.Counts.SignatureLosses == 0 {
		fmt.Fprintf(&b, "No signed commits or tags were affected.\n\n")
	} else {
		fmt.Fprintf(&b, "%d signature(s) could not survive the rewrite, because a signature covers the exact\n", in.Counts.SignatureLosses)
		fmt.Fprintf(&b, "bytes of the object it signs. The affected commits and tags are listed in the scrub\nreport. If your signed commit is one of them, re-sign it with `git commit --amend -S` after\ncherry-picking.\n\n")
	}

	fmt.Fprintf(&b, "If you think you pushed the old history anywhere\n")
	fmt.Fprintf(&b, "------------------------------------------------\n")
	fmt.Fprintf(&b, "Tell the security contact immediately. Removing it from this repository does not remove\n")
	fmt.Fprintf(&b, "it from forks, caches, or anything already fetched. The affected credentials must be\n")
	fmt.Fprintf(&b, "rotated regardless of this cleanup.\n\n")

	fmt.Fprintf(&b, "Thanks,\nThe maintainers\n")

	checklist := []string{
		"Rotate every credential that was in the removed files; rewriting history does not make an exposed key safe again.",
		"Push the rewritten refs with --force-with-lease --force-if-includes (never plain --force).",
		"Forbid non-fast-forward pushes on the affected branches for the transition window, so an old clone cannot push the old objects back.",
		"Delete refs/historyscrub/backup/* and run the prune step only after every collaborator confirms a fresh clone.",
		"Ask collaborators to delete forks, CI caches and artifact stores that may hold the old commit ids.",
		"Keep the audit report and the old/new tip table: they are the record of what changed.",
	}
	fmt.Fprintf(&b, "\n--- maintainer checklist (do not send) ---\n")
	for i, c := range checklist {
		fmt.Fprintf(&b, "%d. %s\n", i+1, c)
	}

	short := fmt.Sprintf("%s history was rewritten on %s to remove sensitive data. Delete your clone and re-clone with `git clone %s`; do not pull or merge your old clone. Full instructions follow.",
		repoName, in.RewrittenAt.UTC().Format("2006-01-02"), remote)

	return Notification{
		Subject:   subject,
		Body:      b.String(),
		Short:     short,
		Checklist: checklist,
		OldTips:   oldTips,
		NewTips:   newTips,
	}
}
