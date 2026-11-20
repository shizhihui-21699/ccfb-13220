# historyscrub

Remove customer data exports, production keys and other sensitive content from **every
commit** of a git repository — all branches and all tags — then prove from the object
database that the data is unreachable.

Deleting a file in a new commit does not remove it: the objects stay in history and in
everybody's clone. This tool rewrites the history that contained them, on every ref at
once, and tells you exactly what it could not preserve.

```
┌──────────┐   ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐
│  select  │ → │  scope  │ → │ preview  │ → │ rewrite  │ → │ verify & │ → │ notify  │
│   repo   │   │  rules  │   │  (plan)  │   │ refs     │   │  prune   │   │  team   │
└──────────┘   └─────────┘   └──────────┘   └──────────┘   └──────────┘   └─────────┘
```

## Quick start

```bash
go build -o bin/historyscrub ./cmd/scrub
go build -o bin/historyscrub-ui ./cmd/server

# 1. Build a demo repo with the exact problem (branch, merge, signed commit, signed tag)
bash scripts/demo.sh

# 2. Or work on a real repository
bin/historyscrub plan --repo /path/to/repo --spec my-spec.json   # writes nothing
bin/historyscrub run  --repo /path/to/repo --spec my-spec.json --out report.json
bin/historyscrub verify --repo /path/to/repo --spec my-spec.json --report report.json
bin/historyscrub prune  --repo /path/to/repo
bin/historyscrub verify --repo /path/to/repo --spec my-spec.json --report report.json
bin/historyscrub notify --repo /path/to/repo --report report.json --remote git@host:team/repo.git
```

## The spec

```json
{
  "rules": [
    { "kind": "path",    "value": "exports/*.csv",  "note": "customer export" },
    { "kind": "path",    "value": "keys/" },
    { "kind": "literal", "value": "customer-jane@example.com", "ignore_case": true },
    { "kind": "regex",   "value": "prod-[0-9a-f]{8}-secret" },
    { "kind": "preset",  "value": "aws_access_key" }
  ],
  "purge_whole_file": true,
  "scan_commit_messages": false,
  "max_scan_bytes": 8388608
}
```

| kind | meaning |
| --- | --- |
| `path` | gitignore-style glob. `**` crosses directories, `*` does not. A pattern with no slash matches at any depth, so `*.pem` covers `keys/prod.pem`. A trailing `/` matches a directory and everything under it. |
| `literal` | exact string; `ignore_case` makes it case-insensitive. |
| `regex` | Go regular expression, applied per file. |
| `preset` | one of the built-in detectors (`historyscrub presets` lists them): private key blocks, AWS key id and secret, GitHub/Slack/Google tokens, JWTs, URLs with embedded credentials, and a high-entropy heuristic. |

`purge_whole_file` (default **true**) removes every version of a path once *any* version of
that path matches a content rule. Without it, an earlier clean version of the same file
survives, which leaves the file's history intact and makes the scrub look successful while
`config/prod.env` is still in the repository. Turn it off only when you know the rule is
sufficiently narrow.

**A content match removes the whole file.** Keeping a partially redacted copy of a
credential file is not something the tool can call safe.

## What it does to history

* Rewrites commits reachable from `refs/heads/*` and `refs/tags/*`, all at once, parents
  first, so merge commits keep all their parents (rewritten to the new ids).
* Rewrites annotated tags, including tags of tags, and drops the signature when the target
  moves.
* Preserves everything it does not deliberately change: message bytes, author/committer
  timestamps and time zones, `encoding` and other unknown headers. Commits that end up
  byte-identical keep their original object id.
* Creates backup refs under `refs/historyscrub/backup/<stamp>/` and a manifest at
  `.git/historyscrub/backup-<stamp>.txt` before touching anything. The old objects stay
  recoverable until you prune.
* Applies every ref update in **one `git update-ref` transaction**, each ref pinned to the
  value it was read at. If anybody pushed in the meantime, the whole transaction is
  rejected and nothing changes.
* Refuses to run on a dirty worktree or in the middle of a merge/rebase/bisect.

## Signatures

A signature covers the exact bytes of the object it signs, so a rewritten commit or tag
**cannot** keep a valid signature. The tool:

1. verifies every signed commit and signed tag *before* rewriting, and records the verdict;
2. strips the signature from every object it rewrites (never leaving a signature that
   cannot verify);
3. lists each one in `signature_losses` with the old verdict, the signer identity, and the
   replacement object id.

Re-sign with `git commit --amend -S` / `git tag -s` if your policy requires signed history.

## Verification

`verify` works from the object database up, not from the working tree:

* every matched blob and every pre-rewrite ref tip is looked up in the object database;
* reachability is computed **per ref**, so an object reachable only through
  `refs/historyscrub/backup/*` is reported as `backup-only` (recoverable by design) rather
  than as a leak, and an object reachable from any live ref or a detached HEAD is a
  failure;
* every blob reachable from a live ref is re-scanned with the same rules, so a copy of the
  secret that was not at the expected path is still caught;
* blobs above the scan limit are reported explicitly rather than silently skipped.

`prune` deletes the backup refs, expires reflogs, and runs `gc --prune=now` with cruft packs
disabled (cruft packs keep unreachable objects on purpose). Run `verify` again afterwards:
a passing result then means the sensitive objects are gone from the object database
entirely.

## The operator UI

```bash
cd web && npm install && npm run build && cd ..   # rebuild the embedded UI
go build -o bin/historyscrub-ui ./cmd/server
bin/historyscrub-ui -root /path/to/parent-of-repos -allow-run
```

The built UI is committed under `internal/server/dist/` and embedded in the server
binary, so `go build` works without npm. Rebuild it only when `web/` changes.

Then open <http://127.0.0.1:8765>. The UI walks the same five steps: pick a repository,
describe what to remove (form or JSON), preview the plan, confirm the rewrite by typing
`REWRITE`, verify, prune (disabled until verification passes), and generate the notice.

* Mutating endpoints are off unless the server is started with `-allow-run`.
* The repository browser and every API path are confined to `-root`; a path outside it is
  refused with a 400.

## Pushing and telling people

The tool never pushes. After a successful run:

```bash
git push --force-with-lease --force-if-includes origin 'refs/heads/*' 'refs/tags/*'
```

Then send the generated notice (`historyscrub notify`). It explains why pulling will not
fix an existing clone and gives the exact re-clone steps, because an old clone still holds
the old objects and merging or rebasing it back would reintroduce them.

Two things the rewrite does **not** do:

* **It does not rotate the credential.** The key was exposed the moment it was pushed;
  rewriting history only limits further distribution. Rotate first.
* **It does not reach forks, CI caches, artifact stores or anything already fetched.**
  Those have to be deleted separately, and the notice says so.

## Repository layout

```
cmd/scrub        CLI: plan, run, verify, prune, notify, presets
cmd/server       HTTP API + embedded UI
cmd/demorepo     builds the leaky demo repository
internal/gitx    git plumbing: refs, objects (commit/tag/tree codec), signature verdicts
internal/rules   rule spec, globs, presets, content scanning
internal/scrub   rewrite engine, verification, pruning, notification text
web/             React UI (Vite, no runtime dependencies beyond React)
```

## Limitations

* History that is not in the repository cannot be scrubbed: shallow clones and partial
  clones are reported as warnings, and the run refuses to guess.
* Submodules (gitlinks) are left alone; they are commits in another repository.
* Symlink blobs are not content-scanned (the blob is a link target, not file data).
* Refs outside `refs/heads` and `refs/tags` (remote-tracking refs, `refs/stash`,
  `refs/replace`, notes) are not rewritten; they are reported as warnings because they keep
  old objects alive.

## Tests

```bash
go test ./...
cd web && npm run build   # the embedded UI is part of the server binary
```

The suite covers glob semantics and false positives, content presets, commit/tag/tree
round-tripping, plans vs. real runs, whole-file purge, merge-parent preservation, tagged
commits, SSH-signed commits and tags (real signature verification, then confirmed loss),
SHA-256 repositories, concurrent ref changes, dry runs writing nothing, and the HTTP API
including path-escape refusal.
