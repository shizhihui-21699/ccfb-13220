#!/usr/bin/env bash
# Build a throwaway repository that contains the two kinds of leak this tool
# handles, then walk the whole workflow against a copy.
set -euo pipefail
cd "$(dirname "$0")/.."

DEMO_DIR="${DEMO_DIR:-$(mktemp -d)/leaky-repo}"
SPEC="demo/leaky-spec.json"

echo "== building demo repository =="
go run ./cmd/demorepo -out "$DEMO_DIR"

echo
echo "== plan (writes nothing) =="
go run ./cmd/scrub plan --repo "$DEMO_DIR" --spec "$SPEC"

echo
echo "== rewriting a copy so the demo repo stays reproducible =="
WORK="$(mktemp -d)/work"
cp -R "$DEMO_DIR" "$WORK"
# Keep signing usable in the copy: the key paths are recorded in the copy's config.
if [ -f "${DEMO_DIR}-signing-key" ]; then
  git -C "$WORK" config user.signingkey "${DEMO_DIR}-signing-key"
  git -C "$WORK" config gpg.ssh.allowedSignersFile "${DEMO_DIR}-allowed-signers"
fi

go run ./cmd/scrub run --repo "$WORK" --spec "$SPEC" --out "$WORK-report.json" --reset-worktree
echo
echo "== verify from the object database =="
go run ./cmd/scrub verify --repo "$WORK" --spec "$SPEC" --report "$WORK-report.json" || true
echo
echo "== prune and verify again =="
go run ./cmd/scrub prune --repo "$WORK"
go run ./cmd/scrub verify --repo "$WORK" --spec "$SPEC" --report "$WORK-report.json"
echo
echo "== collaborator notice =="
go run ./cmd/scrub notify --repo "$WORK" --report "$WORK-report.json" --remote git@example.com:acme/analytics.git --name analytics-service

echo
echo "demo repo:  $DEMO_DIR"
echo "rewritten:  $WORK"
