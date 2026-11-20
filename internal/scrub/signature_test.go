package scrub

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"historyscrub/internal/rules"
)

// TestSignedCommitsAndTagsAreReported uses SSH signing, which needs no agent
// and no gpg keyring, so the test is hermetic.
func TestSignedCommitsAndTagsAreReported(t *testing.T) {
	f := newFixture(t)
	keyPath := filepath.Join(f.dir, "..", "signing_key_"+filepath.Base(f.dir))
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath, "-C", "signer@example.com").CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen unavailable: %v %s", err, out)
	}
	defer os.Remove(keyPath)
	defer os.Remove(keyPath + ".pub")

	f.git("config", "gpg.format", "ssh")
	f.git("config", "user.signingkey", keyPath)
	allowed := filepath.Join(f.dir, "..", "allowed_signers_"+filepath.Base(f.dir))
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowed, []byte("signer@example.com "+strings.TrimSpace(string(pub))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(allowed)
	f.git("config", "gpg.ssh.allowedSignersFile", allowed)

	f.write("README.md", "demo\n")
	f.commitAll("base")

	f.write("secret.txt", "PRIVATE-CONTENT-XYZ\n")
	f.git("add", "-A")
	leaky := f.commitAll("leaky signed commit")
	f.git("commit", "-S", "-q", "--allow-empty", "--amend", "--no-edit")
	leaky = f.git("rev-parse", "HEAD")

	f.write("README.md", "demo v2\n")
	f.commitAll("clean commit")
	signedTag := f.git("tag", "-s", "-m", "release", "v1.0")

	// Both objects must verify before the rewrite, or the test proves nothing.
	if got := f.git("log", "-1", "--format=%G?", leaky); got != "G" {
		t.Fatalf("fixture signature does not verify: %q", got)
	}
	if out, err := exec.Command("git", "-C", f.dir, "verify-tag", "v1.0").CombinedOutput(); err != nil {
		t.Fatalf("fixture tag does not verify: %v %s", err, out)
	}
	_ = signedTag

	spec := pathOnlySpec(t, "secret.txt")
	rep, err := Run(Options{Repo: f.repo(), Spec: spec, ResetWorktree: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.SignatureLosses) == 0 {
		t.Fatal("expected signature losses to be reported")
	}
	var sawCommit, sawTag bool
	for _, l := range rep.SignatureLosses {
		if l.Kind == "commit" && l.OldOID == leaky {
			sawCommit = true
			if l.OldSig != "valid" {
				t.Fatalf("expected the pre-rewrite signature to be recorded as valid, got %q", l.OldSig)
			}
			if l.NewOID == l.OldOID {
				t.Fatal("lost signature has an unchanged object id")
			}
		}
		if l.Kind == "tag" && l.Ref == "refs/tags/v1.0" {
			sawTag = true
		}
	}
	if !sawCommit || !sawTag {
		t.Fatalf("expected commit and tag signature losses, got %+v", rep.SignatureLosses)
	}

	// The rewritten commit must not falsely claim a valid signature.
	newOID := ""
	for _, l := range rep.SignatureLosses {
		if l.Kind == "commit" {
			newOID = l.NewOID
		}
	}
	if got := f.git("log", "-1", "--format=%G?", newOID); got != "N" {
		t.Fatalf("rewritten commit still carries a signature status %q", got)
	}
}

func pathOnlySpec(t *testing.T, pattern string) *rules.Spec {
	t.Helper()
	s := &rules.Spec{Rules: []rules.Rule{{Kind: "path", Value: pattern}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}
