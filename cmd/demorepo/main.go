package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// demo builds a realistic leaky repository: two branches, a merge, a signed
// commit, a signed annotated tag, a customer export that is deleted in a later
// commit (the mistake this tool exists to fix) and a production key that lives
// inside an otherwise ordinary config file.
func main() {
	out := flag.String("out", "demo/leaky-repo", "directory to create")
	sign := flag.Bool("sign", true, "create an ssh signing key and sign a commit and a tag")
	flag.Parse()

	if err := run(*out, *sign); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
	fmt.Printf("\nDemo repository ready: %s\n", *out)
	fmt.Println("Try:")
	fmt.Printf("  go run ./cmd/scrub plan   --repo %s --spec demo/leaky-spec.json\n", *out)
	fmt.Printf("  go run ./cmd/scrub run    --repo %s --spec demo/leaky-spec.json --out demo/report.json\n", *out)
}

func run(dir string, sign bool) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err == nil {
		return fmt.Errorf("%s already exists; remove it first", abs)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}
	// Keep the demo hermetic: no system or user git config can change the result.
	home, err := os.MkdirTemp("", "historyscrub-demo-home-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(home)

	g := &gitc{dir: abs, env: append(os.Environ(),
		"HOME="+home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Ada Lovelace", "GIT_AUTHOR_EMAIL=ada@example.com",
		"GIT_COMMITTER_NAME=Ada Lovelace", "GIT_COMMITTER_EMAIL=ada@example.com",
	)}
	if err := g.run("init", "-q", "-b", "main"); err != nil {
		return err
	}
	g.mustRun("config", "user.name", "Ada Lovelace")
	g.mustRun("config", "user.email", "ada@example.com")

	var keyPath, allowed string
	if sign {
		keyPath = abs + "-signing-key"
		os.Remove(keyPath)
		os.Remove(keyPath + ".pub")
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", keyPath, "-C", "ada@example.com").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: ssh-keygen failed, continuing unsigned: %v %s\n", err, out)
			sign = false
		} else {
			allowed = abs + "-allowed-signers"
			pub, err := os.ReadFile(keyPath + ".pub")
			if err != nil {
				return err
			}
			if err := os.WriteFile(allowed, []byte("ada@example.com "+strings.TrimSpace(string(pub))+"\n"), 0o644); err != nil {
				return err
			}
			g.mustRun("config", "gpg.format", "ssh")
			g.mustRun("config", "user.signingkey", keyPath)
			g.mustRun("config", "gpg.ssh.allowedSignersFile", allowed)
		}
	}

	write := func(rel, content string) error {
		full := filepath.Join(abs, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		return os.WriteFile(full, []byte(content), 0o644)
	}
	commit := func(msg string, signed bool) error {
		if err := g.run("add", "-A"); err != nil {
			return err
		}
		args := []string{"commit", "-q", "-m", msg}
		if signed {
			args = append(args, "-S")
		}
		return g.run(args...)
	}

	// --- history ---------------------------------------------------------
	if err := write("README.md", "# analytics-service\n\nInternal analytics service.\n"); err != nil {
		return err
	}
	if err := write("go.mod", "module analytics-service\n\ngo 1.22\n"); err != nil {
		return err
	}
	if err := write("internal/api/server.go", "package api\n\nfunc Serve() {}\n"); err != nil {
		return err
	}
	if err := commit("initial analytics service", false); err != nil {
		return err
	}

	if err := write("internal/api/reports.go", "package api\n\nfunc Reports() {}\n"); err != nil {
		return err
	}
	if err := commit("add reports endpoint", false); err != nil {
		return err
	}

	// The mistake: a customer export with real-looking PII.
	export := "customer_id,email,full_name,phone,address\n" +
		"1001,grace@example.com,Grace Hopper,+1-555-0100,1 Compiler Way\n" +
		"1002,alan@example.com,Alan Turing,+1-555-0101,2 Enigma Road\n" +
		"1003,edsger@example.com,Edsger Dijkstra,+1-555-0102,3 Shortest Path\n"
	if err := write("exports/customers-2024-03.csv", export); err != nil {
		return err
	}
	if err := commit("export customers for the Q1 churn analysis", false); err != nil {
		return err
	}
	if err := write("internal/api/reports.go", "package api\n\nimport \"time\"\n\nfunc Reports() { _ = time.Now }\n"); err != nil {
		return err
	}
	if err := commit("chore: format analytics report query", false); err != nil {
		return err
	}

	if err := write("deploy/prod.env", "API_BASE=https://api.example.com\nLOG_LEVEL=info\n"); err != nil {
		return err
	}
	if err := commit("add production deploy config", false); err != nil {
		return err
	}

	// The key that must not be in git, added with a plausible-looking change.
	if err := write("deploy/prod.env", "API_BASE=https://api.example.com\nLOG_LEVEL=info\n"+
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"+
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"); err != nil {
		return err
	}
	if err := commit("deploy: point production at the new API host", false); err != nil {
		return err
	}

	// A signed commit, so the rewrite demonstrably invalidates a signature.
	if err := write("internal/api/reports_test.go", "package api\n\nimport \"testing\"\n\nfunc TestReports(t *testing.T) {}\n"); err != nil {
		return err
	}
	if err := commit("test: cover the reports endpoint", sign); err != nil {
		return err
	}

	// Feature branch with a merge back, so the rewrite has to fix merge parents.
	if err := g.run("checkout", "-q", "-b", "feature/churn-report"); err != nil {
		return err
	}
	if err := write("internal/api/churn.go", "package api\n\nfunc Churn() {}\n"); err != nil {
		return err
	}
	if err := commit("add churn report", false); err != nil {
		return err
	}
	if err := write("internal/api/churn.go", "package api\n\nfunc Churn() { /* v2 */ }\n"); err != nil {
		return err
	}
	if err := commit("churn report: handle empty cohorts", false); err != nil {
		return err
	}
	if err := g.run("checkout", "-q", "main"); err != nil {
		return err
	}
	if err := write("CHANGELOG.md", "# Changelog\n\n## Unreleased\n\n- churn report\n"); err != nil {
		return err
	}
	if err := commit("start changelog", false); err != nil {
		return err
	}
	if err := g.run("merge", "-q", "--no-ff", "-m", "merge: feature/churn-report", "feature/churn-report"); err != nil {
		return err
	}

	// A signed annotated tag on the release commit.
	tagArgs := []string{"tag", "-a", "-m", "release 2024.03"}
	if sign {
		tagArgs = []string{"tag", "-s", "-m", "release 2024.03"}
	}
	if err := g.run(append(tagArgs, "v2024.03")...); err != nil {
		return err
	}

	// The thing everyone tries first, which does not work: delete the file.
	if err := g.run("rm", "-q", "exports/customers-2024-03.csv"); err != nil {
		return err
	}
	if err := commit("remove accidental customer export", false); err != nil {
		return err
	}
	if err := write("docs/runbook.md", "# Runbook\n\nRotate keys quarterly.\n"); err != nil {
		return err
	}
	if err := commit("docs: add runbook", false); err != nil {
		return err
	}

	// A leaky branch left behind, which the rewrite must also clean.
	if err := g.run("checkout", "-q", "-b", "hotfix/keys", "main~4"); err != nil {
		return err
	}
	if err := write("keys/deploy_signing.pem", "-----BEGIN OPENSSH PRIVATE KEY-----\n"+
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"+
		"QyNTUxOQAAACBkZW1vb25seWtleWZvcmRlbW9uc3RyYXRpb25vbmx5AAAAAEXAMPLE\n"+
		"-----END OPENSSH PRIVATE KEY-----\n"); err != nil {
		return err
	}
	if err := commit("hotfix: add deploy signing key (TEMPORARY)", false); err != nil {
		return err
	}
	if err := g.run("checkout", "-q", "main"); err != nil {
		return err
	}

	fmt.Printf("created %s\n", abs)
	if sign {
		fmt.Printf("signing key (outside the repo): %s\n", keyPath)
	}
	return nil
}

type gitc struct {
	dir string
	env []string
}

func (g *gitc) run(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.dir
	cmd.Env = g.env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (g *gitc) mustRun(args ...string) {
	if err := g.run(args...); err != nil {
		panic(fmt.Sprintf("git %s: %v", strings.Join(args, " "), err))
	}
}
