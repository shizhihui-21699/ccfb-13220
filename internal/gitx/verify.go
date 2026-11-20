package gitx

import (
	"strconv"
	"strings"
)

// SignatureStatus is the outcome of verifying one signature.
type SignatureStatus struct {
	Status string // G good, B bad, U unknown key, X expired sig, Y expired key, R revoked key, E missing, N no signature
	Signer string
	Key    string
	Finger string
	Trust  string
	Err    string
}

// Human renders a short human-readable status.
func (s SignatureStatus) Human() string {
	switch s.Status {
	case "G":
		return "valid"
	case "B":
		return "BAD signature"
	case "U":
		return "unknown signer key"
	case "X":
		return "signature expired"
	case "Y":
		return "signer key expired"
	case "R":
		return "signer key revoked"
	case "E":
		return "cannot verify (missing key or config)"
	case "N":
		return "unsigned"
	}
	return s.Status
}

// VerifyCommits verifies the signatures recorded in the given commits.
// Only commits that carry a signature header are checked; the rest report N.
func (r *Repo) VerifyCommits(oids []string) (map[string]SignatureStatus, error) {
	out := map[string]SignatureStatus{}
	if len(oids) == 0 {
		return out, nil
	}
	// %G? and friends are only meaningful for signed commits, and only when
	// gpg/ssh verification is configured. Failures are reported per commit as E
	// rather than aborting the run.
	for _, batch := range chunk(oids, 500) {
		args := append([]string{"log", "--no-walk=unsorted", "--stdin", "--format=%H%x00%G?%x00%GK%x00%GF%x00%GS%x00%GX%x00%GT"}, "--")
		list, err := r.RunInput([]byte(strings.Join(batch, "\n")+"\n"), args...)
		if err != nil {
			// Retry one at a time so a single bad object does not lose the batch.
			for _, oid := range batch {
				one, e := r.verifyOne(oid)
				if e != nil {
					out[oid] = SignatureStatus{Status: "E", Err: e.Error()}
					continue
				}
				out[oid] = one
			}
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(list), "\n") {
			if line == "" {
				continue
			}
			f := strings.Split(line, "\x00")
			if len(f) < 7 {
				continue
			}
			out[f[0]] = SignatureStatus{Status: f[1], Key: f[2], Finger: f[3], Signer: f[4], Trust: f[5]}
		}
	}
	return out, nil
}

func (r *Repo) verifyOne(oid string) (SignatureStatus, error) {
	list, err := r.Output("log", "--no-walk=unsorted", "-1", "--format=%H%x00%G?%x00%GK%x00%GF%x00%GS%x00%GX%x00%GT", oid)
	if err != nil {
		return SignatureStatus{}, err
	}
	f := strings.Split(strings.TrimSpace(list), "\x00")
	if len(f) < 7 {
		return SignatureStatus{}, nil
	}
	return SignatureStatus{Status: f[1], Key: f[2], Finger: f[3], Signer: f[4], Trust: f[5]}, nil
}

// VerifyTag verifies an annotated tag object's signature.
//
// `git verify-tag` has no --format, so this parses the machine-readable
// `--raw` status lines ([GNUPG:] ...) rather than the human sentence, which is
// localised and changes between git and gpg versions.
func (r *Repo) VerifyTag(name string) (SignatureStatus, error) {
	stdout, stderr, err := r.OutputBoth("verify-tag", "--raw", name)
	out := stdout + "\n" + stderr
	s := parseStatusLines(out)
	if s.Status == "" {
		// SSH and X.509 signatures are verified by git itself, which emits no
		// [GNUPG:] lines. Our subprocesses run with LC_ALL=C, so the sentence
		// below is stable English.
		s = parseVerifySentence(out)
	}
	if err != nil {
		if s.Status == "" || s.Status == "E" {
			switch {
			case strings.Contains(out, "no signature found"):
				s.Status, s.Err = "N", ""
			case strings.Contains(out, "BAD signature"):
				s.Status = "B"
			case strings.Contains(out, "No principal matched"), strings.Contains(out, "unknown key"):
				s.Status = "U"
			default:
				s.Status = "E"
				s.Err = err.Error()
			}
		}
		return s, nil
	}
	if s.Status == "" {
		s.Status = "N"
	}
	return s, nil
}

// parseVerifySentence extracts the signer from git's own English output.
func parseVerifySentence(out string) SignatureStatus {
	var s SignatureStatus
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Good ") && strings.Contains(line, "signature for "):
			s.Status = "G"
			rest := line[strings.Index(line, "signature for ")+len("signature for "):]
			if i := strings.Index(rest, " with "); i > 0 {
				rest = rest[:i]
			}
			s.Signer = rest
		case strings.Contains(line, "BAD signature"):
			s.Status = "B"
		case strings.Contains(line, "No principal matched"):
			s.Status = "U"
		}
	}
	return s
}

// parseStatusLines maps gpg status lines to a SignatureStatus.
func parseStatusLines(out string) SignatureStatus {
	var s SignatureStatus
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[GNUPG:] ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "[GNUPG:] "))
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "GOODSIG":
			s.Status = "G"
			if len(fields) >= 2 {
				s.Key = fields[1]
			}
			if len(fields) >= 3 {
				s.Signer = strings.Join(fields[2:], " ")
			}
		case "BADSIG":
			s.Status = "B"
			if len(fields) >= 2 {
				s.Key = fields[1]
			}
			if len(fields) >= 3 {
				s.Signer = strings.Join(fields[2:], " ")
			}
		case "EXPSIG":
			s.Status = "X"
		case "EXPKEYSIG":
			s.Status = "Y"
		case "REVKEYSIG":
			s.Status = "R"
		case "ERRSIG":
			if s.Status == "" {
				s.Status = "E"
			}
			if len(fields) >= 3 {
				s.Key = fields[2]
			}
			if len(fields) >= 2 && strings.HasPrefix(fields[1], "NO_PUBKEY") {
				s.Status = "U"
			}
		case "NO_PUBKEY":
			if s.Status == "" || s.Status == "E" {
				s.Status = "U"
			}
		case "VALIDSIG":
			if len(fields) >= 2 {
				s.Finger = fields[1]
			}
			if len(fields) >= 2 && s.Key == "" {
				s.Key = fields[1]
			}
		case "TRUST_ULTIMATE", "TRUST_FULLY", "TRUST_MARGINAL":
			s.Trust = strings.TrimPrefix(fields[0], "TRUST_")
		}
	}
	return s
}

// HasSigningConfigured reports whether git is configured to make signatures.
func (r *Repo) HasSigningConfigured() bool {
	return r.GitConfig("user.signingkey") != ""
}

func chunk(xs []string, n int) [][]string {
	var out [][]string
	for len(xs) > n {
		out = append(out, xs[:n])
		xs = xs[n:]
	}
	if len(xs) > 0 {
		out = append(out, xs)
	}
	return out
}

// ParseTimeFromIdentity returns the unix timestamp embedded in a raw
// "Name <email> 1700000000 +0100" identity line.
func ParseTimeFromIdentity(id string) (int64, bool) {
	fields := strings.Fields(id)
	if len(fields) < 3 {
		return 0, false
	}
	ts, err := strconv.ParseInt(fields[len(fields)-2], 10, 64)
	if err != nil {
		return 0, false
	}
	return ts, true
}
