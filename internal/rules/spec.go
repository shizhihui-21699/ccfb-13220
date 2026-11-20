// Package rules describes what must be scrubbed: path patterns and content
// features (literal strings, regular expressions and secret presets).
package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Rule is one path pattern or content feature.
type Rule struct {
	// Kind is "path", "literal", "regex" or "preset".
	Kind string `json:"kind"`
	// Value is the glob, the literal string, the regexp, or the preset name.
	Value string `json:"value"`
	// Note is shown to operators in findings and in the audit report.
	Note string `json:"note,omitempty"`
	// IgnoreCase applies to literal and regex rules.
	IgnoreCase bool `json:"ignore_case,omitempty"`
}

// Spec is a complete scrub specification.
type Spec struct {
	Rules []Rule `json:"rules"`
	// MaxScanBytes caps how much of a single file is inspected for content
	// features. Larger files are reported as unscanned and can still be removed
	// by path rule.
	MaxScanBytes int64 `json:"max_scan_bytes,omitempty"`
	// ScanCommitMessages enables scrubbing of the same content features inside
	// commit and tag messages.
	ScanCommitMessages bool `json:"scan_commit_messages,omitempty"`
	// Replacement is what redacted message text is replaced with.
	Replacement string `json:"replacement,omitempty"`
	// PurgeWholeFile (default true) removes every version of a path once any
	// version of that path matches a content rule. Without it, only the blobs
	// that actually contain the secret are removed and earlier clean versions
	// of the same file survive.
	PurgeWholeFile *bool `json:"purge_whole_file,omitempty"`
}

// PurgesWholeFile reports the effective value of PurgeWholeFile.
func (s *Spec) PurgesWholeFile() bool {
	return s.PurgeWholeFile == nil || *s.PurgeWholeFile
}

// DefaultMaxScanBytes is 8 MiB.
const DefaultMaxScanBytes int64 = 8 << 20

// DefaultReplacement is used when Spec.Replacement is empty.
const DefaultReplacement = "***REMOVED***"

// Load reads a JSON spec from disk.
func Load(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Spec
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse spec %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks every rule and normalizes defaults.
func (s *Spec) Validate() error {
	if len(s.Rules) == 0 {
		return errors.New("spec has no rules")
	}
	if s.MaxScanBytes <= 0 {
		s.MaxScanBytes = DefaultMaxScanBytes
	}
	if s.Replacement == "" {
		s.Replacement = DefaultReplacement
	}
	seen := map[string]bool{}
	for i := range s.Rules {
		r := &s.Rules[i]
		r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
		switch r.Kind {
		case "path":
			if strings.TrimSpace(r.Value) == "" {
				return fmt.Errorf("rule #%d: empty path pattern", i+1)
			}
			if _, err := CompileGlob(r.Value); err != nil {
				return fmt.Errorf("rule #%d: %w", i+1, err)
			}
		case "literal":
			if r.Value == "" {
				return fmt.Errorf("rule #%d: empty literal", i+1)
			}
		case "regex":
			if _, err := compileRegex(r.Value, r.IgnoreCase); err != nil {
				return fmt.Errorf("rule #%d: invalid regex: %w", i+1, err)
			}
		case "preset":
			if _, ok := presets[strings.ToLower(r.Value)]; !ok {
				return fmt.Errorf("rule #%d: unknown preset %q (available: %s)", i+1, r.Value, strings.Join(PresetNames(), ", "))
			}
			r.Value = strings.ToLower(r.Value)
		default:
			return fmt.Errorf("rule #%d: unknown kind %q (want path, literal, regex or preset)", i+1, r.Kind)
		}
		key := r.Kind + "\x00" + r.Value
		if seen[key] {
			return fmt.Errorf("rule #%d: duplicate rule %s %q", i+1, r.Kind, r.Value)
		}
		seen[key] = true
	}
	return nil
}

func compileRegex(expr string, ignoreCase bool) (*regexp.Regexp, error) {
	if ignoreCase {
		expr = "(?i)" + expr
	}
	return regexp.Compile(expr)
}

// Preset is a named content feature.
type Preset struct {
	Name        string
	Description string
	Pattern     *regexp.Regexp
	// Entropy-based presets use these instead.
	HighEntropy bool
	MinLen      int
	MinBits     float64
}

var presets = map[string]Preset{}

func init() {
	add := func(p Preset) { presets[p.Name] = p }
	add(Preset{Name: "private_key", Description: "PEM/OpenSSH/PGP private key block",
		Pattern: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`)})
	add(Preset{Name: "aws_access_key", Description: "AWS access key id",
		Pattern: regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA)[0-9A-Z]{16}\b`)})
	add(Preset{Name: "aws_secret_key", Description: "AWS secret access key assignment",
		Pattern: regexp.MustCompile(`(?i)aws_?secret_?access_?key["'\s:=]*[A-Za-z0-9/+=]{40}`)})
	add(Preset{Name: "github_token", Description: "GitHub personal access / app token",
		Pattern: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`)})
	add(Preset{Name: "slack_token", Description: "Slack bot/user/app token",
		Pattern: regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`)})
	add(Preset{Name: "google_api_key", Description: "Google API key",
		Pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)})
	add(Preset{Name: "jwt", Description: "JSON Web Token",
		Pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)})
	add(Preset{Name: "connection_string", Description: "URL with embedded credentials",
		Pattern: regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:[^\s:/@]{6,}@[^\s/]+`)})
	add(Preset{Name: "high_entropy", Description: "Long random-looking token (32+ chars, >=4.0 bits/char)",
		HighEntropy: true, MinLen: 32, MinBits: 4.0})
}

// PresetNames lists available presets, sorted.
func PresetNames() []string {
	names := make([]string, 0, len(presets))
	for n := range presets {
		names = append(names, n)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// PresetByName returns a preset.
func PresetByName(name string) (Preset, bool) {
	p, ok := presets[strings.ToLower(name)]
	return p, ok
}

// MarshalJSON for Spec.
func (s *Spec) MarshalJSON() ([]byte, error) {
	type alias Spec
	return json.Marshal((*alias)(s))
}
