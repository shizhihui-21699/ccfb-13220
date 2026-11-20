package rules

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Compiled is a Spec compiled into matchers.
type Compiled struct {
	Spec        *Spec
	pathRules   []pathRule
	content     []contentRule
	replacement []byte
	maxScan     int64
	scanMsgs    bool
}

type pathRule struct {
	Rule
	re *regexp.Regexp
}

type contentRule struct {
	Rule
	re      *regexp.Regexp
	literal []byte
	lowLit  []byte
	preset  Preset
	key     string
}

// Compile prepares a spec for matching.
func Compile(s *Spec) (*Compiled, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	c := &Compiled{
		Spec:        s,
		replacement: []byte(s.Replacement),
		maxScan:     s.MaxScanBytes,
		scanMsgs:    s.ScanCommitMessages,
	}
	for _, r := range s.Rules {
		switch r.Kind {
		case "path":
			re, err := CompileGlob(r.Value)
			if err != nil {
				return nil, err
			}
			c.pathRules = append(c.pathRules, pathRule{Rule: r, re: re})
		case "literal":
			cr := contentRule{Rule: r}
			lit := []byte(r.Value)
			cr.literal = lit
			cr.key = "literal:" + r.Value
			if r.IgnoreCase {
				cr.lowLit = bytes.ToLower(lit)
			}
			c.content = append(c.content, cr)
		case "regex":
			re, err := compileRegex(r.Value, r.IgnoreCase)
			if err != nil {
				return nil, err
			}
			c.content = append(c.content, contentRule{Rule: r, re: re, key: "regex:" + r.Value})
		case "preset":
			p, _ := PresetByName(r.Value)
			cr := contentRule{Rule: r, preset: p, key: "preset:" + p.Name}
			if !p.HighEntropy {
				cr.re = p.Pattern
			}
			c.content = append(c.content, cr)
		}
	}
	return c, nil
}

// HasPathRules reports whether any path rule exists.
func (c *Compiled) HasPathRules() bool { return len(c.pathRules) > 0 }

// HasContentRules reports whether any content rule exists.
func (c *Compiled) HasContentRules() bool { return len(c.content) > 0 }

// ScanCommitMessages reports whether messages should be scrubbed.
func (c *Compiled) ScanCommitMessages() bool { return c.scanMsgs }

// PurgesWholeFile reports whether a content match condemns every version of
// the matched path.
func (c *Compiled) PurgesWholeFile() bool { return c.Spec.PurgesWholeFile() }

// MaxScanBytes is the per-file inspection cap.
func (c *Compiled) MaxScanBytes() int64 { return c.maxScan }

// Replacement is the redaction text.
func (c *Compiled) Replacement() string { return string(c.replacement) }

// MatchPath returns the path rules matching a repo-relative path (slash
// separated) and whether the entry is a directory.
func (c *Compiled) MatchPath(path string, isDir bool) []Rule {
	var hits []Rule
	probe := path
	if isDir && !strings.HasSuffix(probe, "/") {
		probe += "/"
	}
	for _, pr := range c.pathRules {
		if pr.re.MatchString(probe) || pr.re.MatchString(path) {
			hits = append(hits, pr.Rule)
		}
	}
	return hits
}

// Hit is one content match.
type Hit struct {
	Rule   Rule
	Offset int
	Line   int
	Match  []byte
	// Preset is set when the rule is a preset.
	PresetName string
}

// ScanContent returns content hits for a blob's bytes, deduplicated per rule
// (first match per rule is enough to decide a blob is dirty). Overlapping
// matches of different rules are all reported.
func (c *Compiled) ScanContent(data []byte) []Hit {
	if len(c.content) == 0 || len(data) == 0 {
		return nil
	}
	if int64(len(data)) > c.maxScan {
		data = data[:c.maxScan]
	}
	var hits []Hit
	for _, cr := range c.content {
		h, ok := cr.find(data)
		if ok {
			h.PresetName = cr.preset.Name
			hits = append(hits, h)
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Offset < hits[j].Offset })
	return hits
}

func (cr *contentRule) find(data []byte) (Hit, bool) {
	if cr.preset.HighEntropy {
		if off, tok := findHighEntropy(data, cr.preset.MinLen, cr.preset.MinBits); off >= 0 {
			return Hit{Rule: cr.Rule, Offset: off, Line: lineOf(data, off), Match: tok}, true
		}
		return Hit{}, false
	}
	if cr.re != nil {
		loc := cr.re.FindIndex(data)
		if loc == nil {
			return Hit{}, false
		}
		return Hit{Rule: cr.Rule, Offset: loc[0], Line: lineOf(data, loc[0]), Match: data[loc[0]:loc[1]]}, true
	}
	idx := -1
	if cr.lowLit != nil {
		idx = bytes.Index(bytes.ToLower(data), cr.lowLit)
	} else {
		idx = bytes.Index(data, cr.literal)
	}
	if idx < 0 {
		return Hit{}, false
	}
	return Hit{Rule: cr.Rule, Offset: idx, Line: lineOf(data, idx), Match: data[idx : idx+len(cr.literal)]}, true
}

// RedactMessage replaces every content match in a message with the
// replacement text. Returns the new bytes and whether anything changed.
func (c *Compiled) RedactMessage(msg []byte) ([]byte, []Hit) {
	if !c.scanMsgs || len(c.content) == 0 {
		return msg, nil
	}
	// Collect all match spans across rules.
	type span struct{ start, end int }
	var spans []span
	var hits []Hit
	for _, cr := range c.content {
		if cr.preset.HighEntropy {
			off, tok := findHighEntropy(msg, cr.preset.MinLen, cr.preset.MinBits)
			if off >= 0 {
				spans = append(spans, span{off, off + len(tok)})
				hits = append(hits, Hit{Rule: cr.Rule, Offset: off, Line: lineOf(msg, off), Match: tok, PresetName: cr.preset.Name})
			}
			continue
		}
		if cr.re != nil {
			for _, loc := range cr.re.FindAllIndex(msg, -1) {
				spans = append(spans, span{loc[0], loc[1]})
				hits = append(hits, Hit{Rule: cr.Rule, Offset: loc[0], Line: lineOf(msg, loc[0]), Match: msg[loc[0]:loc[1]], PresetName: cr.preset.Name})
			}
			continue
		}
		search := msg
		if cr.lowLit != nil {
			search = bytes.ToLower(msg)
		}
		at := 0
		for {
			idx := bytes.Index(search[at:], firstNonNil(cr.lowLit, cr.literal))
			if idx < 0 {
				break
			}
			abs := at + idx
			spans = append(spans, span{abs, abs + len(cr.literal)})
			hits = append(hits, Hit{Rule: cr.Rule, Offset: abs, Line: lineOf(msg, abs), Match: msg[abs : abs+len(cr.literal)]})
			at = abs + len(cr.literal)
		}
	}
	if len(spans) == 0 {
		return msg, nil
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var out bytes.Buffer
	prev := 0
	for _, s := range spans {
		if s.start < prev {
			if s.end > prev {
				prev = s.end
			}
			continue
		}
		out.Write(msg[prev:s.start])
		out.Write(c.replacement)
		prev = s.end
	}
	out.Write(msg[prev:])
	return out.Bytes(), hits
}

func firstNonNil(a, b []byte) []byte {
	if a != nil {
		return a
	}
	return b
}

// lineOf returns the 1-based line number of an offset.
func lineOf(data []byte, off int) int {
	if off > len(data) {
		off = len(data)
	}
	return 1 + bytes.Count(data[:off], []byte("\n"))
}

// entropyToken matches candidate high-entropy tokens.
var entropyToken = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{16,}`)

func findHighEntropy(data []byte, minLen int, minBits float64) (int, []byte) {
	for _, loc := range entropyToken.FindAllIndex(data, -1) {
		tok := data[loc[0]:loc[1]]
		if len(tok) < minLen {
			continue
		}
		if looksLikeProse(tok) {
			continue
		}
		if shannonBits(tok) >= minBits {
			return loc[0], tok
		}
	}
	return -1, nil
}

func looksLikeProse(tok []byte) bool {
	// Long runs of lowercase letters with no digits are usually words/identifiers.
	hasDigit, hasUpper, hasLower := false, false, false
	for _, b := range tok {
		switch {
		case b >= '0' && b <= '9':
			hasDigit = true
		case b >= 'A' && b <= 'Z':
			hasUpper = true
		case b >= 'a' && b <= 'z':
			hasLower = true
		}
	}
	return !hasDigit && !(hasUpper && hasLower)
}

func shannonBits(tok []byte) float64 {
	if len(tok) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range tok {
		freq[b]++
	}
	var h float64
	n := float64(len(tok))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// FormatPreview renders a match for reports without exposing the whole secret.
func FormatPreview(match []byte, keep int) string {
	s := string(match)
	if keep < 2 {
		keep = 2
	}
	if len(s) <= keep*2+3 {
		return strings.Repeat("*", len(s))
	}
	return s[:keep] + strings.Repeat("*", 6) + s[len(s)-keep:]
}

// DescribeRule is a short label for reports.
func DescribeRule(r Rule) string {
	switch r.Kind {
	case "preset":
		return "preset:" + r.Value
	case "path":
		return "path:" + r.Value
	case "literal":
		return "literal"
	case "regex":
		return "regex"
	}
	return fmt.Sprintf("%s:%s", r.Kind, r.Value)
}
