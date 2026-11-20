package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// Glob support: gitignore-style patterns without leading "!" negation.
//
//	**      matches any number of path segments
//	*       matches any run of characters except "/"
//	?       matches one character except "/"
//	[a-z]   character class
//
// A pattern without any slash matches at any depth (so "*.pem" matches
// "keys/prod.pem"). A leading slash anchors to the repository root. A trailing
// slash matches directories and everything under them.
var globCache = map[string]*regexp.Regexp{}

// CompileGlob converts a gitignore-style glob into an anchored regexp.
func CompileGlob(pattern string) (*regexp.Regexp, error) {
	key := pattern
	if re, ok := globCache[key]; ok {
		return re, nil
	}
	p := strings.TrimSpace(pattern)
	if p == "" {
		return nil, fmt.Errorf("empty glob")
	}
	dirOnly := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	anchored := strings.HasPrefix(p, "/")
	p = strings.TrimPrefix(p, "/")

	var b strings.Builder
	b.WriteString("^")
	if !anchored && !strings.Contains(p, "/") {
		b.WriteString("(?:.*/)?")
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if seg == "**" {
			if i == len(segs)-1 {
				b.WriteString(".*")
			} else {
				b.WriteString("(?:.*/)?")
			}
			continue
		}
		if i > 0 && segs[i-1] != "**" {
			b.WriteString("/")
		}
		compileSegment(&b, seg)
	}
	if dirOnly {
		b.WriteString("/?.*")
	}
	if !dirOnly {
		b.WriteString("$")
	}
	expr := b.String()
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("glob %q: %w", pattern, err)
	}
	globCache[key] = re
	return re, nil
}

func compileSegment(b *strings.Builder, seg string) {
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch c {
		case '*':
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '[':
			end := strings.IndexByte(seg[i:], ']')
			if end < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := seg[i : i+end+1]
			class = strings.ReplaceAll(class, `\`, `\\`)
			b.WriteString(class)
			i += end
		case '\\':
			if i+1 < len(seg) {
				i++
				b.WriteString(regexp.QuoteMeta(string(seg[i])))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
}
