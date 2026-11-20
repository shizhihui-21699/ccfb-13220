package rules

import "testing"

func TestGlobSemantics(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		isDir   bool
		want    bool
	}{
		{"exports/*.csv", "exports/customers.csv", false, true},
		{"exports/*.csv", "exports/2024/customers.csv", false, false},
		{"exports/**/*.csv", "exports/2024/q1/customers.csv", false, true},
		{"*.pem", "keys/prod.pem", false, true},
		{"*.pem", "prod.pem", false, true},
		{"/keys/", "keys", true, true},
		{"/keys/", "keys/deploy.pem", false, true},
		{"keys/", "nested/keys", true, true},
		{"keys/", "notkeys", true, false},
		{"**/id_rsa*", "a/b/id_rsa.pub", false, true},
		{"id_rsa*", "a/b/id_rsa", false, true},
		{"*.key", "README.md", false, false},
		{"docs/**", "docs/a/b.md", false, true},
		{"docs/**", "src/a.md", false, false},
	}
	for _, c := range cases {
		re, err := CompileGlob(c.pattern)
		if err != nil {
			t.Fatalf("%s: %v", c.pattern, err)
		}
		probe := c.path
		if c.isDir {
			probe += "/"
		}
		got := re.MatchString(probe) || re.MatchString(c.path)
		if got != c.want {
			t.Errorf("glob %q vs %q (dir=%v) = %v, want %v (regex %s)", c.pattern, c.path, c.isDir, got, c.want, re)
		}
	}
}

func TestContentRules(t *testing.T) {
	spec := &Spec{Rules: []Rule{
		{Kind: "preset", Value: "aws_access_key"},
		{Kind: "preset", Value: "private_key"},
		{Kind: "preset", Value: "high_entropy"},
		{Kind: "literal", Value: "customer-jane@example.com", IgnoreCase: true},
	}}
	c, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	dirty := []byte("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" +
		"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n" +
		"contact Customer-Jane@example.com\n" +
		"token=Zx8Qv2LmN4pR7tY1wB6cF3hJ9kS5dG0aE2uI4oP8\n")
	hits := c.ScanContent(dirty)
	seen := map[string]bool{}
	for _, h := range hits {
		seen[h.PresetName] = true
		seen[DescribeRule(h.Rule)] = true
	}
	for _, want := range []string{"aws_access_key", "private_key", "high_entropy", "literal"} {
		if !seen[want] {
			t.Errorf("missing hit %q, got %v", want, seen)
		}
	}

	clean := []byte("package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\nvar someLongIdentifierName = 1\n")
	if hits := c.ScanContent(clean); len(hits) != 0 {
		t.Fatalf("false positives on ordinary source: %+v", hits)
	}
}

func TestHighEntropyIgnoresProse(t *testing.T) {
	spec := &Spec{Rules: []Rule{{Kind: "preset", Value: "high_entropy"}}}
	c, _ := Compile(spec)
	// Long camelCase identifier and a URL path are not secrets.
	for _, s := range []string{
		"internalServerErrorHandlerFactoryWrapperImpl",
		"https://example.com/some/long/path/to/a/resource",
		"com.example.analytics.service.ReportsController",
	} {
		if hits := c.ScanContent([]byte(s)); len(hits) > 0 {
			t.Errorf("false positive on %q: %+v", s, hits)
		}
	}
}

func TestSpecValidation(t *testing.T) {
	bad := []*Spec{
		{},
		{Rules: []Rule{{Kind: "nope", Value: "x"}}},
		{Rules: []Rule{{Kind: "regex", Value: "(["}}},
		{Rules: []Rule{{Kind: "preset", Value: "not_a_preset"}}},
		{Rules: []Rule{{Kind: "literal", Value: ""}}},
		{Rules: []Rule{{Kind: "path", Value: "a"}, {Kind: "path", Value: "a"}}},
	}
	for i, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("case %d: expected a validation error", i)
		}
	}
	good := &Spec{Rules: []Rule{{Kind: "path", Value: "*.csv"}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if !good.PurgesWholeFile() {
		t.Error("purge_whole_file should default to true")
	}
	if good.MaxScanBytes == 0 || good.Replacement == "" {
		t.Error("defaults were not applied")
	}
}

func TestRedactMessage(t *testing.T) {
	spec := &Spec{
		Rules:              []Rule{{Kind: "literal", Value: "AKIAIOSFODNN7EXAMPLE"}},
		ScanCommitMessages: true,
		Replacement:        "[redacted]",
	}
	c, _ := Compile(spec)
	out, hits := c.RedactMessage([]byte("fix: rotate AKIAIOSFODNN7EXAMPLE before release"))
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if string(out) != "fix: rotate [redacted] before release" {
		t.Fatalf("got %q", out)
	}
	if _, hits := c.RedactMessage([]byte("fix: nothing here")); len(hits) != 0 {
		t.Fatal("unexpected hit")
	}
}
