package gitx

import (
	"bytes"
	"strings"
	"testing"
)

func TestCommitRoundTripPreservesUnknownHeaders(t *testing.T) {
	raw := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"parent 6f366ff23c2452466881424b1b9414b9c5a5e526\n" +
		"author Ada <ada@example.com> 1700000000 +0100\n" +
		"committer Ada <ada@example.com> 1700000100 +0100\n" +
		"encoding ISO-8859-1\n" +
		"gpgsig -----BEGIN PGP SIGNATURE-----\n \n abc\n -----END PGP SIGNATURE-----\n" +
		"\nsubject\n\nbody with trailing newline\n")
	c, err := ParseCommit("x", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Signed {
		t.Fatal("signature not detected")
	}
	if v, ok := c.Extra.Get("encoding"); !ok || string(v) != "ISO-8859-1" {
		t.Fatalf("encoding not preserved: %q", v)
	}
	// The message must survive byte for byte, including the blank line.
	if string(c.Message) != "subject\n\nbody with trailing newline\n" {
		t.Fatalf("message changed: %q", c.Message)
	}
	out := c.Serialize(c.Tree, c.Parents)
	if bytes.Contains(out, []byte("gpgsig")) {
		t.Fatal("signature kept although the tree may have changed")
	}
	if !bytes.Contains(out, []byte("encoding ISO-8859-1\n")) {
		t.Fatal("encoding header lost in serialization")
	}
	if !bytes.HasSuffix(out, []byte("\nsubject\n\nbody with trailing newline\n")) {
		t.Fatalf("message lost: %q", out)
	}
}

func TestTagWithSSHSignature(t *testing.T) {
	raw := []byte("object 6f366ff23c2452466881424b1b9414b9c5a5e526\n" +
		"type commit\n" +
		"tag v1\n" +
		"tagger Ada <ada@example.com> 1700000000 +0000\n" +
		"\nrelease\n" +
		"-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n")
	tg, err := ParseTag("x", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(tg.Signature) == 0 {
		t.Fatal("ssh signature not separated")
	}
	if strings.TrimSpace(string(tg.Message)) != "release" {
		t.Fatalf("message wrong: %q", tg.Message)
	}
	withSig := tg.Serialize(tg.Object, true)
	if !bytes.Equal(withSig, raw) {
		t.Fatalf("round trip differs:\n%q\n%q", withSig, raw)
	}
	without := tg.Serialize("0000000000000000000000000000000000000000", false)
	if bytes.Contains(without, []byte("SIGNATURE")) {
		t.Fatal("signature retained after retarget")
	}
}

func TestTreeRoundTrip(t *testing.T) {
	entries := []TreeEntry{
		{Mode: "100644", Name: "a.txt", OID: strings.Repeat("ab", 20)},
		{Mode: "40000", Name: "dir", OID: strings.Repeat("cd", 20)},
		{Mode: "100755", Name: "run.sh", OID: strings.Repeat("ef", 20)},
	}
	raw, err := SerializeTree(entries, 20)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTree("x", raw, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(entries) {
		t.Fatalf("entry count %d != %d", len(got), len(entries))
	}
	for i := range entries {
		if got[i] != entries[i] {
			t.Fatalf("entry %d: %+v != %+v", i, got[i], entries[i])
		}
	}
	if _, err := SerializeTree([]TreeEntry{{Mode: "100644", Name: "x", OID: "short"}}, 20); err == nil {
		t.Fatal("expected an error for a wrong-length object id")
	}
}
