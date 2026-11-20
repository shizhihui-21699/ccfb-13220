package gitx

import (
	"bytes"
	"fmt"
	"strings"
)

// Header is one object header line, with continuation lines folded in.
type Header struct {
	Key   string
	Value []byte
}

// HeaderBlock preserves the exact order of an object's headers.
type HeaderBlock []Header

// Get returns the first header with the given key.
func (h HeaderBlock) Get(key string) ([]byte, bool) {
	for _, x := range h {
		if x.Key == key {
			return x.Value, true
		}
	}
	return nil, false
}

// All returns every value for a key, in order.
func (h HeaderBlock) All(key string) [][]byte {
	var out [][]byte
	for _, x := range h {
		if x.Key == key {
			out = append(out, x.Value)
		}
	}
	return out
}

// parseHeaderBlock splits an object into headers (order preserved, continuation
// lines folded into their parent value) and the message bytes.
func parseHeaderBlock(raw []byte) (HeaderBlock, []byte, error) {
	header, message, ok := bytes.Cut(raw, []byte("\n\n"))
	if !ok {
		return nil, nil, fmt.Errorf("missing blank line between header and message")
	}
	var block HeaderBlock
	for _, line := range bytes.Split(header, []byte("\n")) {
		if len(line) > 0 && line[0] == ' ' {
			if len(block) == 0 {
				return nil, nil, fmt.Errorf("unexpected continuation line")
			}
			block[len(block)-1].Value = append(block[len(block)-1].Value, '\n')
			block[len(block)-1].Value = append(block[len(block)-1].Value, line...)
			continue
		}
		key, val, found := bytes.Cut(line, []byte(" "))
		if !found {
			return nil, nil, fmt.Errorf("malformed header line %q", line)
		}
		block = append(block, Header{Key: string(key), Value: append([]byte(nil), val...)})
	}
	return block, message, nil
}

func serializeHeaderBlock(b *bytes.Buffer, block HeaderBlock, skip func(string) bool) {
	for _, h := range block {
		if skip != nil && skip(h.Key) {
			continue
		}
		if h.Key == "" {
			continue
		}
		b.WriteString(h.Key)
		b.WriteByte(' ')
		b.Write(h.Value)
		b.WriteByte('\n')
	}
}

// Commit is a parsed commit object. Everything that is not deliberately
// changed (encoding, mergetag, message bytes) round-trips exactly.
type Commit struct {
	OID       string
	Tree      string
	Parents   []string
	Author    string
	Committer string
	Extra     HeaderBlock // headers other than tree/parent/author/committer/gpgsig, in order
	Message   []byte
	Signed    bool // had a gpgsig / gpgsig-sha256 header
}

// ParseCommit parses raw commit object bytes.
func ParseCommit(oid string, raw []byte) (*Commit, error) {
	block, message, err := parseHeaderBlock(raw)
	if err != nil {
		return nil, fmt.Errorf("commit %s: %w", oid, err)
	}
	c := &Commit{OID: oid, Message: message}
	for _, h := range block {
		switch h.Key {
		case "tree":
			c.Tree = string(h.Value)
		case "parent":
			c.Parents = append(c.Parents, string(h.Value))
		case "author":
			c.Author = string(h.Value)
		case "committer":
			c.Committer = string(h.Value)
		case "gpgsig", "gpgsig-sha256":
			c.Signed = true
		default:
			c.Extra = append(c.Extra, h)
		}
	}
	if c.Tree == "" || c.Author == "" || c.Committer == "" {
		return nil, fmt.Errorf("commit %s: missing required header", oid)
	}
	return c, nil
}

// Serialize renders the commit with a new tree and parent list. Signatures are
// dropped: the signed payload includes the tree and parents, which we changed.
func (c *Commit) Serialize(newTree string, newParents []string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "tree %s\n", newTree)
	for _, p := range newParents {
		fmt.Fprintf(&b, "parent %s\n", p)
	}
	if c.Author != "" {
		fmt.Fprintf(&b, "author %s\n", c.Author)
	}
	fmt.Fprintf(&b, "committer %s\n", c.Committer)
	serializeHeaderBlock(&b, c.Extra, nil)
	b.WriteByte('\n')
	b.Write(c.Message)
	return b.Bytes()
}

// Tag is a parsed annotated tag object.
type Tag struct {
	OID       string
	Object    string
	Type      string
	Tag       string
	Tagger    string
	HasTagger bool
	Message   []byte // message text without the trailing signature block
	Signature []byte // raw signature block (PGP or SSH), empty when unsigned
	Extra     HeaderBlock
}

// ParseTag parses raw annotated tag object bytes.
func ParseTag(oid string, raw []byte) (*Tag, error) {
	block, message, err := parseHeaderBlock(raw)
	if err != nil {
		return nil, fmt.Errorf("tag %s: %w", oid, err)
	}
	t := &Tag{OID: oid}
	for _, h := range block {
		switch h.Key {
		case "object":
			t.Object = string(h.Value)
		case "type":
			t.Type = string(h.Value)
		case "tag":
			t.Tag = string(h.Value)
		case "tagger":
			t.Tagger = string(h.Value)
			t.HasTagger = true
		default:
			t.Extra = append(t.Extra, h)
		}
	}
	if t.Object == "" || t.Type == "" || t.Tag == "" {
		return nil, fmt.Errorf("tag %s: missing required header", oid)
	}
	t.Message, t.Signature = splitSignature(message)
	return t, nil
}

// splitSignature separates a trailing PGP/SSH signature block from the message.
func splitSignature(message []byte) (body, sig []byte) {
	for _, begin := range []string{"-----BEGIN PGP SIGNATURE-----", "-----BEGIN SSH SIGNATURE-----"} {
		idx := bytes.LastIndex(message, []byte(begin))
		if idx < 0 {
			continue
		}
		if idx > 0 && message[idx-1] != '\n' {
			continue
		}
		return message[:idx], message[idx:]
	}
	return message, nil
}

// Serialize rebuilds the tag around a new target. A signature is only kept
// when the signed payload is byte-identical (same object, no rewrite at all).
func (t *Tag) Serialize(newObject string, keepSignature bool) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "object %s\n", newObject)
	fmt.Fprintf(&b, "type %s\n", t.Type)
	fmt.Fprintf(&b, "tag %s\n", t.Tag)
	if t.HasTagger {
		fmt.Fprintf(&b, "tagger %s\n", t.Tagger)
	}
	serializeHeaderBlock(&b, t.Extra, nil)
	b.WriteByte('\n')
	b.Write(t.Message)
	if keepSignature && len(t.Signature) > 0 {
		b.Write(t.Signature)
	}
	return b.Bytes()
}

// TreeEntry is one entry of a git tree object.
type TreeEntry struct {
	Mode string
	Name string
	OID  string
}

// IsDir reports whether the entry is a subtree (mode 40000).
func (e TreeEntry) IsDir() bool { return e.Mode == "40000" || e.Mode == "040000" }

// ParseTree parses raw tree object content for the given hash length in bytes.
func ParseTree(oid string, raw []byte, hashLen int) ([]TreeEntry, error) {
	var entries []TreeEntry
	rest := raw
	for len(rest) > 0 {
		sp := bytes.IndexByte(rest, ' ')
		if sp < 0 {
			return nil, fmt.Errorf("tree %s: truncated mode", oid)
		}
		mode := string(rest[:sp])
		rest = rest[sp+1:]
		nul := bytes.IndexByte(rest, 0)
		if nul < 0 {
			return nil, fmt.Errorf("tree %s: truncated name", oid)
		}
		name := string(rest[:nul])
		rest = rest[nul+1:]
		if len(rest) < hashLen {
			return nil, fmt.Errorf("tree %s: truncated object id", oid)
		}
		entries = append(entries, TreeEntry{Mode: mode, Name: name, OID: fmt.Sprintf("%x", rest[:hashLen])})
		rest = rest[hashLen:]
	}
	return entries, nil
}

// SerializeTree renders tree entries in their existing order (git stores trees
// sorted, so preserving input order preserves validity).
func SerializeTree(entries []TreeEntry, hashLen int) ([]byte, error) {
	var b bytes.Buffer
	for _, e := range entries {
		if len(e.OID) != hashLen*2 {
			return nil, fmt.Errorf("tree entry %q: bad object id %q", e.Name, e.OID)
		}
		fmt.Fprintf(&b, "%s %s", e.Mode, e.Name)
		b.WriteByte(0)
		for i := 0; i < hashLen; i++ {
			hi, lo := e.OID[i*2], e.OID[i*2+1]
			b.WriteByte(hexVal(hi)<<4 | hexVal(lo))
		}
	}
	return b.Bytes(), nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// IdentityOf extracts the "Name <email>" part of a raw author/tagger line.
func IdentityOf(line string) string {
	if i := strings.LastIndexByte(line, '>'); i >= 0 {
		return line[:i+1]
	}
	return line
}
