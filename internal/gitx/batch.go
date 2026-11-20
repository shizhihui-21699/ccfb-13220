package gitx

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// BatchReader reads objects through a single long-lived `git cat-file --batch`.
type BatchReader struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr bytes.Buffer
	closed bool
}

// NewBatchReader starts the cat-file process.
func (r *Repo) NewBatchReader() (*BatchReader, error) {
	cmd := r.command("cat-file", "--batch")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	br := &BatchReader{cmd: cmd, stdin: in, stdout: bufio.NewReaderSize(out, 1<<16)}
	cmd.Stderr = &br.stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return br, nil
}

// Read returns the type and raw bytes of one object. A missing object returns
// ErrMissingObject.
func (b *BatchReader) Read(oid string) (string, []byte, error) {
	if _, err := io.WriteString(b.stdin, oid+"\n"); err != nil {
		return "", nil, fmt.Errorf("cat-file write: %w", err)
	}
	line, err := b.stdout.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("cat-file read: %w (stderr: %s)", err, strings.TrimSpace(b.stderr.String()))
	}
	line = strings.TrimSuffix(line, "\n")
	if strings.HasSuffix(line, " missing") || strings.HasSuffix(line, " ambiguous") || strings.HasSuffix(line, " ambiguous") {
		return "", nil, ErrMissingObject
	}
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return "", nil, fmt.Errorf("cat-file: unexpected header %q", line)
	}
	size, err := strconv.Atoi(fields[2])
	if err != nil {
		return "", nil, fmt.Errorf("cat-file: bad size in %q", line)
	}
	data := make([]byte, size+1) // +1 for the trailing newline
	if _, err := io.ReadFull(b.stdout, data); err != nil {
		return "", nil, fmt.Errorf("cat-file: short read: %w", err)
	}
	return fields[1], data[:size], nil
}

// Close shuts the process down.
func (b *BatchReader) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	b.stdin.Close()
	return b.cmd.Wait()
}
