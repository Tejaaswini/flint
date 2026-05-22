package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"flint/pkg/api"
)

// Writer is a concurrency-safe append-only JSONL writer for audit rows.
// A single mutex serializes writes so the file always contains complete lines.
// File rotation is not in scope for v1 but the interface is designed to allow
// it: callers hold only a *Writer and the path is stored for external inspection.
type Writer struct {
	f    *os.File
	bw   *bufio.Writer
	enc  *json.Encoder
	mu   sync.Mutex
	path string

	// poisoned is set once any write fails. Further writes are refused so
	// a partial line from an encoder mid-error cannot corrupt subsequent
	// rows in the JSONL stream.
	poisoned error
}

// NewWriter opens (or creates) the file at path in append mode and returns a
// Writer ready for use. The caller must call Close when done.
func NewWriter(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("audit writer: open %s: %w", path, err)
	}
	bw := bufio.NewWriter(f)
	return &Writer{
		f:    f,
		bw:   bw,
		enc:  json.NewEncoder(bw),
		path: path,
	}, nil
}

// Write marshals row as a single JSON line and flushes the buffer.
// It sets row.SchemaVersion to api.AuditSchemaVersion before marshaling so
// callers do not need to remember to do it.
// Write is safe to call concurrently from multiple goroutines.
func (w *Writer) Write(row api.DecisionRow) error {
	row.SchemaVersion = api.AuditSchemaVersion
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned != nil {
		return fmt.Errorf("audit writer: refusing write (poisoned): %w", w.poisoned)
	}
	if err := w.enc.Encode(row); err != nil {
		w.poisoned = err
		return fmt.Errorf("audit writer: encode: %w", err)
	}
	if err := w.bw.Flush(); err != nil {
		w.poisoned = err
		return fmt.Errorf("audit writer: flush: %w", err)
	}
	// fsync to durable storage. The audit is a security artifact — losing the
	// last few seconds on power-cut or OOM would let an attacker erase their
	// tracks. Throughput cost (~1ms per write) is acceptable at gateway RPS.
	if err := w.f.Sync(); err != nil {
		w.poisoned = err
		return fmt.Errorf("audit writer: sync: %w", err)
	}
	return nil
}

// Close flushes any remaining buffered data and closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.bw.Flush(); err != nil {
		_ = w.f.Close()
		return fmt.Errorf("audit writer: final flush: %w", err)
	}
	return w.f.Close()
}

// Path returns the filesystem path this writer is targeting.
func (w *Writer) Path() string {
	return w.path
}
