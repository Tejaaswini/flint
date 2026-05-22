package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"flint/pkg/api"
)

// AuditWriter is a concurrency-safe append-only JSONL writer for router audit rows.
// A single mutex serializes writes so the file always contains complete lines.
//
// Every row has SchemaVersion stamped to api.RouterAuditSchemaVersion and is
// flushed + fsynced to durable storage after each write — the audit is a
// cost/decision artifact and must survive process crashes.
type AuditWriter struct {
	f    *os.File
	bw   *bufio.Writer
	enc  *json.Encoder
	mu   sync.Mutex
	path string

	// poisoned is set once any write fails. Further writes are refused so
	// a partial line from an encoder mid-error cannot corrupt subsequent rows.
	poisoned error
}

// NewAuditWriter opens (or creates) the file at path in append mode and
// returns an AuditWriter ready for use. The caller must call Close when done.
func NewAuditWriter(path string) (*AuditWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("router audit writer: open %s: %w", path, err)
	}
	bw := bufio.NewWriter(f)
	return &AuditWriter{
		f:    f,
		bw:   bw,
		enc:  json.NewEncoder(bw),
		path: path,
	}, nil
}

// Write marshals a RoutingDecision as a single JSON line and syncs to disk.
// It stamps SchemaVersion before marshaling so callers do not need to remember.
// Write is safe to call concurrently from multiple goroutines.
func (w *AuditWriter) Write(row api.RoutingDecision) error {
	row.SchemaVersion = api.RouterAuditSchemaVersion
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned != nil {
		return fmt.Errorf("router audit writer: refusing write (poisoned): %w", w.poisoned)
	}
	if err := w.enc.Encode(row); err != nil {
		w.poisoned = err
		return fmt.Errorf("router audit writer: encode: %w", err)
	}
	if err := w.bw.Flush(); err != nil {
		w.poisoned = err
		return fmt.Errorf("router audit writer: flush: %w", err)
	}
	// fsync to durable storage. The audit is a cost/decision artifact — losing
	// the last few rows on power-cut would corrupt the savings calculation.
	// Throughput cost (~1ms) is acceptable at router RPS.
	if err := w.f.Sync(); err != nil {
		w.poisoned = err
		return fmt.Errorf("router audit writer: sync: %w", err)
	}
	return nil
}

// Close flushes any remaining buffered data and closes the underlying file.
func (w *AuditWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.bw.Flush(); err != nil {
		_ = w.f.Close()
		return fmt.Errorf("router audit writer: final flush: %w", err)
	}
	return w.f.Close()
}

// Path returns the filesystem path this writer is targeting.
func (w *AuditWriter) Path() string {
	return w.path
}
