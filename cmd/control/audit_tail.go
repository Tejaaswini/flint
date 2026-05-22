package main

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"flint/pkg/api"
)

// AuditTail watches an audit JSONL file and feeds parsed DecisionRows to a
// State and Bus. It handles file truncation/rotation by resetting the offset.
type AuditTail struct {
	path  string
	state *State
	bus   *Bus

	mu         sync.Mutex
	lastOffset int64
}

// NewAuditTail creates a new AuditTail but does not start it.
func NewAuditTail(path string, state *State, bus *Bus) *AuditTail {
	return &AuditTail{
		path:  path,
		state: state,
		bus:   bus,
	}
}

// Bootstrap reads the entire audit file from byte 0, seeding the ring buffer
// with up to ringBufferCap recent decisions. Call this before Start.
func (t *AuditTail) Bootstrap() {
	f, err := os.Open(t.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("audit bootstrap: open failed", "path", t.path, "err", err)
		}
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var rows []api.DecisionRow
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row api.DecisionRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			slog.Debug("audit bootstrap: skip malformed line", "err", err)
			continue
		}
		rows = append(rows, row)
	}

	// Seed state; only add up to ringBufferCap most recent.
	start := 0
	if len(rows) > ringBufferCap {
		start = len(rows) - ringBufferCap
	}
	for _, row := range rows[start:] {
		t.state.AddDecision(row)
	}

	// Advance the offset to end-of-file so tail reads only new lines.
	size, _ := f.Seek(0, 2) // seek to end
	t.mu.Lock()
	t.lastOffset = size
	t.mu.Unlock()

	slog.Info("audit bootstrap complete", "path", t.path, "rows_loaded", len(rows[start:]))
}

// Start begins watching the audit file. It blocks until ctx is cancelled or
// the watcher encounters an unrecoverable error. Runs in its own goroutine.
func (t *AuditTail) Start(stop <-chan struct{}) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("fsnotify unavailable, falling back to poll", "err", err)
		t.pollLoop(stop)
		return
	}
	defer watcher.Close()

	// If the file doesn't exist yet, watch the parent directory for creation.
	watchTarget := t.path
	if _, err := os.Stat(t.path); os.IsNotExist(err) {
		watchTarget = dirOf(t.path)
	}

	if err := watcher.Add(watchTarget); err != nil {
		slog.Warn("fsnotify watch failed, falling back to poll", "path", watchTarget, "err", err)
		t.pollLoop(stop)
		return
	}

	slog.Info("audit tail: watching", "path", t.path)

	for {
		select {
		case <-stop:
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				if strings.HasSuffix(event.Name, t.path) || event.Name == t.path {
					t.readNewLines()
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("fsnotify error", "err", err)
		}
	}
}

// pollLoop falls back to polling every 500ms when fsnotify is unavailable.
func (t *AuditTail) pollLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			t.readNewLines()
		}
	}
}

// readNewLines opens the file, seeks to lastOffset, reads any new complete
// lines, and updates lastOffset. Handles file truncation by resetting to 0.
func (t *AuditTail) readNewLines() {
	f, err := os.Open(t.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("audit tail: open failed", "err", err)
		}
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return
	}

	t.mu.Lock()
	offset := t.lastOffset
	t.mu.Unlock()

	// Detect truncation / rotation.
	if fi.Size() < offset {
		slog.Info("audit tail: file truncated/rotated, resetting offset", "path", t.path)
		offset = 0
	}

	if _, err := f.Seek(offset, 0); err != nil {
		slog.Warn("audit tail: seek failed", "err", err)
		return
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row api.DecisionRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			slog.Debug("audit tail: skip malformed line", "err", err)
			continue
		}

		// Schema gating: refuse to ingest rows from a newer gateway version
		// to avoid silent field misinterpretation during rolling upgrades.
		if row.SchemaVersion > api.AuditSchemaVersion {
			slog.Warn("audit tail: dropping row with newer schema_version",
				"saw", row.SchemaVersion,
				"support", api.AuditSchemaVersion,
			)
			continue
		}

		t.state.AddDecision(row)
		t.publishDecision(row)
	}

	// Update the offset to the current file position.
	newOffset, err := f.Seek(0, 1) // current position
	if err == nil {
		t.mu.Lock()
		t.lastOffset = newOffset
		t.mu.Unlock()
	}
}

// publishDecision serializes a decision row and publishes it to the bus.
func (t *AuditTail) publishDecision(row api.DecisionRow) {
	frame := map[string]any{
		"type": "decision",
		"data": row,
	}
	b, err := json.Marshal(frame)
	if err != nil {
		return
	}
	t.bus.Publish(b)

	// Also publish an agent_seen frame so the UI can update the agent list.
	if row.AgentID != "" {
		seen := map[string]any{
			"type": "agent_seen",
			"data": map[string]string{
				"agent_id": row.AgentID,
				"ts":       row.TS,
			},
		}
		b2, _ := json.Marshal(seen)
		t.bus.Publish(b2)
	}
}

// dirOf returns the directory component of a file path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
