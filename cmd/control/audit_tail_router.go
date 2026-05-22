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

// RouterAuditTail watches the router's audit JSONL file and feeds parsed
// RoutingDecision rows to a State and Bus. It mirrors AuditTail's logic but
// is a separate struct so the two files watch independently (each has its own
// fsnotify watcher and 500ms poll fallback). Schema version gating is enforced:
// rows with schema_version > api.RouterAuditSchemaVersion are skipped with a warning.
type RouterAuditTail struct {
	path  string
	state *State
	bus   *Bus

	mu         sync.Mutex
	lastOffset int64
}

// NewRouterAuditTail creates a new RouterAuditTail but does not start it.
func NewRouterAuditTail(path string, state *State, bus *Bus) *RouterAuditTail {
	return &RouterAuditTail{
		path:  path,
		state: state,
		bus:   bus,
	}
}

// Bootstrap reads the entire router audit file from byte 0, seeding the
// routing ring buffer. Call this before Start.
func (t *RouterAuditTail) Bootstrap() {
	f, err := os.Open(t.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("router audit bootstrap: open failed", "path", t.path, "err", err)
		}
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var rows []api.RoutingDecision
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row api.RoutingDecision
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			slog.Debug("router audit bootstrap: skip malformed line", "err", err)
			continue
		}
		if row.SchemaVersion > api.RouterAuditSchemaVersion {
			slog.Warn("router audit bootstrap: dropping row with newer schema_version",
				"saw", row.SchemaVersion,
				"support", api.RouterAuditSchemaVersion,
			)
			continue
		}
		rows = append(rows, row)
	}

	// Seed state; only add up to routerRingBufferCap most recent.
	start := 0
	if len(rows) > routerRingBufferCap {
		start = len(rows) - routerRingBufferCap
	}
	for _, row := range rows[start:] {
		t.state.AddRoutingDecision(row)
	}

	// Advance the offset to end-of-file so tail reads only new lines.
	size, _ := f.Seek(0, 2)
	t.mu.Lock()
	t.lastOffset = size
	t.mu.Unlock()

	slog.Info("router audit bootstrap complete", "path", t.path, "rows_loaded", len(rows[start:]))
}

// Start begins watching the router audit file. It blocks until stop is closed.
// Runs in its own goroutine.
func (t *RouterAuditTail) Start(stop <-chan struct{}) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("router audit fsnotify unavailable, falling back to poll", "err", err)
		t.pollLoop(stop)
		return
	}
	defer watcher.Close()

	watchTarget := t.path
	if _, err := os.Stat(t.path); os.IsNotExist(err) {
		watchTarget = dirOf(t.path)
	}

	if err := watcher.Add(watchTarget); err != nil {
		slog.Warn("router audit fsnotify watch failed, falling back to poll", "path", watchTarget, "err", err)
		t.pollLoop(stop)
		return
	}

	slog.Info("router audit tail: watching", "path", t.path)

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
			slog.Warn("router audit fsnotify error", "err", err)
		}
	}
}

// pollLoop falls back to polling every 500ms when fsnotify is unavailable.
func (t *RouterAuditTail) pollLoop(stop <-chan struct{}) {
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
func (t *RouterAuditTail) readNewLines() {
	f, err := os.Open(t.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("router audit tail: open failed", "err", err)
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
		slog.Info("router audit tail: file truncated/rotated, resetting offset", "path", t.path)
		offset = 0
	}

	if _, err := f.Seek(offset, 0); err != nil {
		slog.Warn("router audit tail: seek failed", "err", err)
		return
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row api.RoutingDecision
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			slog.Debug("router audit tail: skip malformed line", "err", err)
			continue
		}

		// Schema gating: refuse to ingest rows from a newer router version
		// to avoid silent field misinterpretation during rolling upgrades.
		if row.SchemaVersion > api.RouterAuditSchemaVersion {
			slog.Warn("router audit tail: dropping row with newer schema_version",
				"saw", row.SchemaVersion,
				"support", api.RouterAuditSchemaVersion,
			)
			continue
		}

		t.state.AddRoutingDecision(row)
		t.publishDecision(row)
	}

	// Update the offset to the current file position.
	newOffset, err := f.Seek(0, 1)
	if err == nil {
		t.mu.Lock()
		t.lastOffset = newOffset
		t.mu.Unlock()
	}
}

// publishDecision serializes a routing decision and publishes it to the router bus.
func (t *RouterAuditTail) publishDecision(row api.RoutingDecision) {
	frame := map[string]any{
		"type": "routing_decision",
		"data": row,
	}
	b, err := json.Marshal(frame)
	if err != nil {
		return
	}
	t.bus.Publish(b)
}
