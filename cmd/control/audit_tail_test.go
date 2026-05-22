package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flint/pkg/api"
)

// TestAuditTail_ParsesAppendedLines writes rows to a temp file, bootstraps
// the tail, then appends more rows and verifies they appear in state.
func TestAuditTail_ParsesAppendedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-audit.jsonl")

	// Write initial rows.
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	row1 := api.DecisionRow{
		TS:        "2026-05-20T10:00:00Z",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		Direction: "request",
		Allowed:   true,
	}
	writeJSONLRow(t, f, row1)
	f.Close()

	state := NewState("", "", "", path, "")
	bus := NewBus()
	tail := NewAuditTail(path, state, bus)

	// Bootstrap reads the initial row.
	tail.Bootstrap()

	decisions := state.RecentDecisions(0)
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision after bootstrap, got %d", len(decisions))
	}
	if decisions[0].AgentID != "agent-a" {
		t.Errorf("expected agent-a, got %q", decisions[0].AgentID)
	}

	// Now start the tail and append a new row.
	stop := make(chan struct{})
	defer close(stop)
	go tail.Start(stop)

	// Give the fsnotify watcher a moment to register before we append.
	// On macOS kqueue, events fired before registration are not delivered.
	time.Sleep(200 * time.Millisecond)

	// Append a second row.
	f2, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("append open: %v", err)
	}
	row2 := api.DecisionRow{
		TS:        "2026-05-20T10:01:00Z",
		AgentID:   "agent-b",
		SessionID: "sess-2",
		Direction: "request",
		Allowed:   false,
	}
	writeJSONLRow(t, f2, row2)
	f2.Close()

	// Poll for the second decision to appear (up to 3s).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		decisions = state.RecentDecisions(0)
		if len(decisions) >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if len(decisions) < 2 {
		t.Fatalf("expected 2 decisions after tail, got %d", len(decisions))
	}
	found := false
	for _, d := range decisions {
		if d.AgentID == "agent-b" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected agent-b in decisions")
	}
}

// TestAuditTail_SkipsMalformedLines verifies that parse errors don't crash the tail.
func TestAuditTail_SkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "malformed.jsonl")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.WriteString("this is not json\n")
	row := api.DecisionRow{
		TS:        "2026-05-20T10:00:00Z",
		AgentID:   "agent-ok",
		SessionID: "sess-ok",
		Direction: "request",
		Allowed:   true,
	}
	writeJSONLRow(t, f, row)
	f.Close()

	state := NewState("", "", "", path, "")
	bus := NewBus()
	tail := NewAuditTail(path, state, bus)
	tail.Bootstrap()

	decisions := state.RecentDecisions(0)
	if len(decisions) != 1 {
		t.Fatalf("expected 1 good decision, got %d", len(decisions))
	}
	if decisions[0].AgentID != "agent-ok" {
		t.Errorf("expected agent-ok, got %q", decisions[0].AgentID)
	}
}

func writeJSONLRow(t *testing.T, f *os.File, row api.DecisionRow) {
	t.Helper()
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f.Write(b)
	f.WriteString("\n")
}
