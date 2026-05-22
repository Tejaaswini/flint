package main

import (
	"fmt"
	"testing"
	"time"

	"flint/pkg/api"
)

// TestState_AddDecision_RingBufferCap verifies that the ring buffer caps at
// ringBufferCap entries and the oldest entries are overwritten.
func TestState_AddDecision_RingBufferCap(t *testing.T) {
	state := NewState("", "", "", "", "")

	// Fill beyond capacity.
	total := ringBufferCap + 50
	for i := 0; i < total; i++ {
		row := api.DecisionRow{
			TS:        fmt.Sprintf("2026-05-20T00:%02d:%02d.000Z", i/60, i%60),
			SessionID: "sess-1",
			AgentID:   "agent-1",
			Direction: "request",
			Allowed:   true,
		}
		state.AddDecision(row)
	}

	recent := state.RecentDecisions(0)
	if len(recent) != ringBufferCap {
		t.Errorf("expected %d entries, got %d", ringBufferCap, len(recent))
	}

	// The first entry should be the 51st (index 50 in 0-based) — the oldest
	// entry surviving after ringBufferCap + 50 inserts.
	first := recent[0]
	expected := fmt.Sprintf("2026-05-20T00:%02d:%02d.000Z", 50/60, 50%60)
	if first.TS != expected {
		t.Errorf("expected first TS %q, got %q", expected, first.TS)
	}
}

// TestState_AddDecision_AgentStats verifies per-agent tracking.
func TestState_AddDecision_AgentStats(t *testing.T) {
	state := NewState("", "", "", "", "")

	now := time.Now().UTC()
	tsAt := func(d time.Duration) string {
		return now.Add(d).Format(time.RFC3339Nano)
	}

	state.AddDecision(api.DecisionRow{
		TS:        tsAt(-2 * time.Minute),
		AgentID:   "alice",
		SessionID: "sess-alice",
		Allowed:   false,
	})
	state.AddDecision(api.DecisionRow{
		TS:        tsAt(-1 * time.Minute),
		AgentID:   "alice",
		SessionID: "sess-alice",
		Allowed:   true,
	})
	state.AddDecision(api.DecisionRow{
		TS:        tsAt(0),
		AgentID:   "alice",
		SessionID: "sess-alice",
		Allowed:   false,
	})

	state.mu.RLock()
	stats := state.perAgentStats["alice"]
	state.mu.RUnlock()

	if stats == nil {
		t.Fatal("expected stats for alice")
	}
	// Two denials in the last 24h.
	if stats.DeniedLast24h != 2 {
		t.Errorf("expected 2 denied in last 24h, got %d", stats.DeniedLast24h)
	}
}

// TestState_DecisionsSince verifies filtering by timestamp cursor.
func TestState_DecisionsSince(t *testing.T) {
	state := NewState("", "", "", "", "")

	rows := []api.DecisionRow{
		{TS: "2026-05-20T10:00:00Z", AgentID: "a", SessionID: "s1", Direction: "request"},
		{TS: "2026-05-20T11:00:00Z", AgentID: "a", SessionID: "s1", Direction: "request"},
		{TS: "2026-05-20T12:00:00Z", AgentID: "a", SessionID: "s1", Direction: "request"},
		{TS: "2026-05-20T13:00:00Z", AgentID: "a", SessionID: "s1", Direction: "request"},
	}
	for _, r := range rows {
		state.AddDecision(r)
	}

	// Since 11:00 should return 11:00, 12:00, 13:00.
	items, hasMore := state.DecisionsSince("2026-05-20T11:00:00Z", 10)
	if len(items) != 3 {
		t.Errorf("expected 3 items since 11:00, got %d", len(items))
	}
	if hasMore {
		t.Error("expected hasMore=false")
	}
}

// TestState_SessionTracking verifies session aggregation.
func TestState_SessionTracking(t *testing.T) {
	state := NewState("", "", "", "", "")

	for i := 0; i < 5; i++ {
		state.AddDecision(api.DecisionRow{
			TS:        fmt.Sprintf("2026-05-20T12:00:0%dZ", i),
			AgentID:   "bot",
			SessionID: "sess-x",
			Allowed:   i != 2, // row index 2 is denied
		})
	}

	sess, ok := state.GetSession("sess-x")
	if !ok {
		t.Fatal("expected session sess-x")
	}
	if sess.EventCount != 5 {
		t.Errorf("expected 5 events, got %d", sess.EventCount)
	}
	if sess.DeniedCount != 1 {
		t.Errorf("expected 1 denial, got %d", sess.DeniedCount)
	}
}
