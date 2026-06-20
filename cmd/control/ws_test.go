package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"flint/pkg/api"
)

// TestWebSocket_ReceivesBacklog connects to the WS endpoint and verifies that
// it receives a hello frame followed by backlog decision frames.
func TestWebSocket_ReceivesBacklog(t *testing.T) {
	state := NewState("", "", "", "", "")
	bus := NewBus()

	// Seed a few decisions into state.
	for i := 0; i < 3; i++ {
		state.AddDecision(api.DecisionRow{
			TS:        "2026-05-20T10:00:00Z",
			AgentID:   "agent-1",
			SessionID: "sess-1",
			Direction: "request",
			Allowed:   true,
		})
	}

	// Create a test HTTP server.
	srv := httptest.NewServer(handleWS(state, bus))
	defer srv.Close()

	// Connect via WebSocket.
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/stream"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read frames: expect 1 hello + 3 decision frames.
	frameTypes := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		var frame struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(msg, &frame); err != nil {
			t.Fatalf("unmarshal frame %d: %v", i, err)
		}
		frameTypes = append(frameTypes, frame.Type)
	}

	if frameTypes[0] != "hello" {
		t.Errorf("expected first frame type 'hello', got %q", frameTypes[0])
	}
	for _, ft := range frameTypes[1:] {
		if ft != "decision" {
			t.Errorf("expected backlog frame type 'decision', got %q", ft)
		}
	}

	// Verify the hello frame has the correct schema version and backlog count.
	conn2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer conn2.Close()
	conn2.SetReadDeadline(time.Now().Add(5 * time.Second))

	_, msg, err := conn2.ReadMessage()
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	var helloEnvelope struct {
		Type string      `json:"type"`
		Data api.WSHello `json:"data"`
	}
	if err := json.Unmarshal(msg, &helloEnvelope); err != nil {
		t.Fatalf("unmarshal hello: %v", err)
	}
	if helloEnvelope.Data.SchemaVersion != api.AuditSchemaVersion {
		t.Errorf("expected schema_version %d, got %d", api.AuditSchemaVersion, helloEnvelope.Data.SchemaVersion)
	}
	if helloEnvelope.Data.BacklogCount != 3 {
		t.Errorf("expected backlog_count 3, got %d", helloEnvelope.Data.BacklogCount)
	}
}

// TestWebSocket_LiveFrame verifies that a live publish reaches a connected client.
func TestWebSocket_LiveFrame(t *testing.T) {
	state := NewState("", "", "", "", "")
	bus := NewBus()

	srv := httptest.NewServer(handleWS(state, bus))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/stream"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Consume the hello (no backlog).
	_, _, err = conn.ReadMessage()
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}

	// Publish a live frame.
	frame := map[string]any{
		"type": "decision",
		"data": api.DecisionRow{TS: "2026-05-20T13:00:00Z", AgentID: "bot"},
	}
	b, _ := json.Marshal(frame)
	bus.Publish(b)

	// Read the live frame.
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read live frame: %v", err)
	}
	var f struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(msg, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.Type != "decision" {
		t.Errorf("expected 'decision' frame, got %q", f.Type)
	}
}
