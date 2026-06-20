package main

import (
	"encoding/json"
	"testing"
	"time"

	"flint/engine"
)

// newResponseBlockProxy builds a Proxy whose session is pre-set to the given
// disposition, with a nil audit writer (so handleToolsCallResponse does no file
// I/O) and the given enforce mode. RBAC is skipped on response events, so a nil
// policy holder is fine.
func newResponseBlockProxy(disposition, mode string) *Proxy {
	eng := engine.New("test-session", nil, nil)
	eng.Session.Disposition = disposition // disposition only ever escalates
	return NewProxy("test-agent", []string{"noop"}, eng, nil, nil, mode)
}

// originalResult is a benign upstream tool-call result. No rule fires on it, so
// the session disposition stays whatever we seeded it with.
const originalResult = `{"content":[{"type":"text","text":"sensitive upstream data"}]}`

// TestHandleToolsCallResponse_BlockReplacesPayload is the regression test for
// the response-side enforcement bug: handleToolsCallResponse took msg by value,
// so its in-place msg.Result replacement was lost and the caller forwarded the
// ORIGINAL upstream payload despite logging/auditing the response as "blocked".
//
// With msg passed by pointer, a blocked response must have msg.Result rewritten
// to the {"isError":true,...} blocked shape so the caller's enc.Encode(msg)
// forwards the replacement, not the original bytes.
func TestHandleToolsCallResponse_BlockReplacesPayload(t *testing.T) {
	cases := []struct {
		name         string
		disposition  string
		mode         string
		wantBlocked  bool
		wantReplaced bool // msg.Result should differ from originalResult
	}{
		{name: "terminate_block_replaces", disposition: "terminate", mode: "block", wantBlocked: true, wantReplaced: true},
		{name: "pause_block_replaces", disposition: "pause", mode: "block", wantBlocked: true, wantReplaced: true},
		{name: "terminate_observe_passthrough", disposition: "terminate", mode: "observe", wantBlocked: false, wantReplaced: false},
		{name: "allow_block_passthrough", disposition: "allow", mode: "block", wantBlocked: false, wantReplaced: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newResponseBlockProxy(tc.disposition, tc.mode)
			msg := message{
				JSONRPC: "2.0",
				ID:      json.RawMessage(`1`),
				Result:  json.RawMessage(originalResult),
			}

			blocked := p.handleToolsCallResponse(&msg, "1", "github.read_file", time.Now())

			if blocked != tc.wantBlocked {
				t.Errorf("blocked: got %v, want %v", blocked, tc.wantBlocked)
			}

			replaced := string(msg.Result) != originalResult
			if replaced != tc.wantReplaced {
				t.Fatalf("payload replaced: got %v, want %v (msg.Result=%s)", replaced, tc.wantReplaced, msg.Result)
			}

			if tc.wantReplaced {
				// The forwarded payload must be the blocked shape, not the
				// original upstream data.
				var got map[string]any
				if err := json.Unmarshal(msg.Result, &got); err != nil {
					t.Fatalf("blocked result is not valid JSON: %v", err)
				}
				if got["isError"] != true {
					t.Errorf("blocked result missing isError:true; got %v", got)
				}
			} else {
				// Pass-through: the agent must receive the exact upstream bytes.
				if string(msg.Result) != originalResult {
					t.Errorf("passthrough altered the payload: got %s", msg.Result)
				}
			}
		})
	}
}
