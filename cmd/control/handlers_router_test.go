package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flint/pkg/api"
)

// nopRouterClient is a RouterClient test double that succeeds silently.
type nopRouterClient struct{}

func (n *nopRouterClient) Reload(_ context.Context) error {
	return nil
}
func (n *nopRouterClient) Healthz(_ context.Context) (routerHealthz, error) {
	return routerHealthz{Status: "ok", RouterUp: true}, nil
}

// ---------------------------------------------------------------------------
// Policy round-trip tests
// ---------------------------------------------------------------------------

// minimalRouterPolicyYAML is a minimal valid router-policy.yaml for testing.
const minimalRouterPolicyYAML = `schema_version: 1
classifier:
  model: openai/gpt-4o-mini
  timeout_ms: 1500
  max_tokens: 150
routes:
  - name: cheap-classification
    if:
      task: [classification]
      complexity: [low]
    target: meta-llama/llama-3.2-3b-instruct:free
    reason: cheap model for simple labeling
default:
  target: openai/gpt-4o-mini
  reason: fallback
baseline:
  model: openai/gpt-4o
`

// TestRouterPolicyPut_RoundTrip verifies that PUT /api/v1/router/policy writes
// the YAML and returns {ok: true}.
func TestRouterPolicyPut_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "router-policy.yaml")

	state := NewState("", "", "", "", "")
	state.SetRouterPaths(policyPath, "", "")
	rc := &nopRouterClient{}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/router/policy",
		bytes.NewBufferString(minimalRouterPolicyYAML))
	req.Header.Set("Content-Type", "application/x-yaml")
	rec := httptest.NewRecorder()

	handleRouterPolicyPut(state, rc)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp api.RouterPolicyPutResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Errorf("expected ok=true, got errors: %v", resp.Errors)
	}

	// Verify the file was written.
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read policy file: %v", err)
	}
	if !bytes.Contains(data, []byte("openai/gpt-4o-mini")) {
		t.Errorf("policy file does not contain expected content:\n%s", data)
	}
}

// TestRouterPolicyPut_RejectsInvalidYAML verifies that an invalid policy
// body returns 400 with errors.
func TestRouterPolicyPut_RejectsInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "router-policy.yaml")

	state := NewState("", "", "", "", "")
	state.SetRouterPaths(policyPath, "", "")
	rc := &nopRouterClient{}

	// Missing required 'default' section.
	invalidYAML := `schema_version: 1
classifier:
  model: openai/gpt-4o-mini
  timeout_ms: 1500
  max_tokens: 150
routes: []
baseline:
  model: openai/gpt-4o
`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/router/policy",
		bytes.NewBufferString(invalidYAML))
	rec := httptest.NewRecorder()

	handleRouterPolicyPut(state, rc)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp api.RouterPolicyPutResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OK {
		t.Error("expected ok=false for invalid policy")
	}
	if len(resp.Errors) == 0 {
		t.Error("expected at least one error message")
	}
}

// TestRouterPolicyPut_DryRun verifies that ?dry_run=true does not write the file.
func TestRouterPolicyPut_DryRun(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "router-policy.yaml")

	state := NewState("", "", "", "", "")
	state.SetRouterPaths(policyPath, "", "")
	rc := &nopRouterClient{}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/router/policy?dry_run=true",
		bytes.NewBufferString(minimalRouterPolicyYAML))
	rec := httptest.NewRecorder()

	handleRouterPolicyPut(state, rc)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// File must NOT exist after dry run.
	if _, err := os.Stat(policyPath); !os.IsNotExist(err) {
		t.Error("expected policy file to NOT exist after dry run")
	}
}

// TestRouterPolicyGet_ReturnsJSON verifies that GET /api/v1/router/policy
// returns a valid JSON RouterPolicy when the file exists.
func TestRouterPolicyGet_ReturnsJSON(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "router-policy.yaml")

	if err := os.WriteFile(policyPath, []byte(minimalRouterPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	state := NewState("", "", "", "", "")
	state.SetRouterPaths(policyPath, "", "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/router/policy", nil)
	rec := httptest.NewRecorder()

	handleRouterPolicyGet(state)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var rp api.RouterPolicy
	if err := json.NewDecoder(rec.Body).Decode(&rp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rp.Classifier.Model != "openai/gpt-4o-mini" {
		t.Errorf("expected classifier model 'openai/gpt-4o-mini', got %q", rp.Classifier.Model)
	}
	if rp.Default.Target != "openai/gpt-4o-mini" {
		t.Errorf("expected default target 'openai/gpt-4o-mini', got %q", rp.Default.Target)
	}
}

// TestRouterPolicyRaw_ReturnsYAML verifies that GET /api/v1/router/policy/raw
// returns the raw YAML content.
func TestRouterPolicyRaw_ReturnsYAML(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "router-policy.yaml")

	if err := os.WriteFile(policyPath, []byte(minimalRouterPolicyYAML), 0644); err != nil {
		t.Fatal(err)
	}

	state := NewState("", "", "", "", "")
	state.SetRouterPaths(policyPath, "", "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/router/policy/raw", nil)
	rec := httptest.NewRecorder()

	handleRouterPolicyRaw(state)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected Content-Type text/plain, got %q", ct)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("schema_version: 1")) {
		t.Errorf("expected raw YAML in response body")
	}
}

// ---------------------------------------------------------------------------
// Router ring buffer tests
// ---------------------------------------------------------------------------

// TestState_RoutingRingBuffer verifies cap, ordering, and since-filter.
func TestState_RoutingRingBuffer(t *testing.T) {
	state := NewState("", "", "", "", "")

	// Fill beyond capacity.
	total := routerRingBufferCap + 50
	for i := 0; i < total; i++ {
		row := api.RoutingDecision{
			TS:          fmt.Sprintf("2026-05-20T00:%02d:%02d.000Z", i/60, i%60),
			RequestID:   fmt.Sprintf("req-%d", i),
			TargetModel: "openai/gpt-4o-mini",
		}
		state.AddRoutingDecision(row)
	}

	recent := state.RecentRoutingDecisions(0)
	if len(recent) != routerRingBufferCap {
		t.Errorf("expected %d entries, got %d", routerRingBufferCap, len(recent))
	}

	// The first surviving entry should be the 51st (index 50 in 0-based).
	first := recent[0]
	expectedReqID := fmt.Sprintf("req-%d", 50)
	if first.RequestID != expectedReqID {
		t.Errorf("expected first RequestID %q, got %q", expectedReqID, first.RequestID)
	}
}

// TestState_RoutingDecisionsSince verifies the since-filter cursor.
func TestState_RoutingDecisionsSince(t *testing.T) {
	state := NewState("", "", "", "", "")

	rows := []api.RoutingDecision{
		{TS: "2026-05-20T10:00:00Z", RequestID: "r1"},
		{TS: "2026-05-20T11:00:00Z", RequestID: "r2"},
		{TS: "2026-05-20T12:00:00Z", RequestID: "r3"},
		{TS: "2026-05-20T13:00:00Z", RequestID: "r4"},
	}
	for _, r := range rows {
		state.AddRoutingDecision(r)
	}

	// Since 11:00 should return 11:00, 12:00, 13:00.
	items, hasMore := state.RoutingDecisionsSince("2026-05-20T11:00:00Z", 10)
	if len(items) != 3 {
		t.Errorf("expected 3 items since 11:00, got %d", len(items))
	}
	if hasMore {
		t.Error("expected hasMore=false")
	}
}

// TestState_RoutingDecisionsSince_LimitPagination verifies the limit parameter
// and hasMore flag.
func TestState_RoutingDecisionsSince_LimitPagination(t *testing.T) {
	state := NewState("", "", "", "", "")

	for i := 0; i < 10; i++ {
		state.AddRoutingDecision(api.RoutingDecision{
			TS:        fmt.Sprintf("2026-05-20T10:0%d:00Z", i),
			RequestID: fmt.Sprintf("r%d", i),
		})
	}

	items, hasMore := state.RoutingDecisionsSince("", 5)
	if len(items) != 5 {
		t.Errorf("expected 5 items, got %d", len(items))
	}
	if !hasMore {
		t.Error("expected hasMore=true when limit < total")
	}
}

// ---------------------------------------------------------------------------
// Router stats tests
// ---------------------------------------------------------------------------

// TestRouterStats_BasicAggregation pushes 5 fixture rows with different
// tasks/models and verifies totals and per-task/per-model breakdowns.
func TestRouterStats_BasicAggregation(t *testing.T) {
	state := NewState("", "", "", "", "")

	now := time.Now().UTC()

	fixtures := []api.RoutingDecision{
		{
			TS:              now.Add(-10 * time.Second).Format(time.RFC3339Nano),
			RequestID:       "r1",
			TargetModel:     "openai/gpt-4o-mini",
			TotalCostUSD:    0.001,
			BaselineCostUSD: 0.005,
			SavingsUSD:      0.004,
			ForwardCostUSD:  0.0009,
			ForwardLatencyMs: 200,
			ClassifierLatencyMs: 50,
			TotalLatencyMs:  250,
			ClassifierOutput: api.ClassifierOutput{Task: "code", Complexity: "high"},
		},
		{
			TS:              now.Add(-9 * time.Second).Format(time.RFC3339Nano),
			RequestID:       "r2",
			TargetModel:     "meta-llama/llama-3.2-3b-instruct:free",
			TotalCostUSD:    0.0,
			BaselineCostUSD: 0.003,
			SavingsUSD:      0.003,
			ForwardCostUSD:  0.0,
			ForwardLatencyMs: 100,
			ClassifierLatencyMs: 40,
			TotalLatencyMs:  140,
			ClassifierOutput: api.ClassifierOutput{Task: "classification", Complexity: "low"},
		},
		{
			TS:              now.Add(-8 * time.Second).Format(time.RFC3339Nano),
			RequestID:       "r3",
			TargetModel:     "openai/gpt-4o-mini",
			TotalCostUSD:    0.002,
			BaselineCostUSD: 0.008,
			SavingsUSD:      0.006,
			ForwardCostUSD:  0.0018,
			ForwardLatencyMs: 300,
			ClassifierLatencyMs: 45,
			TotalLatencyMs:  345,
			ClassifierOutput: api.ClassifierOutput{Task: "code", Complexity: "high"},
		},
		{
			TS:              now.Add(-7 * time.Second).Format(time.RFC3339Nano),
			RequestID:       "r4",
			TargetModel:     "meta-llama/llama-3.2-3b-instruct:free",
			TotalCostUSD:    0.0,
			BaselineCostUSD: 0.002,
			SavingsUSD:      0.002,
			ForwardCostUSD:  0.0,
			ForwardLatencyMs: 90,
			ClassifierLatencyMs: 38,
			TotalLatencyMs:  128,
			ClassifierOutput: api.ClassifierOutput{Task: "rag", Complexity: "low"},
		},
		{
			TS:              now.Add(-6 * time.Second).Format(time.RFC3339Nano),
			RequestID:       "r5",
			TargetModel:     "openai/gpt-4o-mini",
			TotalCostUSD:    0.0015,
			BaselineCostUSD: 0.006,
			SavingsUSD:      0.0045,
			ForwardCostUSD:  0.0013,
			ForwardLatencyMs: 250,
			ClassifierLatencyMs: 42,
			TotalLatencyMs:  292,
			ClassifierOutput: api.ClassifierOutput{Task: "conversation", Complexity: "medium"},
		},
	}

	for _, row := range fixtures {
		state.AddRoutingDecision(row)
	}

	stats := state.ComputeRouterStats("session")

	// Total calls.
	if stats.TotalCalls != 5 {
		t.Errorf("expected TotalCalls=5, got %d", stats.TotalCalls)
	}

	// Total cost: 0.001 + 0 + 0.002 + 0 + 0.0015 = 0.0045
	wantTotal := 0.001 + 0.0 + 0.002 + 0.0 + 0.0015
	if abs(stats.TotalCostUSD-wantTotal) > 1e-9 {
		t.Errorf("expected TotalCostUSD=%v, got %v", wantTotal, stats.TotalCostUSD)
	}

	// Savings: 0.004 + 0.003 + 0.006 + 0.002 + 0.0045 = 0.0195
	wantSavings := 0.004 + 0.003 + 0.006 + 0.002 + 0.0045
	if abs(stats.SavingsUSD-wantSavings) > 1e-9 {
		t.Errorf("expected SavingsUSD=%v, got %v", wantSavings, stats.SavingsUSD)
	}

	// Per-task breakdown: code=2, classification=1, rag=1, conversation=1.
	if stats.PerTask["code"] != 2 {
		t.Errorf("expected PerTask[code]=2, got %d", stats.PerTask["code"])
	}
	if stats.PerTask["classification"] != 1 {
		t.Errorf("expected PerTask[classification]=1, got %d", stats.PerTask["classification"])
	}
	if stats.PerTask["rag"] != 1 {
		t.Errorf("expected PerTask[rag]=1, got %d", stats.PerTask["rag"])
	}
	if stats.PerTask["conversation"] != 1 {
		t.Errorf("expected PerTask[conversation]=1, got %d", stats.PerTask["conversation"])
	}

	// Per-model: gpt-4o-mini has 3, llama has 2.
	miniStat := stats.PerModel["openai/gpt-4o-mini"]
	if miniStat.Count != 3 {
		t.Errorf("expected PerModel[gpt-4o-mini].Count=3, got %d", miniStat.Count)
	}
	llamaStat := stats.PerModel["meta-llama/llama-3.2-3b-instruct:free"]
	if llamaStat.Count != 2 {
		t.Errorf("expected PerModel[llama].Count=2, got %d", llamaStat.Count)
	}

	// SavingsPct: savings / baseline * 100
	if stats.BaselineCostUSD > 0 {
		wantPct := stats.SavingsUSD / stats.BaselineCostUSD * 100
		if abs(stats.SavingsPct-wantPct) > 1e-9 {
			t.Errorf("expected SavingsPct=%v, got %v", wantPct, stats.SavingsPct)
		}
	}
}

// TestRouterStats_WindowFilter verifies that a time window filters out older rows.
func TestRouterStats_WindowFilter(t *testing.T) {
	state := NewState("", "", "", "", "")

	// Add one old row (way in the past) and one fresh row.
	state.AddRoutingDecision(api.RoutingDecision{
		TS:           "2020-01-01T00:00:00Z",
		RequestID:    "old",
		TotalCostUSD: 999.0,
		ClassifierOutput: api.ClassifierOutput{Task: "code"},
	})
	state.AddRoutingDecision(api.RoutingDecision{
		TS:           time.Now().UTC().Add(-5 * time.Second).Format(time.RFC3339Nano),
		RequestID:    "fresh",
		TotalCostUSD: 0.001,
		ClassifierOutput: api.ClassifierOutput{Task: "code"},
	})

	stats := state.ComputeRouterStats("1h")

	// Only the fresh row should be counted.
	if stats.TotalCalls != 1 {
		t.Errorf("expected 1 call in 1h window, got %d", stats.TotalCalls)
	}
	if abs(stats.TotalCostUSD-0.001) > 1e-9 {
		t.Errorf("expected TotalCostUSD=0.001, got %v", stats.TotalCostUSD)
	}
}

// abs returns the absolute value of a float64.
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
