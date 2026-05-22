package routing

import (
	"sync"
	"testing"
)

// testPolicy builds a standard Policy for evaluator tests.
func testPolicy() *Policy {
	return &Policy{
		SchemaVersion: 1,
		Classifier: ClassifierConfig{
			Model:     "openai/gpt-4o-mini",
			TimeoutMs: 1500,
			MaxTokens: 150,
		},
		Routes: []Rule{
			{
				Name: "Vision needed",
				If: MatchCondition{
					CapabilitiesInclude: []string{"vision"},
				},
				Target:   "google/gemini-flash-latest",
				Fallback: []string{"openai/gpt-4o"},
			},
			{
				Name: "High-complexity code",
				If: MatchCondition{
					Task:       []string{"code"},
					Complexity: []string{"medium", "high"},
				},
				Target:   "anthropic/claude-sonnet-4.6",
				Fallback: []string{"anthropic/claude-haiku-4.5"},
			},
			{
				Name: "Code or summarization",
				If: MatchCondition{
					Task: []string{"code", "summarization"},
				},
				Target:   "anthropic/claude-haiku-4.5",
				Fallback: []string{"openai/gpt-4o-mini"},
			},
			{
				Name: "Long context",
				If: MatchCondition{
					MessagesTotalTokGT: 50000,
				},
				Target:   "anthropic/claude-sonnet-4.6",
				Fallback: []string{"anthropic/claude-haiku-4.5"},
			},
		},
		Default: Rule{
			Name:     "<default>",
			Target:   "openai/gpt-4o-mini",
			Fallback: []string{"anthropic/claude-haiku-4.5"},
		},
		Baseline: Baseline{Model: "openai/gpt-4o"},
	}
}

// TestEvaluate_FirstMatchWins verifies that when two rules could match,
// the earlier rule wins.
func TestEvaluate_FirstMatchWins(t *testing.T) {
	// "code" + "medium" matches both "High-complexity code" (index 1) AND
	// "Code or summarization" (index 2). The first one wins.
	p := testPolicy()
	c := ClassifierOutput{Task: "code", Complexity: "medium"}
	ctx := MessagesContext{TotalChars: 200, EstTokens: 50}

	dec := Evaluate(p, c, ctx)
	if dec.MatchedRuleName != "High-complexity code" {
		t.Errorf("matched rule = %q, want 'High-complexity code'", dec.MatchedRuleName)
	}
	if dec.TargetModel != "anthropic/claude-sonnet-4.6" {
		t.Errorf("target = %q, want anthropic/claude-sonnet-4.6", dec.TargetModel)
	}
}

// TestEvaluate_FallsBackToDefault verifies that when no named rule matches,
// the default rule is returned.
func TestEvaluate_FallsBackToDefault(t *testing.T) {
	p := testPolicy()
	// "other" with "low" — no named rule covers this
	c := ClassifierOutput{Task: "other", Complexity: "low"}
	ctx := MessagesContext{TotalChars: 10, EstTokens: 2}

	dec := Evaluate(p, c, ctx)
	if dec.MatchedRuleName != "<default>" {
		t.Errorf("matched rule = %q, want '<default>'", dec.MatchedRuleName)
	}
	if dec.TargetModel != "openai/gpt-4o-mini" {
		t.Errorf("target = %q, want openai/gpt-4o-mini", dec.TargetModel)
	}
}

// TestEvaluate_CapabilitiesInclude_SubsetMatch verifies that the evaluator
// matches when the classifier output has MORE capabilities than required.
func TestEvaluate_CapabilitiesInclude_SubsetMatch(t *testing.T) {
	p := testPolicy()
	// Rule requires "vision"; classifier has [vision, reasoning] — should match
	c := ClassifierOutput{
		Task:         "vision",
		Complexity:   "medium",
		Capabilities: []string{"vision", "reasoning"},
	}
	ctx := MessagesContext{TotalChars: 100, EstTokens: 25}

	dec := Evaluate(p, c, ctx)
	if dec.MatchedRuleName != "Vision needed" {
		t.Errorf("matched rule = %q, want 'Vision needed'", dec.MatchedRuleName)
	}
}

// TestEvaluate_CapabilitiesInclude_MissingFails verifies that if a required
// capability is absent, the rule does not match.
func TestEvaluate_CapabilitiesInclude_MissingFails(t *testing.T) {
	p := testPolicy()
	// Vision rule requires "vision"; classifier has only [reasoning] — no match
	c := ClassifierOutput{
		Task:         "conversation",
		Complexity:   "low",
		Capabilities: []string{"reasoning"},
	}
	ctx := MessagesContext{TotalChars: 100, EstTokens: 25}

	dec := Evaluate(p, c, ctx)
	// The vision rule should NOT match; falls through to default
	if dec.MatchedRuleName == "Vision needed" {
		t.Errorf("vision rule incorrectly matched when 'vision' capability was absent")
	}
}

// TestEvaluate_MessagesTotalTokens_OnlyAboveThreshold verifies the token
// threshold condition: below threshold → no match; above → match.
func TestEvaluate_MessagesTotalTokens_OnlyAboveThreshold(t *testing.T) {
	p := testPolicy()
	c := ClassifierOutput{Task: "rag", Complexity: "medium"}

	// Below threshold (50000) → long-context rule should NOT match
	ctxBelow := MessagesContext{TotalChars: 100000, EstTokens: 25000}
	decBelow := Evaluate(p, c, ctxBelow)
	if decBelow.MatchedRuleName == "Long context" {
		t.Errorf("long-context rule matched when EstTokens (%d) <= threshold (50000)", ctxBelow.EstTokens)
	}

	// Above threshold → long-context rule SHOULD match
	ctxAbove := MessagesContext{TotalChars: 240000, EstTokens: 60000}
	decAbove := Evaluate(p, c, ctxAbove)
	if decAbove.MatchedRuleName != "Long context" {
		t.Errorf("long-context rule did not match when EstTokens (%d) > threshold (50000); got %q", ctxAbove.EstTokens, decAbove.MatchedRuleName)
	}
}

// TestEvaluate_TaskListMatch verifies that a rule with task: [code, summarization]
// matches both task values.
func TestEvaluate_TaskListMatch(t *testing.T) {
	p := testPolicy()

	for _, task := range []string{"summarization"} {
		// Use low complexity so we skip "High-complexity code" and hit "Code or summarization"
		c := ClassifierOutput{Task: task, Complexity: "low"}
		ctx := MessagesContext{TotalChars: 100, EstTokens: 25}
		dec := Evaluate(p, c, ctx)
		if dec.MatchedRuleName != "Code or summarization" {
			t.Errorf("task=%q: matched rule = %q, want 'Code or summarization'", task, dec.MatchedRuleName)
		}
	}

	// code with low complexity should also hit "Code or summarization" (not the high-complexity code rule)
	cCodeLow := ClassifierOutput{Task: "code", Complexity: "low"}
	ctx := MessagesContext{TotalChars: 100, EstTokens: 25}
	dec := Evaluate(p, cCodeLow, ctx)
	if dec.MatchedRuleName != "Code or summarization" {
		t.Errorf("code+low: matched rule = %q, want 'Code or summarization'", dec.MatchedRuleName)
	}
}

// TestEvaluate_NilPolicy_ReturnsZero verifies that a nil policy does not panic
// and returns a zero RouteDecision.
func TestEvaluate_NilPolicy_ReturnsZero(t *testing.T) {
	c := ClassifierOutput{Task: "code", Complexity: "high"}
	ctx := MessagesContext{TotalChars: 200, EstTokens: 50}

	dec := Evaluate(nil, c, ctx)
	if dec.MatchedRuleName != "" || dec.TargetModel != "" {
		t.Errorf("expected zero RouteDecision for nil policy, got %+v", dec)
	}
}

// TestPolicyHolder_AtomicSwap verifies that concurrent Get and Set calls are
// race-detector clean.
func TestPolicyHolder_AtomicSwap(t *testing.T) {
	p1 := testPolicy()
	p2 := testPolicy()
	p2.Default.Target = "anthropic/claude-haiku-4.5"

	holder := NewPolicyHolder(p1)

	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				got := holder.Get()
				if got == nil {
					t.Errorf("Get returned nil")
				}
			} else {
				if n%4 == 1 {
					holder.Set(p2)
				} else {
					holder.Set(p1)
				}
			}
		}(i)
	}

	wg.Wait()

	// After all goroutines, policy must be non-nil
	final := holder.Get()
	if final == nil {
		t.Error("final policy is nil")
	}
}
