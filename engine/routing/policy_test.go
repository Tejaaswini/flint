package routing

import (
	"strings"
	"testing"
)

const minimalValidYAML = `
schema_version: 1

classifier:
  model: openai/gpt-4o-mini
  timeout_ms: 1500
  max_tokens: 150

baseline:
  model: openai/gpt-4o

routes: []

default:
  target: openai/gpt-4o-mini
  fallback: [anthropic/claude-haiku-4.5]
`

// TestLoadPolicy_Minimal checks that a minimal valid YAML compiles without errors.
func TestLoadPolicy_Minimal(t *testing.T) {
	p, err := LoadPolicyBytes([]byte(minimalValidYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
	if p.Classifier.Model != "openai/gpt-4o-mini" {
		t.Errorf("classifier.model = %q, want openai/gpt-4o-mini", p.Classifier.Model)
	}
	if p.Default.Target != "openai/gpt-4o-mini" {
		t.Errorf("default.target = %q, want openai/gpt-4o-mini", p.Default.Target)
	}
	if p.Baseline.Model != "openai/gpt-4o" {
		t.Errorf("baseline.model = %q, want openai/gpt-4o", p.Baseline.Model)
	}
}

// TestLoadPolicy_AllConditionKinds checks that a YAML using every match
// condition key compiles correctly.
func TestLoadPolicy_AllConditionKinds(t *testing.T) {
	yaml := `
schema_version: 1

classifier:
  model: openai/gpt-4o-mini
  timeout_ms: 1500
  max_tokens: 150

baseline:
  model: openai/gpt-4o

routes:
  - name: "All conditions"
    if:
      task: code
      complexity: [medium, high]
      capabilities_include: [vision, reasoning]
      messages_min_length: 100
      messages_total_tokens_gt: 50000
    target: anthropic/claude-sonnet-4.6
    fallback: [openai/gpt-4o]

default:
  target: openai/gpt-4o-mini
`
	p, err := LoadPolicyBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(p.Routes))
	}
	r := p.Routes[0]
	if len(r.If.Task) != 1 || r.If.Task[0] != "code" {
		t.Errorf("task = %v, want [code]", r.If.Task)
	}
	if len(r.If.Complexity) != 2 {
		t.Errorf("complexity = %v, want [medium high]", r.If.Complexity)
	}
	if len(r.If.CapabilitiesInclude) != 2 {
		t.Errorf("capabilities_include = %v, want [vision reasoning]", r.If.CapabilitiesInclude)
	}
	if r.If.MessagesMinLength != 100 {
		t.Errorf("messages_min_length = %d, want 100", r.If.MessagesMinLength)
	}
	if r.If.MessagesTotalTokGT != 50000 {
		t.Errorf("messages_total_tokens_gt = %d, want 50000", r.If.MessagesTotalTokGT)
	}
}

// TestLoadPolicy_UnknownIfKey checks that an unknown key inside if: is a load-time error.
func TestLoadPolicy_UnknownIfKey(t *testing.T) {
	yaml := `
schema_version: 1
classifier:
  model: openai/gpt-4o-mini
baseline:
  model: openai/gpt-4o
routes:
  - name: "Bad rule"
    if:
      unknown_key: something
    target: openai/gpt-4o-mini
default:
  target: openai/gpt-4o-mini
`
	_, err := LoadPolicyBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown if key, got nil")
	}
	if !strings.Contains(err.Error(), "unknown if-key") {
		t.Errorf("error %q does not mention 'unknown if-key'", err.Error())
	}
}

// TestLoadPolicy_InvalidTaskValue checks that an invalid task value is rejected.
func TestLoadPolicy_InvalidTaskValue(t *testing.T) {
	yaml := `
schema_version: 1
classifier:
  model: openai/gpt-4o-mini
baseline:
  model: openai/gpt-4o
routes:
  - name: "Bad task"
    if:
      task: nonsense
    target: openai/gpt-4o-mini
default:
  target: openai/gpt-4o-mini
`
	_, err := LoadPolicyBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid task value, got nil")
	}
	if !strings.Contains(err.Error(), "invalid task value") {
		t.Errorf("error %q does not mention 'invalid task value'", err.Error())
	}
}

// TestLoadPolicy_MissingDefault checks that a policy without default.target is rejected.
func TestLoadPolicy_MissingDefault(t *testing.T) {
	yaml := `
schema_version: 1
classifier:
  model: openai/gpt-4o-mini
baseline:
  model: openai/gpt-4o
routes: []
default:
  target: ""
`
	_, err := LoadPolicyBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing default target, got nil")
	}
	if !strings.Contains(err.Error(), "default.target") {
		t.Errorf("error %q does not mention 'default.target'", err.Error())
	}
}

// TestLoadPolicy_DuplicateRuleNames_Warns checks that duplicate rule names
// compile but produce a warning (not a hard error).
func TestLoadPolicy_DuplicateRuleNames_Warns(t *testing.T) {
	yaml := `
schema_version: 1
classifier:
  model: openai/gpt-4o-mini
baseline:
  model: openai/gpt-4o
routes:
  - name: "Dup rule"
    if:
      task: code
    target: openai/gpt-4o-mini
  - name: "Dup rule"
    if:
      task: rag
    target: anthropic/claude-haiku-4.5
default:
  target: openai/gpt-4o-mini
`
	p, err := LoadPolicyBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("expected no error for duplicate names (warn only), got: %v", err)
	}
	if len(p.Warnings) == 0 {
		t.Error("expected at least one warning for duplicate rule name")
	}
	found := false
	for _, w := range p.Warnings {
		if strings.Contains(w, "Dup rule") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings %v do not mention the duplicate rule name", p.Warnings)
	}
}

// TestLoadPolicy_SchemaVersionMismatch checks that schema_version != 1 is rejected.
func TestLoadPolicy_SchemaVersionMismatch(t *testing.T) {
	yaml := `
schema_version: 2
classifier:
  model: openai/gpt-4o-mini
baseline:
  model: openai/gpt-4o
routes: []
default:
  target: openai/gpt-4o-mini
`
	_, err := LoadPolicyBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for schema_version mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error %q does not mention 'schema_version'", err.Error())
	}
}
