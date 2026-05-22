// Package routing provides the policy types, loader, and evaluator for the
// Flint task-aware LLM router. It mirrors the structure of engine/authz but is
// completely independent — no shared types with authz or any HTTP layer.
package routing

import "sync/atomic"

// SchemaVersion is the YAML schema version this package expects.
const SchemaVersion = 1

// MatchCondition describes all filter constraints on a routing rule's if-block.
// All non-zero/non-empty fields must match (logical AND). A zero value matches
// everything (used for the default rule).
type MatchCondition struct {
	// Task is the classifier task label. Empty means "match any task".
	Task []string

	// Complexity is the classifier complexity. Empty means "match any complexity".
	Complexity []string

	// CapabilitiesInclude is a subset-check: every listed capability must appear
	// in the classifier output's capabilities list (but extras are allowed).
	CapabilitiesInclude []string

	// MessagesMinLength is the minimum total character count of all messages
	// combined. 0 means "no minimum".
	MessagesMinLength int

	// MessagesTotalTokGT is a "total estimated tokens > N" threshold.
	// Estimated as chars/4. 0 means "no threshold".
	MessagesTotalTokGT int
}

// IsEmpty reports whether the condition imposes no constraints and therefore
// matches all requests. Used at load time to warn about unconditional rules.
func (m MatchCondition) IsEmpty() bool {
	return len(m.Task) == 0 &&
		len(m.Complexity) == 0 &&
		len(m.CapabilitiesInclude) == 0 &&
		m.MessagesMinLength == 0 &&
		m.MessagesTotalTokGT == 0
}

// Rule is one entry in the policy routes list.
type Rule struct {
	Name     string
	If       MatchCondition
	Target   string
	Fallback []string
	Reason   string
}

// ClassifierConfig controls the classifier model call behaviour.
type ClassifierConfig struct {
	Model     string
	TimeoutMs int
	MaxTokens int
}

// Baseline holds the counterfactual reference model for the savings display.
type Baseline struct {
	Model string
}

// Policy is the compiled, immutable result of loading router-policy.yaml.
// Store it behind a PolicyHolder for hot-reload support.
type Policy struct {
	SchemaVersion int
	Classifier    ClassifierConfig
	Routes        []Rule
	Default       Rule // Name is set to "<default>"; If is empty
	Baseline      Baseline

	// Warnings are non-fatal issues collected during load (e.g. duplicate rule
	// names). Callers may log these but they do not prevent the policy from being
	// used.
	Warnings []string
}

// PolicyHolder holds a *Policy behind an atomic pointer, enabling lock-free
// reads from any goroutine and safe swaps by a single writer (the router's
// reload path). The hot path is: h.Get() once at entry, use the snapshot for
// the lifetime of the request. This means a reload mid-request does not affect
// that in-flight request; the next request sees the new policy.
type PolicyHolder struct {
	ptr atomic.Pointer[Policy]
}

// NewPolicyHolder constructs a PolicyHolder pre-loaded with the given policy.
// p may be nil.
func NewPolicyHolder(p *Policy) *PolicyHolder {
	h := &PolicyHolder{}
	if p != nil {
		h.ptr.Store(p)
	}
	return h
}

// Get returns the current policy snapshot. The returned pointer must not be
// stored beyond the current request's lifetime; callers should re-call Get()
// on each new request to pick up reloads.
func (h *PolicyHolder) Get() *Policy {
	return h.ptr.Load()
}

// Set atomically replaces the stored policy. Safe to call concurrently with
// Get from any number of goroutines.
func (h *PolicyHolder) Set(p *Policy) {
	h.ptr.Store(p)
}
