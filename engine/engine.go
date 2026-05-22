package engine

import (
	"encoding/json"
	"sync"
	"time"

	"flint/engine/authz"
	"flint/engine/lineage"
	"flint/engine/risk"
	"flint/engine/rules"
	"flint/engine/session"
)

type Engine struct {
	Session  *session.SessionState
	registry map[string]session.ToolMeta
	holder   *authz.PolicyHolder

	// mu serializes mutations to Session from concurrent goroutines.
	// The gateway calls ProcessEvent from both the agent→upstream and
	// upstream→agent goroutines; without this, append/map writes race.
	mu sync.Mutex
}

// New creates an Engine with a PolicyHolder for hot-reload support.
// The gateway should use this constructor, passing a holder it manages.
// If registry is nil it falls back to the built-in defaults.
// If holder is nil, RBAC is skipped (passthrough/dev mode).
func New(id string, registry map[string]session.ToolMeta, holder *authz.PolicyHolder) *Engine {
	if registry == nil {
		registry = session.DefaultRegistry
	}
	if holder == nil {
		holder = authz.NewPolicyHolder(nil)
	}
	return &Engine{
		registry: registry,
		holder:   holder,
		Session: &session.SessionState{
			SessionID:        id,
			StartedAt:        time.Now(),
			Disposition:      "allow",
			TokenIndex:       make(map[string][]session.TokenOccurrence),
			FieldHashIndex:   make(map[string][]session.FieldOccurrence),
			DeniedRequestIDs: make(map[string]bool),
		},
	}
}

// NewWithPolicy is a backward-compatible constructor for callers that don't
// need hot reload (e.g. test suites, cmd/replay). It wraps the policy in a
// fresh PolicyHolder internally. The returned Engine cannot be reloaded
// without calling Reload explicitly.
func NewWithPolicy(id string, registry map[string]session.ToolMeta, policy *authz.Policy) *Engine {
	return New(id, registry, authz.NewPolicyHolder(policy))
}

// Reload atomically swaps the policy used by this engine. Safe to call from
// any goroutine. In-flight ProcessEvent calls that have already captured the
// old policy snapshot will finish against that snapshot; the next call will
// see the new policy. (See architecture devlog §2, semantic decision 4.)
func (e *Engine) Reload(p *authz.Policy) {
	e.holder.Set(p)
}

// TransformResponse is a v1.5 hook for response transformation.
// This build returns r unchanged. The gateway can already call it on response
// paths so the signature is stable when the feature is implemented.
func (e *Engine) TransformResponse(r session.Response) session.Response {
	return r
}

// Evaluate runs a pure RBAC evaluation against the current policy snapshot.
// The gateway may call this directly for non-stateful checks (e.g. a "simulate"
// endpoint in the control plane). Unlike ProcessEvent, this method does not
// mutate session state.
func (e *Engine) Evaluate(agentID string, evt session.SessionEvent) session.PolicyDecision {
	policy := e.holder.Get()
	session.ResolveToolWith(e.registry, &evt)
	return authz.Evaluate(policy, agentID, &evt)
}

// Snapshot returns a copy-on-read snapshot of session state.
// Reserved for control-plane debugging endpoints; not used this build.
func (e *Engine) Snapshot() session.SessionState {
	return *e.Session
}

// ProcessEvent runs an event through RBAC + behavioral analysis.
// Returns the PolicyDecision (nil for response-side events that skip the gate)
// alongside any findings, so callers don't need to read e.Session under their
// own locking. Safe for concurrent calls.
func (e *Engine) ProcessEvent(evt session.SessionEvent) (*session.PolicyDecision, []session.Finding) {
	// Capture the policy snapshot once at entry so the entire request
	// (including its correlated response) uses the same policy version,
	// even if Reload is called mid-flight.
	policy := e.holder.Get()

	session.ResolveToolWith(e.registry, &evt)
	evt.PayloadSize = estSize(evt.Payload)

	// Serialize all SessionState mutations; the gateway calls this method
	// from both the agent→upstream and upstream→agent goroutines.
	e.mu.Lock()
	defer e.mu.Unlock()

	var decision *session.PolicyDecision

	// RBAC gate — only evaluate requests, not responses
	if evt.Direction != "response" {
		d := authz.Evaluate(policy, evt.AgentID, &evt)
		decision = &d
		e.Session.PolicyDecisions = append(e.Session.PolicyDecisions, d)
		if !d.Allowed {
			e.Session.DeniedRequestIDs[evt.RequestID] = true
			return decision, nil
		}
	}

	e.Session.Events = append(e.Session.Events, evt)
	e.Session.LastEventSeq = evt.EventSeq

	e.Session.Edges = append(e.Session.Edges, lineage.BuildLineage(e.Session, &evt)...)

	var findings []session.Finding
	findings = append(findings, rules.EvalSecretRelay(e.Session, &evt)...)
	findings = append(findings, rules.EvalRestrictedWrite(e.Session, &evt)...)
	findings = append(findings, rules.EvalPagination(e.Session, &evt)...)
	findings = append(findings, rules.EvalToolPoisoning(e.Session, &evt)...)
	findings = append(findings, rules.EvalFilesystemTraversal(e.Session, &evt)...)
	findings = append(findings, rules.EvalCrossScopeMovement(e.Session, &evt)...)

	for _, f := range findings {
		e.Session.Findings = append(e.Session.Findings, f)
		risk.Apply(e.Session, f)
	}

	return decision, findings
}

func estSize(p any) int {
	b, _ := json.Marshal(p)
	return len(b)
}
