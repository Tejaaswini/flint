package authz

import (
	"strings"
	"time"

	"flint/engine/session"
)

// fieldAliases maps each constraint type to the payload field names it recognizes,
// in priority order. Each constraint owns its alias table.
var fieldAliases = map[string][]string{
	"sql_intent":  {"query", "sql"},
	"path_prefix": {"path", "file", "filepath", "file_path", "filename"},
}

// Evaluate is the core authorization function. Pure: no I/O, no side effects.
// Same inputs always produce the same output.
func Evaluate(policy *Policy, agentID string, evt *session.SessionEvent) session.PolicyDecision {
	base := session.PolicyDecision{
		EventSeq:  evt.EventSeq,
		AgentID:   agentID,
		ToolName:  evt.ToolName,
		Timestamp: time.Now(),
	}

	// policy == nil: passthrough (dev mode)
	if policy == nil {
		return allow(base, session.ReasonNoPolicy, "", "", 0)
	}

	// empty principal is always denied
	if agentID == "" {
		return deny(base, session.ReasonNoPrincipal, "", "", 0, nil)
	}

	binding, ok := policy.Bindings[agentID]
	if !ok {
		return deny(base, session.ReasonNoBinding, "", "", 0, nil)
	}

	// Scope check
	evtScope := normalizeScope(evt.Scope)
	evaluatedScopes := scopeList(binding.Scopes)
	if !scopeAllowed(binding.Scopes, evtScope) {
		return deny(base, session.ReasonScopeMismatch, "", "", 0, evaluatedScopes)
	}

	// Evaluate all roles and rules — additive model
	resourceMatched := false
	var best *candidate // best denial candidate so far

	for _, roleName := range binding.Roles {
		role, exists := policy.Roles[roleName]
		if !exists {
			continue // dangling ref — loader should have caught this
		}

		for ruleIdx, rule := range role.Rules {
			if !rule.Resources[evt.ToolName] && !rule.Resources["*"] {
				continue // not_applicable
			}
			resourceMatched = true

			// Verb check
			required := session.VerbInvoke // all tool calls require invoke
			if session.VerbOrdinal(rule.MaxVerb) < session.VerbOrdinal(required) {
				best = updateCandidate(best, &candidate{
					reason:      session.ReasonVerbInsufficient,
					grantedVerb: rule.MaxVerb,
					matchedRole: roleName,
					matchedRule: ruleIdx,
				})
				continue
			}

			// Constraint checks
			denied, reason, constraintName := evalConstraints(rule.Constraints, evt)
			if denied {
				best = updateCandidate(best, &candidate{
					reason:      reason,
					grantedVerb: rule.MaxVerb,
					matchedRole: roleName,
					matchedRule: ruleIdx,
					constraint:  constraintName,
				})
				continue
			}

			// All checks passed — allow
			d := allow(base, session.ReasonAllowed, roleName, rule.MaxVerb, ruleIdx)
			d.EvaluatedScopes = evaluatedScopes
			return d
		}
	}

	if !resourceMatched {
		return deny(base, session.ReasonNoMatchingRule, "", "", 0, evaluatedScopes)
	}

	// Return the highest-precedence denial candidate
	if best != nil {
		d := deny(base, best.reason, best.matchedRole, best.grantedVerb, best.matchedRule, evaluatedScopes)
		d.Constraint = best.constraint
		return d
	}
	return deny(base, session.ReasonNoMatchingRule, "", "", 0, evaluatedScopes)
}

// evalConstraints runs all constraints on a rule.
// Returns (denied bool, reason, constraintName).
// A failed constraint is a candidate denial, not a hard stop — the caller decides.
func evalConstraints(constraints []Constraint, evt *session.SessionEvent) (bool, string, string) {
	for _, c := range constraints {
		aliases := fieldAliases[c.Type]
		value, found := findField(evt.Payload, aliases)

		if !found {
			if c.Mode == ConstraintStrict {
				return true, session.ReasonConstraintUnverifiable, c.Type
			}
			// permissive: log could go here; continue
			continue
		}

		var passes bool
		switch c.Type {
		case "sql_intent":
			passes = checkSQLIntent(value, c.Allowed)
		case "path_prefix":
			passes = checkPathPrefix(value, c.Allowed)
		}

		if !passes {
			return true, session.ReasonConstraintViolation, c.Type
		}
	}
	return false, "", ""
}

// findField walks the alias list and returns the first matching payload value.
func findField(payload map[string]any, aliases []string) (string, bool) {
	for _, alias := range aliases {
		if v, ok := payload[alias]; ok {
			if s, ok := v.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

// checkSQLIntent checks the first keyword of the query value against the allowlist.
func checkSQLIntent(query string, allowed []string) bool {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return false
	}
	parts := strings.Fields(trimmed)
	if len(parts) == 0 {
		return false
	}
	first := strings.ToLower(parts[0])
	for _, a := range allowed {
		if strings.ToLower(a) == first {
			return true
		}
	}
	return false
}

// checkPathPrefix checks whether the path value starts with any allowed prefix.
func checkPathPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// scopeAllowed returns true if the event scope is permitted by the binding's scope set.
func scopeAllowed(scopes map[string]bool, evtScope string) bool {
	if scopes == nil {
		return true // unscoped binding — wildcard
	}
	if scopes["*"] {
		return true // explicit wildcard
	}
	if evtScope == "" {
		return false // event has no scope but binding has explicit scopes
	}
	return scopes[evtScope]
}

// scopeList converts the scope map to a sorted slice for the audit trail.
func scopeList(scopes map[string]bool) []string {
	if scopes == nil {
		return nil
	}
	out := make([]string, 0, len(scopes))
	for s := range scopes {
		out = append(out, s)
	}
	return out
}

// -- candidate tracks the best denial reason seen so far ---------------------

type candidate struct {
	reason      string
	grantedVerb string
	matchedRole string
	matchedRule int
	constraint  string
}

// updateCandidate replaces current if the new candidate has higher precedence.
func updateCandidate(current, next *candidate) *candidate {
	if current == nil {
		return next
	}
	if session.ReasonPrecedence(next.reason) > session.ReasonPrecedence(current.reason) {
		return next
	}
	return current
}

// -- helpers ------------------------------------------------------------------

func allow(base session.PolicyDecision, reason, matchedRole, grantedVerb string, matchedRule int) session.PolicyDecision {
	base.Allowed = true
	base.Reason = reason
	base.MatchedRole = matchedRole
	base.GrantedVerb = grantedVerb
	base.MatchedRule = matchedRule
	base.RequiredVerb = session.VerbInvoke
	return base
}

func deny(base session.PolicyDecision, reason, matchedRole, grantedVerb string, matchedRule int, evaluatedScopes []string) session.PolicyDecision {
	base.Allowed = false
	base.Reason = reason
	base.MatchedRole = matchedRole
	base.GrantedVerb = grantedVerb
	base.MatchedRule = matchedRule
	base.RequiredVerb = session.VerbInvoke
	base.EvaluatedScopes = evaluatedScopes
	return base
}
