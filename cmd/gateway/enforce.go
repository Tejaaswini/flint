package main

import (
	"flint/engine/session"
)

// EnforcementDecision is the result of consulting the enforcement matrix for a
// single event after the behavioral engine has processed it.
type EnforcementDecision struct {
	// Block is true when the gateway must refuse to forward the message
	// (request not sent upstream / response not forwarded to agent).
	Block bool

	// CitedRuleID is the rule that drove the block decision. Empty when Block
	// is false.
	CitedRuleID string

	// EnforcedAction is the audit-log value for DecisionRow.EnforcedAction.
	// Values: "allow" | "observed" | "blocked".
	EnforcedAction string
}

// actionRank returns a numeric rank for a finding Action so we can pick the
// most severe when multiple findings fire on the same event.
// Higher rank = more severe.
func actionRank(action string) int {
	switch action {
	case "terminate":
		return 3
	case "pause":
		return 2
	case "warn":
		return 1
	default:
		return 0
	}
}

// pickCitedFinding returns the highest-severity finding from the slice, using
// action rank as the primary key and first-in-order to break ties. Returns nil
// when findings is empty.
func pickCitedFinding(findings []session.Finding) *session.Finding {
	if len(findings) == 0 {
		return nil
	}
	best := &findings[0]
	for i := range findings[1:] {
		if actionRank(findings[i+1].Action) > actionRank(best.Action) {
			best = &findings[i+1]
		}
	}
	return best
}

// DecideEnforcement computes the enforcement decision for a single event.
//
// Parameters:
//   - disposition: the session-level disposition AFTER the engine processed
//     the current event ("allow", "warn", "pause", "terminate").
//   - findings: the findings returned by the engine for this specific event.
//   - mode: "block" (default) or "observe". In observe mode all events pass
//     through regardless of disposition; enforced_action is still set correctly
//     so the audit trail reflects what would have been blocked.
//
// Decision matrix:
//
//	disposition=allow/warn + any mode  → Block=false, EnforcedAction="allow" (no findings)
//	                                                   or "observed" (findings present)
//	disposition=pause/terminate + observe mode → Block=false, EnforcedAction="observed"
//	disposition=pause/terminate + block mode   → Block=true,  EnforcedAction="blocked"
func DecideEnforcement(disposition string, findings []session.Finding, mode string) EnforcementDecision {
	shouldBlock := (disposition == "pause" || disposition == "terminate") && mode == "block"

	if shouldBlock {
		cited := pickCitedFinding(findings)
		ruleID := ""
		if cited != nil {
			ruleID = cited.RuleID
		}
		return EnforcementDecision{
			Block:          true,
			CitedRuleID:    ruleID,
			EnforcedAction: "blocked",
		}
	}

	// Not blocking — distinguish clean pass from observed finding.
	if len(findings) > 0 {
		return EnforcementDecision{
			Block:          false,
			EnforcedAction: "observed",
		}
	}
	return EnforcementDecision{
		Block:          false,
		EnforcedAction: "allow",
	}
}
