package authz

// CanDiscover returns true if the agent is permitted to see the tool in a
// tools/list response.
//
// Two-pass logic:
//
//  1. Deny scan: if any deny rule (across all the agent's roles) matches the
//     tool name, return false — BUT only for constraint-less deny rules.
//     A deny rule that has constraints is skipped here because at tools/list
//     time we have no payload to evaluate the constraint against; the tool
//     remains discoverable and the deny will fire at call time if the
//     constraint matches the actual arguments.
//
//  2. Allow scan: the existing behavior — at least one rule in any role must
//     cover the tool (regardless of verb or constraints).
func CanDiscover(policy *Policy, agentID, toolName string) bool {
	if policy == nil {
		return true
	}
	binding, ok := policy.Bindings[agentID]
	if !ok {
		return false
	}

	// Pass 1: deny scan (constraint-less deny rules suppress discovery).
	for _, roleName := range binding.Roles {
		role, exists := policy.Roles[roleName]
		if !exists {
			continue
		}
		for _, rule := range role.Rules {
			if rule.Effect != EffectDeny {
				continue
			}
			if !rule.Resources[toolName] && !rule.Resources["*"] {
				continue
			}
			// A deny rule with constraints does NOT suppress discovery:
			// we cannot evaluate the constraint without a payload, and the
			// tool may be callable with non-matching arguments.
			if len(rule.Constraints) > 0 {
				continue
			}
			// Unconditional deny — tool is not discoverable.
			return false
		}
	}

	// Pass 2: allow scan — at least one allow rule must cover the tool.
	for _, roleName := range binding.Roles {
		role, exists := policy.Roles[roleName]
		if !exists {
			continue
		}
		for _, rule := range role.Rules {
			// Skip deny rules — they do not grant discovery.
			if rule.Effect == EffectDeny {
				continue
			}
			if rule.Resources[toolName] || rule.Resources["*"] {
				return true
			}
		}
	}
	return false
}
