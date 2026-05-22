package main

import (
	"net/http"
	"sort"
	"strings"

	"flint/engine/authz"
	"flint/engine/session"
	"flint/pkg/api"
)

// handleAgentsList handles GET /api/v1/agents.
func handleAgentsList(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ids := state.AgentIDs()
		agents := make([]api.Agent, 0, len(ids))
		for _, id := range ids {
			a, ok := state.AgentSummary(id)
			if ok {
				agents = append(agents, a)
			}
		}
		writeJSON200(w, agents)
	}
}

// handleAgentDetail handles GET /api/v1/agents/:id.
// Path format: /api/v1/agents/{id}
func handleAgentDetail(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
		agentID = strings.Trim(agentID, "/")
		if agentID == "" {
			http.Error(w, "agent id required", http.StatusBadRequest)
			return
		}

		base, ok := state.AgentSummary(agentID)
		if !ok {
			http.Error(w, "agent not found", http.StatusNotFound)
			return
		}

		// Compute effective permissions.
		perms := computeEffectivePermissions(state, agentID)

		// Recent denials — last 50 denied decisions for this agent.
		all := state.RecentDecisions(0)
		var denials []api.DecisionRow
		for i := len(all) - 1; i >= 0 && len(denials) < 50; i-- {
			row := all[i]
			if row.AgentID == agentID && !row.Allowed {
				denials = append(denials, row)
			}
		}
		// Reverse so oldest first.
		for i, j := 0, len(denials)-1; i < j; i, j = i+1, j-1 {
			denials[i], denials[j] = denials[j], denials[i]
		}

		detail := api.AgentDetail{
			Agent:                base,
			EffectivePermissions: perms,
			RecentDenials:        denials,
		}
		writeJSON200(w, detail)
	}
}

// computeEffectivePermissions walks every tool in the registry, evaluates
// allow/deny for agentID, and returns the list of EffectivePermission.
func computeEffectivePermissions(state *State, agentID string) []api.EffectivePermission {
	policy := state.GetPolicy()
	registry := state.GetRegistry()
	if policy == nil || registry == nil {
		return nil
	}

	binding, ok := policy.Bindings[agentID]
	if !ok {
		return nil
	}

	// We need to know which roles grant allow for each tool.
	// Walk roles to find grants and denials.
	type permInfo struct {
		grantedByRoles []string
		deniedByRole   string
		grantedVerb    string
		constraints    []string
	}

	perms := make(map[string]*permInfo)

	// Initialize all tools.
	for toolName := range registry {
		perms[toolName] = &permInfo{}
	}

	// Scan each role for grants and denials.
	for _, roleName := range binding.Roles {
		role, exists := policy.Roles[roleName]
		if !exists {
			continue
		}
		for _, rule := range role.Rules {
			for toolName := range registry {
				if !rule.Resources[toolName] && !rule.Resources["*"] {
					continue
				}
				info := perms[toolName]
				if rule.Effect == authz.EffectDeny {
					// Only unconditional deny rules (no constraints) are surfaced
					// here because we don't have a payload at this point.
					if len(rule.Constraints) == 0 && info.deniedByRole == "" {
						info.deniedByRole = roleName
					}
				} else {
					// Allow rule — add the role to the granted list.
					info.grantedByRoles = append(info.grantedByRoles, roleName)
					if session.VerbOrdinal(rule.MaxVerb) > session.VerbOrdinal(info.grantedVerb) {
						info.grantedVerb = rule.MaxVerb
					}
					// Collect constraint descriptions.
					for _, c := range rule.Constraints {
						desc := c.Type + " in " + strings.Join(c.Allowed, "|")
						info.constraints = append(info.constraints, desc)
					}
				}
			}
		}
	}

	var out []api.EffectivePermission
	for toolName, info := range perms {
		meta := registry[toolName]
		verb := info.grantedVerb
		if verb == "" {
			verb = "discover"
		}

		lens := lensFromVerb(verb, meta)
		if info.deniedByRole != "" {
			lens = "read" // denied tools show as read (conservative UI hint)
		}

		sort.Strings(info.grantedByRoles)
		sort.Strings(info.constraints)

		out = append(out, api.EffectivePermission{
			ToolName:       toolName,
			Server:         serverFromTool(toolName),
			Verb:           verb,
			Lens:           lens,
			GrantedByRoles: info.grantedByRoles,
			Constraints:    info.constraints,
			DeniedByRole:   info.deniedByRole,
		})
	}

	// Sort by tool name for deterministic output.
	sort.Slice(out, func(i, j int) bool {
		return out[i].ToolName < out[j].ToolName
	})

	return out
}

// writeJSON200 writes v as JSON with 200 status code.
func writeJSON200(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}
