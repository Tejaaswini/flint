package main

import (
	"context"
	"net/http"

	"flint/pkg/api"
)

// handleHealthz handles GET /healthz — control-plane health, not gateway healthz.
func handleHealthz(state *State, gw GatewayClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policy := state.GetPolicy()

		// Ping gateway (best-effort, short timeout via gateway client).
		ctx, cancel := context.WithTimeout(r.Context(), reloadTimeout)
		defer cancel()
		gatewayUp := false
		if _, err := gw.Healthz(ctx); err == nil {
			gatewayUp = true
			state.MarkGatewayOK()
		}

		state.mu.RLock()
		agentsKnown := len(state.perAgentStats)
		state.mu.RUnlock()

		resp := api.Healthz{
			Status:       "ok",
			PolicyLoaded: policy != nil,
			AgentsKnown:  agentsKnown,
			AuditPath:    state.auditPath,
			GatewayUp:    gatewayUp,
		}
		writeJSON200(w, resp)
	}
}
