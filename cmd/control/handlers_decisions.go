package main

import (
	"net/http"
	"strconv"

	"flint/pkg/api"
)

const (
	defaultDecisionLimit = 100
	maxDecisionLimit     = 500
)

// handleDecisions handles GET /api/v1/decisions?limit=&since=.
// Returns paginated decisions from the in-memory ring buffer.
func handleDecisions(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		limit := defaultDecisionLimit
		if raw := q.Get("limit"); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 {
				limit = v
			}
		}
		if limit > maxDecisionLimit {
			limit = maxDecisionLimit
		}

		since := q.Get("since")

		items, hasMore := state.DecisionsSince(since, limit)
		if items == nil {
			items = []api.DecisionRow{}
		}

		var nextSince string
		if len(items) > 0 {
			nextSince = items[len(items)-1].TS
		}

		resp := api.DecisionsResponse{
			Items:     items,
			NextSince: nextSince,
			HasMore:   hasMore,
		}
		writeJSON200(w, resp)
	}
}
