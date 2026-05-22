package main

import (
	"net/http"
	"strings"

	"flint/pkg/api"
)

// handleSessionsList handles GET /api/v1/sessions.
func handleSessionsList(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions := state.Sessions()
		writeJSON200(w, sessions)
	}
}

// handleSessionDetail handles GET /api/v1/sessions/:id.
func handleSessionDetail(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := extractPathSegment(r.URL.Path, "/api/v1/sessions/", 1)
		if id == "" {
			http.Error(w, "session id required", http.StatusBadRequest)
			return
		}

		sess, ok := state.GetSession(id)
		if !ok {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		writeJSON200(w, sess)
	}
}

// handleSessionEvents handles GET /api/v1/sessions/:id/events.
func handleSessionEvents(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := extractPathSegment(r.URL.Path, "/api/v1/sessions/", 1)
		if id == "" {
			http.Error(w, "session id required", http.StatusBadRequest)
			return
		}

		// Verify session exists.
		if _, ok := state.GetSession(id); !ok {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}

		events := state.SessionEvents(id)
		if events == nil {
			events = []api.DecisionRow{}
		}
		writeJSON200(w, events)
	}
}

// extractPathSegment returns the Nth segment after a prefix.
// N=1 means the first path component after the prefix.
// For path "/api/v1/sessions/abc123/events" and prefix "/api/v1/sessions/", N=1 → "abc123".
func extractPathSegment(path, prefix string, n int) string {
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.SplitN(rest, "/", n+1)
	if len(parts) < n {
		return ""
	}
	return strings.Trim(parts[n-1], "/")
}
