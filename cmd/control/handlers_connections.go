package main

import (
	"net/http"
	"sort"
	"strings"

	"flint/engine/session"
	"flint/pkg/api"
)

// handleConnectionsList handles GET /api/v1/connections.
// For v1 this returns a single connection representing the connected upstream MCP.
func handleConnectionsList(state *State, gw GatewayClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn := buildConnection(state)
		writeJSON200(w, []api.Connection{conn})
	}
}

// handleConnectionDetail handles GET /api/v1/connections/:name.
func handleConnectionDetail(state *State, gw GatewayClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/connections/")
		name = strings.Trim(name, "/")

		conn := buildConnection(state)
		if name != conn.Name {
			http.Error(w, "connection not found", http.StatusNotFound)
			return
		}

		tools := buildToolEntries(state)
		detail := api.ConnectionDetail{
			Connection: conn,
			Tools:      tools,
		}
		writeJSON200(w, detail)
	}
}

// buildConnection constructs the single Connection entry for the upstream MCP.
func buildConnection(state *State) api.Connection {
	registry := state.GetRegistry()

	// Determine the connection name from tool prefixes.
	// If all tools are flat-named (no "."), use "everything" (server-everything default).
	name := inferConnectionName(registry)

	status := "offline"
	if state.GatewayUp() {
		status = "connected"
	}

	toolCount := len(registry)
	lastCallAt := state.LatestDecisionTS()
	p50 := medianLatency(state.ResponseLatencies(100))

	return api.Connection{
		Name:         name,
		Command:      []string{"npx", "-y", "@modelcontextprotocol/server-everything"},
		Status:       status,
		ToolCount:    toolCount,
		LastCallAt:   lastCallAt,
		P50LatencyMs: p50,
	}
}

// inferConnectionName derives a connection name from the registry tool names.
// If all tools share a common server prefix (e.g. "github."), returns "github".
// If tools are flat (no "."), returns "everything".
// If mixed or multiple prefixes, returns the first distinct prefix, or "everything".
func inferConnectionName(registry map[string]session.ToolMeta) string {
	if len(registry) == 0 {
		return "everything"
	}

	prefixes := make(map[string]int)
	flat := 0
	for toolName := range registry {
		if idx := strings.Index(toolName, "."); idx > 0 {
			prefixes[toolName[:idx]]++
		} else {
			flat++
		}
	}

	if flat > 0 && len(prefixes) == 0 {
		return "everything"
	}
	if len(prefixes) == 1 {
		for p := range prefixes {
			return p
		}
	}
	return "everything"
}

// buildToolEntries converts the registry into a sorted list of ToolEntry.
func buildToolEntries(state *State) []api.ToolEntry {
	registry := state.GetRegistry()
	if registry == nil {
		return nil
	}

	entries := make([]api.ToolEntry, 0, len(registry))
	for name, meta := range registry {
		entries = append(entries, api.ToolEntry{
			Name:           name,
			Tags:           meta.Tags,
			Scope:          meta.Scope,
			PayloadClass:   meta.PayloadClass,
			Classification: classifyTool(meta),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	return entries
}

// medianLatency returns the median of a slice of latency values.
// Returns 0 if the slice is empty.
func medianLatency(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}
