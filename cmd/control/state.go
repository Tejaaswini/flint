package main

import (
	"sort"
	"sync"
	"time"

	"flint/engine/authz"
	"flint/engine/session"
	"flint/pkg/api"
)

const ringBufferCap = 2000
const routerRingBufferCap = 2000

// AgentStats tracks per-agent activity derived from the audit log.
type AgentStats struct {
	LastSeenAt    time.Time
	DeniedLast24h int
	DeniedQueue   []time.Time // rolling window; entries older than 24h are expired
}

// State is the in-memory state for the control plane. All exported methods
// are safe for concurrent use.
type State struct {
	mu sync.RWMutex

	rolesPath    string
	bindingsPath string
	registryPath string
	auditPath    string

	policy   *authz.Policy
	registry map[string]session.ToolMeta

	// Ring buffer of recent decisions; cap=ringBufferCap
	recentDecisions []api.DecisionRow
	ringHead        int // next write position (mod ringBufferCap)
	ringFull        bool

	perAgentStats map[string]*AgentStats
	sessions      map[string]*api.Session

	// Gateway connectivity
	gatewayURL    string
	gatewayLastOK time.Time // last successful health ping

	// Router fields
	routerPolicyPath string
	routerAuditPath  string
	routerSidecarURL string
	routerLastOK     time.Time

	// Ring buffer of recent routing decisions; cap=routerRingBufferCap.
	// Protected by the same mu mutex as the gateway ring — no separate lock.
	recentRoutingDecisions []api.RoutingDecision
	ringRouterHead         int // next write position (mod routerRingBufferCap)
	ringRouterFull         bool
}

// NewState constructs an empty State with the given configuration paths.
func NewState(rolesPath, bindingsPath, registryPath, auditPath, gatewayURL string) *State {
	return &State{
		rolesPath:              rolesPath,
		bindingsPath:           bindingsPath,
		registryPath:           registryPath,
		auditPath:              auditPath,
		gatewayURL:             gatewayURL,
		recentDecisions:        make([]api.DecisionRow, 0, ringBufferCap),
		perAgentStats:          make(map[string]*AgentStats),
		sessions:               make(map[string]*api.Session),
		recentRoutingDecisions: make([]api.RoutingDecision, 0, routerRingBufferCap),
	}
}

// SetRouterPaths configures the router-related file paths and sidecar URL.
func (s *State) SetRouterPaths(policyPath, auditPath, sidecarURL string) {
	s.mu.Lock()
	s.routerPolicyPath = policyPath
	s.routerAuditPath = auditPath
	s.routerSidecarURL = sidecarURL
	s.mu.Unlock()
}

// SetPolicy replaces the loaded policy. Safe to call concurrently.
func (s *State) SetPolicy(p *authz.Policy) {
	s.mu.Lock()
	s.policy = p
	s.mu.Unlock()
}

// GetPolicy returns the current policy. May be nil (passthrough mode).
func (s *State) GetPolicy() *authz.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

// SetRegistry replaces the tool registry.
func (s *State) SetRegistry(r map[string]session.ToolMeta) {
	s.mu.Lock()
	s.registry = r
	s.mu.Unlock()
}

// GetRegistry returns the current registry.
func (s *State) GetRegistry() map[string]session.ToolMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registry
}

// AddDecision appends a decision to the ring buffer and updates derived state.
// Called by audit_tail on every parsed line.
func (s *State) AddDecision(row api.DecisionRow) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ring buffer insert.
	if len(s.recentDecisions) < ringBufferCap {
		s.recentDecisions = append(s.recentDecisions, row)
	} else {
		s.recentDecisions[s.ringHead] = row
		s.ringHead = (s.ringHead + 1) % ringBufferCap
		s.ringFull = true
	}

	// Update per-agent stats.
	if row.AgentID != "" {
		stats := s.perAgentStats[row.AgentID]
		if stats == nil {
			stats = &AgentStats{}
			s.perAgentStats[row.AgentID] = stats
		}
		ts := parseTS(row.TS)
		if ts.After(stats.LastSeenAt) {
			stats.LastSeenAt = ts
		}
		if !row.Allowed {
			stats.DeniedQueue = append(stats.DeniedQueue, ts)
		}
		stats.expireDenials()
		stats.DeniedLast24h = len(stats.DeniedQueue)
	}

	// Update session state.
	if row.SessionID != "" {
		sess := s.sessions[row.SessionID]
		if sess == nil {
			sess = &api.Session{
				ID:          row.SessionID,
				AgentID:     row.AgentID,
				StartedAt:   row.TS,
				Disposition: "allow",
			}
			s.sessions[row.SessionID] = sess
		}
		sess.EventCount++
		if !row.Allowed {
			sess.DeniedCount++
		}
		for _, f := range row.Findings {
			sess.FindingsCount++
			sess.RiskScore += f.Score
			switch {
			case f.Action == "terminate":
				sess.Disposition = "terminate"
			case f.Action == "pause" && sess.Disposition != "terminate":
				sess.Disposition = "pause"
			case f.Action == "warn" && (sess.Disposition == "allow" || sess.Disposition == ""):
				sess.Disposition = "warn"
			}
		}
		// Keep "review" as the catch-all for RBAC-only sessions
		// (denies without any behavioral signal that escalated above allow).
		if sess.DeniedCount > 0 && sess.Disposition == "allow" {
			sess.Disposition = "review"
		}
	}
}

// expireDenials removes entries from DeniedQueue older than 24 hours.
func (a *AgentStats) expireDenials() {
	cutoff := time.Now().Add(-24 * time.Hour)
	i := 0
	for _, t := range a.DeniedQueue {
		if t.After(cutoff) {
			a.DeniedQueue[i] = t
			i++
		}
	}
	a.DeniedQueue = a.DeniedQueue[:i]
}

// RecentDecisions returns a copy of the ring buffer contents in chronological
// order (oldest first), capped to at most maxCount entries.
func (s *State) RecentDecisions(maxCount int) []api.DecisionRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.copyDecisions(maxCount)
}

// copyDecisions must be called with at least an RLock held.
func (s *State) copyDecisions(maxCount int) []api.DecisionRow {
	n := len(s.recentDecisions)
	if n == 0 {
		return nil
	}

	// Build chronological slice.
	var ordered []api.DecisionRow
	if !s.ringFull {
		// Buffer not yet full — the slice is already in order.
		ordered = make([]api.DecisionRow, n)
		copy(ordered, s.recentDecisions)
	} else {
		// Ring is full. Head points to the oldest slot.
		ordered = make([]api.DecisionRow, ringBufferCap)
		tail := copy(ordered, s.recentDecisions[s.ringHead:])
		copy(ordered[tail:], s.recentDecisions[:s.ringHead])
	}

	if maxCount > 0 && len(ordered) > maxCount {
		// Return the most recent maxCount entries.
		ordered = ordered[len(ordered)-maxCount:]
	}
	return ordered
}

// DecisionsSince returns decisions with TS >= sinceTS, up to limit entries.
// The ring buffer is sorted by insertion order, not strictly by TS (clock
// skew or audit replay can put older events after newer ones), so we use a
// linear scan instead of a binary search.
func (s *State) DecisionsSince(sinceTS string, limit int) ([]api.DecisionRow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := s.copyDecisions(0)
	if sinceTS != "" {
		filtered := all[:0]
		for _, row := range all {
			if row.TS >= sinceTS {
				filtered = append(filtered, row)
			}
		}
		all = filtered
	}

	hasMore := false
	if limit > 0 && len(all) > limit {
		all = all[:limit]
		hasMore = true
	}
	return all, hasMore
}

// AgentIDs returns all known agent IDs in sorted order.
// AgentIDs returns the union of agents seen in the audit log and agents
// defined in the policy bindings. Sorted, deduplicated.
func (s *State) AgentIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{}, len(s.perAgentStats))
	for id := range s.perAgentStats {
		seen[id] = struct{}{}
	}
	if s.policy != nil {
		for id := range s.policy.Bindings {
			seen[id] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// AgentSummary returns an api.Agent for the given agentID. Returns ok=true if
// the agent exists in either the policy bindings or the audit log. Agents with
// no audit activity yet get zero-valued stats.
func (s *State) AgentSummary(agentID string) (api.Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats, hasStats := s.perAgentStats[agentID]

	var roles []string
	var scopes []string
	hasBinding := false
	if s.policy != nil {
		if b, ok := s.policy.Bindings[agentID]; ok {
			hasBinding = true
			roles = b.Roles
			if b.Scopes != nil {
				for sc := range b.Scopes {
					scopes = append(scopes, sc)
				}
				sort.Strings(scopes)
			}
		}
	}

	if !hasStats && !hasBinding {
		return api.Agent{}, false
	}

	var lastSeen *string
	deniedCount := 0
	if hasStats {
		ts := stats.LastSeenAt.UTC().Format(time.RFC3339)
		lastSeen = &ts
		deniedCount = stats.DeniedLast24h
	}

	return api.Agent{
		ID:                agentID,
		Roles:             roles,
		Scopes:            scopes,
		DiscoverableTools: s.discoverableCount(agentID),
		InvokableTools:    s.invokableCount(agentID),
		RecentDeniedCount: deniedCount,
		LastSeenAt:        lastSeen,
	}, true
}

// discoverableCount counts tools discoverable by agentID. Must be called with at least RLock.
func (s *State) discoverableCount(agentID string) int {
	if s.policy == nil || s.registry == nil {
		return 0
	}
	count := 0
	for toolName := range s.registry {
		if authz.CanDiscover(s.policy, agentID, toolName) {
			count++
		}
	}
	return count
}

// invokableCount counts tools invokable by agentID. Must be called with at least RLock.
func (s *State) invokableCount(agentID string) int {
	if s.policy == nil || s.registry == nil {
		return 0
	}
	count := 0
	for toolName := range s.registry {
		evt := session.SessionEvent{
			AgentID:  agentID,
			ToolName: toolName,
		}
		d := authz.Evaluate(s.policy, agentID, &evt)
		if d.Allowed {
			count++
		}
	}
	return count
}

// Sessions returns all sessions in a stable order (by start time).
func (s *State) Sessions() []api.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]api.Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, *sess)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt < out[j].StartedAt
	})
	return out
}

// GetSession returns a session by ID.
func (s *State) GetSession(id string) (api.Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return api.Session{}, false
	}
	return *sess, true
}

// SessionEvents returns all decisions for a given session, from the ring buffer.
func (s *State) SessionEvents(sessionID string) []api.DecisionRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.copyDecisions(0)
	var out []api.DecisionRow
	for _, row := range all {
		if row.SessionID == sessionID {
			out = append(out, row)
		}
	}
	return out
}

// MarkGatewayOK records that the gateway health check succeeded.
func (s *State) MarkGatewayOK() {
	s.mu.Lock()
	s.gatewayLastOK = time.Now()
	s.mu.Unlock()
}

// GatewayUp returns true if the gateway was healthy within the last 30 seconds.
func (s *State) GatewayUp() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.gatewayLastOK) < 30*time.Second
}

// LatestDecisionTS returns the most recent TS in the ring buffer, or "".
func (s *State) LatestDecisionTS() *string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.recentDecisions) == 0 {
		return nil
	}
	// Find the most recently added entry. If ring is full, it is the slot before ringHead.
	var latest string
	for _, row := range s.recentDecisions {
		if row.TS > latest {
			latest = row.TS
		}
	}
	if latest == "" {
		return nil
	}
	return &latest
}

// ResponseLatencies returns up to n latency_ms values from response-direction rows.
func (s *State) ResponseLatencies(n int) []float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []float64
	all := s.copyDecisions(0)
	// Walk from newest to oldest.
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		row := all[i]
		if row.Direction == "response" && row.LatencyMs != nil {
			out = append(out, *row.LatencyMs)
		}
	}
	return out
}

// parseTS parses an RFC3339 timestamp string, returning zero time on failure.
func parseTS(ts string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, ts)
	return t
}

// ---------------------------------------------------------------------------
// Router ring buffer methods
// ---------------------------------------------------------------------------

// AddRoutingDecision appends a routing decision to the router ring buffer.
// Called by RouterAuditTail on every parsed line. Thread-safe.
func (s *State) AddRoutingDecision(row api.RoutingDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recentRoutingDecisions) < routerRingBufferCap {
		s.recentRoutingDecisions = append(s.recentRoutingDecisions, row)
	} else {
		s.recentRoutingDecisions[s.ringRouterHead] = row
		s.ringRouterHead = (s.ringRouterHead + 1) % routerRingBufferCap
		s.ringRouterFull = true
	}
}

// RecentRoutingDecisions returns a copy of the router ring buffer in
// chronological order (oldest first), capped to at most maxCount entries.
func (s *State) RecentRoutingDecisions(maxCount int) []api.RoutingDecision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.copyRoutingDecisions(maxCount)
}

// copyRoutingDecisions must be called with at least an RLock held.
func (s *State) copyRoutingDecisions(maxCount int) []api.RoutingDecision {
	n := len(s.recentRoutingDecisions)
	if n == 0 {
		return nil
	}

	var ordered []api.RoutingDecision
	if !s.ringRouterFull {
		ordered = make([]api.RoutingDecision, n)
		copy(ordered, s.recentRoutingDecisions)
	} else {
		ordered = make([]api.RoutingDecision, routerRingBufferCap)
		tail := copy(ordered, s.recentRoutingDecisions[s.ringRouterHead:])
		copy(ordered[tail:], s.recentRoutingDecisions[:s.ringRouterHead])
	}

	if maxCount > 0 && len(ordered) > maxCount {
		ordered = ordered[len(ordered)-maxCount:]
	}
	return ordered
}

// RoutingDecisionsSince returns routing decisions with TS >= sinceTS, up to
// limit entries. Uses a linear scan (not binary search) because the ring buffer
// is sorted by insertion order, not strictly by TS.
func (s *State) RoutingDecisionsSince(sinceTS string, limit int) ([]api.RoutingDecision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := s.copyRoutingDecisions(0)
	if sinceTS != "" {
		filtered := all[:0]
		for _, row := range all {
			if row.TS >= sinceTS {
				filtered = append(filtered, row)
			}
		}
		all = filtered
	}

	hasMore := false
	if limit > 0 && len(all) > limit {
		all = all[:limit]
		hasMore = true
	}
	return all, hasMore
}

// ComputeRouterStats aggregates routing decisions over a window and returns stats.
// window values: "session" (all decisions), "24h", "1h", "5m", "1m", "all".
func (s *State) ComputeRouterStats(window string) api.RouterStats {
	s.mu.RLock()
	all := s.copyRoutingDecisions(0)
	s.mu.RUnlock()

	var windowSecs int
	var cutoff time.Time
	now := time.Now().UTC()

	switch window {
	case "1m":
		windowSecs = 60
		cutoff = now.Add(-1 * time.Minute)
	case "5m":
		windowSecs = 300
		cutoff = now.Add(-5 * time.Minute)
	case "1h":
		windowSecs = 3600
		cutoff = now.Add(-1 * time.Hour)
	case "24h":
		windowSecs = 86400
		cutoff = now.Add(-24 * time.Hour)
	default:
		// "session", "all", or unknown: use all decisions
		windowSecs = 0
		cutoff = time.Time{} // zero = no cutoff
	}

	stats := api.RouterStats{
		WindowSeconds: windowSecs,
		PerTask:       make(map[string]int),
		PerModel:      make(map[string]api.ModelStat),
	}

	var totalClassifierMs, totalForwardMs, totalMs float64
	count := 0

	for _, row := range all {
		if windowSecs > 0 {
			ts := parseTS(row.TS)
			if ts.IsZero() || ts.Before(cutoff) {
				continue
			}
		}

		count++
		stats.TotalCostUSD += row.TotalCostUSD
		stats.BaselineCostUSD += row.BaselineCostUSD
		// Skip classifier-failed rows in savings total — routing was blind (see concerns.md C-002).
		if !row.ClassifierFailed {
			stats.SavingsUSD += row.SavingsUSD
		}
		totalClassifierMs += row.ClassifierLatencyMs
		totalForwardMs += row.ForwardLatencyMs
		totalMs += row.TotalLatencyMs

		// Per-task
		task := row.ClassifierOutput.Task
		if task == "" {
			task = "other"
		}
		stats.PerTask[task]++

		// Per-model
		model := row.TargetModel
		if model != "" {
			ms := stats.PerModel[model]
			ms.Count++
			ms.CostUSD += row.ForwardCostUSD
			ms.AvgLatencyMs += row.ForwardLatencyMs // will normalize below
			stats.PerModel[model] = ms
		}
	}

	stats.TotalCalls = count

	if count > 0 {
		stats.AvgClassifierMs = totalClassifierMs / float64(count)
		stats.AvgForwardMs = totalForwardMs / float64(count)
		stats.AvgTotalMs = totalMs / float64(count)
	}

	if stats.BaselineCostUSD > 0 {
		stats.SavingsPct = stats.SavingsUSD / stats.BaselineCostUSD * 100
	}

	// Normalize AvgLatencyMs per model.
	for model, ms := range stats.PerModel {
		if ms.Count > 0 {
			ms.AvgLatencyMs = ms.AvgLatencyMs / float64(ms.Count)
			stats.PerModel[model] = ms
		}
	}

	return stats
}

// MarkRouterOK records that the router health check succeeded.
func (s *State) MarkRouterOK() {
	s.mu.Lock()
	s.routerLastOK = time.Now()
	s.mu.Unlock()
}

// RouterUp returns true if the router was healthy within the last 30 seconds.
func (s *State) RouterUp() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.routerLastOK) < 30*time.Second
}
