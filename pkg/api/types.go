// Package api defines the wire types shared between Flint's control plane HTTP
// API, the gateway's JSONL audit file, and the dashboard UI. Changes here are
// breaking — bump schema_version on the audit format and update ui/src/api/types.ts.
package api

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

type Agent struct {
	ID                string  `json:"id"`
	Roles             []string `json:"roles"`
	Scopes            []string `json:"scopes"`
	DiscoverableTools int     `json:"discoverable_tools"`
	InvokableTools    int     `json:"invokable_tools"`
	RecentDeniedCount int     `json:"recent_denied_count"`
	LastSeenAt        *string `json:"last_seen_at"`
}

type AgentDetail struct {
	Agent
	EffectivePermissions []EffectivePermission `json:"effective_permissions"`
	RecentDenials        []DecisionRow         `json:"recent_denials"`
}

type EffectivePermission struct {
	ToolName       string   `json:"tool_name"`
	Server         string   `json:"server"`
	Verb           string   `json:"verb"`            // "discover" | "invoke" | "admin"
	Lens           string   `json:"lens"`            // "read" | "write" | "admin"
	GrantedByRoles []string `json:"granted_by_roles"`
	Constraints    []string `json:"constraints"`
	DeniedByRole   string   `json:"denied_by_role"`
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

type Connection struct {
	Name         string   `json:"name"`
	Command      []string `json:"command"`
	Status       string   `json:"status"` // "connected" | "degraded" | "offline"
	ToolCount    int      `json:"tool_count"`
	LastCallAt   *string  `json:"last_call_at"`
	P50LatencyMs float64  `json:"p50_latency_ms"`
}

type ConnectionDetail struct {
	Connection
	Tools []ToolEntry `json:"tools"`
}

type ToolEntry struct {
	Name           string   `json:"name"`
	Tags           []string `json:"tags"`
	Scope          string   `json:"scope"`
	PayloadClass   string   `json:"payload_class"`
	Classification string   `json:"classification"` // "read" | "write" | "admin"
}

// ---------------------------------------------------------------------------
// Roles & Bindings
// ---------------------------------------------------------------------------

type Role struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Name        string              `json:"name,omitempty"`
	Effect      string              `json:"effect"`              // "allow" | "deny"
	Resources   []string            `json:"resources"`
	Verbs       []string            `json:"verbs"`
	Constraints map[string][]string `json:"constraints,omitempty"`
}

type Binding struct {
	Agent  string   `json:"agent"`
	Roles  []string `json:"roles"`
	Scopes []string `json:"scopes"`
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type Session struct {
	ID            string  `json:"id"`
	AgentID       string  `json:"agent_id"`
	StartedAt     string  `json:"started_at"`
	EventCount    int     `json:"event_count"`
	DeniedCount   int     `json:"denied_count"`
	FindingsCount int     `json:"findings_count"`
	RiskScore     float64 `json:"risk_score"`
	Disposition   string  `json:"disposition"`
}

// ---------------------------------------------------------------------------
// Decisions (also the JSONL audit row format — gateway marshals these directly)
// ---------------------------------------------------------------------------

// DecisionRow is the canonical wire shape for a single authorization decision.
// Gateway writes one of these per line in flint-audit.jsonl. Control plane
// tails the file and serves the same struct on the REST API and via WebSocket.
type DecisionRow struct {
	TS              string       `json:"ts"`
	SessionID       string       `json:"session_id"`
	AgentID         string       `json:"agent_id"`
	ToolName        string       `json:"tool_name"`
	Direction       string       `json:"direction"`        // "request" | "response"
	Allowed         bool         `json:"allowed"`
	Reason          string       `json:"reason"`
	Constraint      string       `json:"constraint"`
	MatchedRole     string       `json:"matched_role"`
	MatchedRule     int          `json:"matched_rule"`
	MatchedRuleName string       `json:"matched_rule_name"`
	RequiredVerb    string       `json:"required_verb"`
	GrantedVerb     string       `json:"granted_verb"`
	EvaluatedScopes []string     `json:"evaluated_scopes"`
	LatencyMs       *float64     `json:"latency_ms"`
	RequestID       string       `json:"request_id"`
	EventSeq        int64        `json:"event_seq"`
	PayloadExcerpt  string       `json:"payload_excerpt"`
	Findings        []FindingRow `json:"findings,omitempty"`
	SchemaVersion   int          `json:"schema_version"`
}

type FindingRow struct {
	RuleID   string  `json:"rule_id"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
	Message  string  `json:"message"`
}

// AuditSchemaVersion is the current JSONL audit schema version.
// Bump this on any change to DecisionRow fields. The control plane logs and
// skips lines with a higher version.
const AuditSchemaVersion = 1

// ---------------------------------------------------------------------------
// REST responses
// ---------------------------------------------------------------------------

type DecisionsResponse struct {
	Items     []DecisionRow `json:"items"`
	NextSince string        `json:"next_since,omitempty"`
	HasMore   bool          `json:"has_more"`
}

type RolePutResponse struct {
	OK      bool     `json:"ok"`
	Message string   `json:"message,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

type Healthz struct {
	Status       string `json:"status"`
	PolicyLoaded bool   `json:"policy_loaded"`
	AgentsKnown  int    `json:"agents_known"`
	AuditPath    string `json:"audit_path"`
	GatewayUp    bool   `json:"gateway_up"`
}

// ---------------------------------------------------------------------------
// WebSocket frames
// ---------------------------------------------------------------------------

// WSFrame is the envelope for every WebSocket message from server to client.
// Type discriminates which field of Data is set; clients should switch on Type.
type WSFrame struct {
	Type string `json:"type"` // "hello" | "decision" | "finding" | "agent_seen"
	Data any    `json:"data"`
}

type WSHello struct {
	SchemaVersion int `json:"schema_version"`
	BacklogCount  int `json:"backlog_count"`
}

type WSAgentSeen struct {
	AgentID string `json:"agent_id"`
	TS      string `json:"ts"`
}
