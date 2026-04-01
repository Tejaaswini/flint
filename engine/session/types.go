package session

import "time"

// Verb constants for RBAC authorization.
const (
	VerbDiscover = "discover"
	VerbInvoke   = "invoke"
	VerbAdmin    = "admin"
)

// VerbOrdinal returns the integer rank of a verb for comparison.
// Higher ordinal means more permissive. Returns -1 for unknown verbs.
func VerbOrdinal(verb string) int {
	switch verb {
	case VerbDiscover:
		return 0
	case VerbInvoke:
		return 1
	case VerbAdmin:
		return 2
	default:
		return -1
	}
}

// PolicyDecision is the full record of a single authorization decision.
// Every call to Evaluate produces one, whether allowed or denied.
type PolicyDecision struct {
	EventSeq        int64
	AgentID         string
	ToolName        string
	RequiredVerb    string
	GrantedVerb     string // best grant found, even on denial
	Allowed         bool
	Reason          string // see Reason constants below
	Constraint      string // which constraint failed (constraint_violation / constraint_unverifiable only)
	MatchedRole     string // role that produced the final decision
	MatchedRule     int    // index of the rule within that role
	EvaluatedScopes []string
	Timestamp       time.Time
}

// Reason constants for PolicyDecision.
const (
	ReasonAllowed                = "allowed"
	ReasonNoPolicy               = "no_policy"
	ReasonNoPrincipal            = "no_principal"
	ReasonNoBinding              = "no_binding"
	ReasonScopeMismatch          = "scope_mismatch"
	ReasonNoMatchingRule         = "no_matching_rule"
	ReasonVerbInsufficient       = "verb_insufficient"
	ReasonConstraintViolation    = "constraint_violation"
	ReasonConstraintUnverifiable = "constraint_unverifiable"
)

// ReasonPrecedence returns the priority of a denial reason.
// Higher value = higher priority = reported over lower-priority reasons.
func ReasonPrecedence(reason string) int {
	switch reason {
	case ReasonConstraintUnverifiable:
		return 4
	case ReasonConstraintViolation:
		return 3
	case ReasonVerbInsufficient:
		return 2
	case ReasonNoMatchingRule:
		return 1
	default:
		return 0
	}
}

type SessionEvent struct {
	SessionID    string         `json:"session_id"`
	AgentID      string         `json:"agent_id"`
	EventSeq     int64          `json:"event_seq"`
	Timestamp    time.Time      `json:"timestamp"`
	Direction    string         `json:"direction"`
	Method       string         `json:"method"`
	ToolName     string         `json:"tool_name"`
	ToolTags     []string       `json:"tool_tags"`
	Scope        string         `json:"scope"`
	PayloadClass string         `json:"payload_class"`
	RequestID    string         `json:"request_id"`
	Payload      map[string]any `json:"payload"`
	PayloadSize  int            `json:"payload_size"`
}

type TokenOccurrence struct {
	EventSeq int64
	Field    string
	Value    string
	Pattern  string
}

type FieldOccurrence struct {
	EventSeq int64
	Field    string
	RawValue string
}

type SessionEdge struct {
	SrcEventSeq int64
	DstEventSeq int64
	EdgeType    string
	Confidence  float64
	MatchedKeys []string
}

type Finding struct {
	RuleID          string
	Severity        string
	Confidence      float64
	Message         string
	TriggerEventSeq int64
	SrcEventSeq     int64
	Action          string
	Score           float64
	MatchedEdges    []SessionEdge
}

type SessionState struct {
	SessionID        string
	StartedAt        time.Time
	LastEventSeq     int64
	RiskScore        float64
	Disposition      string
	Events           []SessionEvent
	TokenIndex       map[string][]TokenOccurrence
	FieldHashIndex   map[string][]FieldOccurrence
	Edges            []SessionEdge
	Findings         []Finding
	PolicyDecisions  []PolicyDecision
	DeniedRequestIDs map[string]bool
}

type ToolMeta struct {
	Tags         []string
	Scope        string
	PayloadClass string
}
