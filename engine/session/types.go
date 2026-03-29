package session

import "time"

type SessionEvent struct {
	SessionID    string         `json:"session_id"`
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
	SessionID      string
	StartedAt      time.Time
	LastEventSeq   int64
	RiskScore      float64
	Disposition    string
	Events         []SessionEvent
	TokenIndex     map[string][]TokenOccurrence
	FieldHashIndex map[string][]FieldOccurrence
	Edges          []SessionEdge
	Findings       []Finding
}

type ToolMeta struct {
	Tags         []string
	Scope        string
	PayloadClass string
}
