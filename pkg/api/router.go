package api

// ---------------------------------------------------------------------------
// Router wire types
// ---------------------------------------------------------------------------

// ClassifierOutput is the parsed JSON the classifier model returns.
type ClassifierOutput struct {
	Task         string   `json:"task"`
	Complexity   string   `json:"complexity"`
	Capabilities []string `json:"capabilities"`
	Reasoning    string   `json:"reasoning"`
}

// RoutingDecision is the single-row audit/wire shape for one routing event.
// The router writes one of these per line in router-audit.jsonl. Control plane
// tails the file and serves the same struct on REST and over WebSocket.
type RoutingDecision struct {
	TS            string `json:"ts"`          // RFC3339Nano UTC
	RequestID     string `json:"request_id"`
	SchemaVersion int    `json:"schema_version"`

	// Classifier stage
	ClassifierModel      string           `json:"classifier_model"`
	ClassifierLatencyMs  float64          `json:"classifier_latency_ms"`
	ClassifierCostUSD    float64          `json:"classifier_cost_usd"`
	ClassifierOutput     ClassifierOutput `json:"classifier_output"`
	ClassifierFailed     bool             `json:"classifier_failed,omitempty"`
	ClassifierFailReason string           `json:"classifier_fail_reason,omitempty"`

	// Policy match
	MatchedRuleName string   `json:"matched_rule_name"`
	TargetModel     string   `json:"target_model"`
	FallbacksTried  []string `json:"fallbacks_tried,omitempty"`

	// Forward stage
	ForwardLatencyMs float64 `json:"forward_latency_ms"`
	ForwardCostUSD   float64 `json:"forward_cost_usd"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`

	// Totals
	TotalLatencyMs  float64 `json:"total_latency_ms"`
	TotalCostUSD    float64 `json:"total_cost_usd"`    // classifier + forward
	BaselineCostUSD float64 `json:"baseline_cost_usd"` // hypothetical cost if baseline.model handled this
	SavingsUSD      float64 `json:"savings_usd"`       // baseline - total; may be negative

	// Prompt excerpt (first user message, first 256 bytes, utf8-safe)
	PromptExcerpt string `json:"prompt_excerpt,omitempty"`

	// Error
	Error string `json:"error,omitempty"`
}

// RouterAuditSchemaVersion is the current schema version for router JSONL audit rows.
// Bump this on any change to RoutingDecision fields. The control plane logs and
// skips lines with a higher version.
const RouterAuditSchemaVersion = 1

// ---------------------------------------------------------------------------
// Router REST views
// ---------------------------------------------------------------------------

// RouterPolicy is the JSON-serializable view of router-policy.yaml.
// Used by GET /api/v1/router/policy. Mirrors the YAML structure 1:1.
type RouterPolicy struct {
	SchemaVersion int              `json:"schema_version"`
	Classifier    RouterClassifier `json:"classifier"`
	Routes        []RouterRoute    `json:"routes"`
	Default       RouterRoute      `json:"default"`
	Baseline      RouterBaseline   `json:"baseline"`
}

type RouterClassifier struct {
	Model     string `json:"model"`
	TimeoutMs int    `json:"timeout_ms"`
	MaxTokens int    `json:"max_tokens"`
}

type RouterRoute struct {
	Name     string         `json:"name"`
	If       RouterMatchCond `json:"if,omitempty"`
	Target   string         `json:"target"`
	Fallback []string       `json:"fallback,omitempty"`
	Reason   string         `json:"reason,omitempty"`
}

type RouterMatchCond struct {
	Task                  []string `json:"task,omitempty"`
	Complexity            []string `json:"complexity,omitempty"`
	CapabilitiesInclude   []string `json:"capabilities_include,omitempty"`
	MessagesMinLength     int      `json:"messages_min_length,omitempty"`
	MessagesTotalTokensGT int      `json:"messages_total_tokens_gt,omitempty"`
}

type RouterBaseline struct {
	Model string `json:"model"`
}

// RouterStats summarizes the recent router activity for the dashboard.
type RouterStats struct {
	WindowSeconds   int                  `json:"window_seconds"`
	TotalCalls      int                  `json:"total_calls"`
	TotalCostUSD    float64              `json:"total_cost_usd"`
	BaselineCostUSD float64              `json:"baseline_cost_usd"`
	SavingsUSD      float64              `json:"savings_usd"`
	SavingsPct      float64              `json:"savings_pct"` // savings / baseline * 100
	AvgClassifierMs float64              `json:"avg_classifier_ms"`
	AvgForwardMs    float64              `json:"avg_forward_ms"`
	AvgTotalMs      float64              `json:"avg_total_ms"`
	PerTask         map[string]int       `json:"per_task"`
	PerModel        map[string]ModelStat `json:"per_model"`
}

type ModelStat struct {
	Count        int     `json:"count"`
	CostUSD      float64 `json:"cost_usd"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

type RouterDecisionsResponse struct {
	Items     []RoutingDecision `json:"items"`
	NextSince string            `json:"next_since,omitempty"`
	HasMore   bool              `json:"has_more"`
}

type RouterPolicyPutResponse struct {
	OK      bool     `json:"ok"`
	Message string   `json:"message,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}
