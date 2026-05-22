/**
 * API types — mirror of pkg/api/types.go.
 * Keep in sync manually. Last synced: 2026-05-20.
 * When the Go types change, update this file and bump the comment date.
 */

export interface Agent {
  id: string;
  roles: string[];
  scopes: string[];
  discoverable_tools: number;
  invokable_tools: number;
  recent_denied_count: number;
  last_seen_at: string | null; // RFC3339, nullable
}

export interface AgentDetail extends Agent {
  effective_permissions: EffectivePermission[];
  recent_denials: DecisionRow[]; // last 50
}

export interface EffectivePermission {
  tool_name: string;
  server: string;        // "github", from tool name prefix
  verb: string;          // "invoke" | "discover" | "admin"
  lens: string;          // "read" | "write" | "admin"
  granted_by_roles: string[];
  constraints: string[]; // human strings: "sql_intent in [select, with]"
  denied_by_role: string; // non-empty iff deny rule overrides
}

export interface Connection {
  name: string;          // "everything"
  command: string[];     // ["npx","-y","@modelcontextprotocol/server-everything"]
  status: string;        // "connected" | "degraded" | "offline"
  tool_count: number;
  last_call_at: string | null;
  p50_latency_ms: number;
}

export interface ConnectionDetail extends Connection {
  tools: ToolEntry[];
}

export interface ToolEntry {
  name: string;
  tags: string[];
  scope: string;
  payload_class: string;
  classification: string; // "read" | "write" | "admin"
}

export interface Role {
  name: string;
  rules: Rule[];
}

export interface Rule {
  name?: string;
  effect: string;      // "allow" | "deny"
  resources: string[]; // raw selectors as-written
  verbs: string[];
  constraints?: Record<string, string[]>;
}

export interface Binding {
  agent: string;
  roles: string[];
  scopes: string[];
}

export interface Session {
  id: string;
  agent_id: string;
  started_at: string;
  event_count: number;
  denied_count: number;
  findings_count: number;
  risk_score: number;
  disposition: string;
}

export interface DecisionRow {
  ts: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  direction: string;       // "request" | "response"
  allowed: boolean;
  reason: string;
  constraint: string;
  matched_role: string;
  matched_rule: number;
  matched_rule_name: string;
  required_verb: string;
  granted_verb: string;
  evaluated_scopes: string[];
  latency_ms: number | null;
  request_id: string;
  event_seq: number;
  payload_excerpt: string;
  findings?: FindingRow[];
  schema_version: number;
}

export interface FindingRow {
  rule_id: string;
  severity: string;
  score: number;
  message: string;
}

export interface DecisionsResponse {
  items: DecisionRow[];
  next_since?: string; // ts cursor for next page
  has_more: boolean;
}

export interface RolePutResponse {
  ok: boolean;
  message?: string;
  errors?: string[]; // load-time validation errors
}

export interface Healthz {
  status: string;       // "ok"
  policy_loaded: boolean;
  agents_known: number;
  audit_path: string;
  gateway_up: boolean;
}

// WebSocket frame types
export interface WSHello {
  type: "hello";
  data: {
    schema_version: number;
    backlog_count: number;
  };
}

export interface WSDecisionFrame {
  type: "decision";
  data: DecisionRow;
}

export interface WSFindingFrame {
  type: "finding";
  data: FindingRow & { session_id: string; event_seq: number };
}

export interface WSAgentSeenFrame {
  type: "agent_seen";
  data: { agent_id: string; ts: string };
}

export type WSFrame =
  | WSHello
  | WSDecisionFrame
  | WSFindingFrame
  | WSAgentSeenFrame
  | WSRoutingDecisionFrame;

// ---------------------------------------------------------------------------
// Router wire types — mirrors pkg/api/router.go
// ---------------------------------------------------------------------------

export interface ClassifierOutput {
  task: string;         // "code"|"classification"|"rag"|"summarization"|"conversation"|"vision"|"other"
  complexity: string;   // "low"|"medium"|"high"
  capabilities: string[];
  reasoning: string;
}

export interface RoutingDecision {
  ts: string;
  request_id: string;
  schema_version: number;

  // Classifier stage
  classifier_model: string;
  classifier_latency_ms: number;
  classifier_cost_usd: number;
  classifier_output: ClassifierOutput;
  classifier_failed?: boolean;
  classifier_fail_reason?: string;

  // Policy match
  matched_rule_name: string;
  target_model: string;
  fallbacks_tried?: string[];

  // Forward stage
  forward_latency_ms: number;
  forward_cost_usd: number;
  prompt_tokens: number;
  completion_tokens: number;

  // Totals
  total_latency_ms: number;
  total_cost_usd: number;
  baseline_cost_usd: number;
  savings_usd: number;

  // Error
  error?: string;
}

export interface RouterPolicyView {
  schema_version: number;
  classifier: {
    model: string;
    timeout_ms: number;
    max_tokens: number;
  };
  baseline: { model: string };
  routes: Array<{
    name: string;
    if?: {
      task?: string | string[];
      complexity?: string | string[];
      capabilities_include?: string | string[];
      capabilities_all?: string[];
      messages_min_length?: number;
      messages_total_tokens_gt?: number;
    };
    target: string;
    fallback?: string[];
    reason?: string;
  }>;
  default: {
    target: string;
    fallback?: string[];
    reason?: string;
  };
}

export interface RouterStats {
  window_seconds: number;
  total_calls: number;
  total_cost_usd: number;
  baseline_cost_usd: number;
  savings_usd: number;
  savings_pct: number;
  avg_classifier_ms: number;
  avg_forward_ms: number;
  avg_total_ms: number;
  per_task: Record<string, number>;
  per_model: Record<string, { count: number; cost_usd: number; avg_latency_ms: number }>;
}

export interface RouterDecisionsResponse {
  items: RoutingDecision[];
  next_since?: string;
  has_more: boolean;
}

export interface RouterPolicyPutResponse {
  ok: boolean;
  message?: string;
  errors?: string[];
}

export interface WSRoutingDecisionFrame {
  type: "routing_decision";
  data: RoutingDecision;
}
