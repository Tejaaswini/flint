/**
 * Mock data fixtures for all API endpoints.
 * Used when USE_MOCK=true in client.ts.
 * All data is deterministic and self-consistent.
 */

import type {
  Agent,
  AgentDetail,
  Binding,
  Connection,
  ConnectionDetail,
  DecisionRow,
  DecisionsResponse,
  EffectivePermission,
  FindingRow,
  Role,
  RolePutResponse,
  RouterDecisionsResponse,
  RouterPolicyPutResponse,
  RouterPolicyView,
  RouterStats,
  RoutingDecision,
  Session,
  ToolEntry,
  WSDecisionFrame,
  WSFindingFrame,
  WSRoutingDecisionFrame,
} from "./types";

// ─── Agents ──────────────────────────────────────────────────────────────────

export const MOCK_AGENTS: Agent[] = [
  {
    id: "support-bot",
    roles: ["support-read", "github-viewer"],
    scopes: ["customer_data", "support"],
    discoverable_tools: 12,
    invokable_tools: 8,
    recent_denied_count: 3,
    last_seen_at: new Date(Date.now() - 45_000).toISOString(),
  },
  {
    id: "code-agent",
    roles: ["dev-full", "github-viewer"],
    scopes: ["codebase", "ci"],
    discoverable_tools: 20,
    invokable_tools: 18,
    recent_denied_count: 1,
    last_seen_at: new Date(Date.now() - 120_000).toISOString(),
  },
  {
    id: "crm-agent",
    roles: ["crm-admin"],
    scopes: ["crm", "customer_data"],
    discoverable_tools: 7,
    invokable_tools: 7,
    recent_denied_count: 0,
    last_seen_at: new Date(Date.now() - 3_600_000).toISOString(),
  },
];

const supportPerms: EffectivePermission[] = [
  {
    tool_name: "github.search_code",
    server: "github",
    verb: "invoke",
    lens: "read",
    granted_by_roles: ["github-viewer"],
    constraints: [],
    denied_by_role: "",
  },
  {
    tool_name: "github.create_issue",
    server: "github",
    verb: "invoke",
    lens: "write",
    granted_by_roles: ["support-read"],
    constraints: ["sql_intent in [select]"],
    denied_by_role: "",
  },
  {
    tool_name: "github.delete_branch",
    server: "github",
    verb: "invoke",
    lens: "admin",
    granted_by_roles: [],
    constraints: [],
    denied_by_role: "github-admin-guard",
  },
  {
    tool_name: "db.query",
    server: "db",
    verb: "invoke",
    lens: "read",
    granted_by_roles: ["support-read"],
    constraints: ["sql_intent in [select, with]"],
    denied_by_role: "",
  },
  {
    tool_name: "slack.post_message",
    server: "slack",
    verb: "invoke",
    lens: "write",
    granted_by_roles: ["support-read"],
    constraints: [],
    denied_by_role: "",
  },
];

export const MOCK_AGENT_DETAILS: Record<string, AgentDetail> = {
  "support-bot": {
    ...MOCK_AGENTS[0],
    effective_permissions: supportPerms,
    recent_denials: [],
  },
  "code-agent": {
    ...MOCK_AGENTS[1],
    effective_permissions: [
      {
        tool_name: "github.search_code",
        server: "github",
        verb: "invoke",
        lens: "read",
        granted_by_roles: ["github-viewer", "dev-full"],
        constraints: [],
        denied_by_role: "",
      },
      {
        tool_name: "github.push_commit",
        server: "github",
        verb: "invoke",
        lens: "write",
        granted_by_roles: ["dev-full"],
        constraints: [],
        denied_by_role: "",
      },
      {
        tool_name: "github.delete_repo",
        server: "github",
        verb: "invoke",
        lens: "admin",
        granted_by_roles: [],
        constraints: [],
        denied_by_role: "github-admin-guard",
      },
    ],
    recent_denials: [],
  },
  "crm-agent": {
    ...MOCK_AGENTS[2],
    effective_permissions: [
      {
        tool_name: "crm.list_contacts",
        server: "crm",
        verb: "invoke",
        lens: "read",
        granted_by_roles: ["crm-admin"],
        constraints: [],
        denied_by_role: "",
      },
      {
        tool_name: "crm.update_contact",
        server: "crm",
        verb: "invoke",
        lens: "write",
        granted_by_roles: ["crm-admin"],
        constraints: [],
        denied_by_role: "",
      },
    ],
    recent_denials: [],
  },
};

// ─── Connections ──────────────────────────────────────────────────────────────

export const MOCK_CONNECTIONS: Connection[] = [
  {
    name: "everything",
    command: ["npx", "-y", "@modelcontextprotocol/server-everything"],
    status: "connected",
    tool_count: 14,
    last_call_at: new Date(Date.now() - 12_000).toISOString(),
    p50_latency_ms: 42.5,
  },
  {
    name: "filesystem-mock",
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    status: "degraded",
    tool_count: 6,
    last_call_at: new Date(Date.now() - 300_000).toISOString(),
    p50_latency_ms: 8.1,
  },
];

const everythingTools: ToolEntry[] = [
  { name: "echo", tags: [], scope: "public", payload_class: "standard", classification: "read" },
  { name: "add", tags: [], scope: "public", payload_class: "standard", classification: "read" },
  { name: "printEnv", tags: ["internal_write"], scope: "internal", payload_class: "standard", classification: "write" },
  { name: "longRunningOperation", tags: [], scope: "public", payload_class: "standard", classification: "read" },
  { name: "sampleLLM", tags: ["network_egress"], scope: "public", payload_class: "standard", classification: "write" },
  { name: "getTinyImage", tags: [], scope: "public", payload_class: "standard", classification: "read" },
  { name: "github.search_code", tags: [], scope: "public", payload_class: "standard", classification: "read" },
  { name: "github.create_issue", tags: ["internal_write"], scope: "public", payload_class: "standard", classification: "write" },
  { name: "github.delete_branch", tags: ["admin"], scope: "restricted", payload_class: "standard", classification: "admin" },
  { name: "github.push_commit", tags: ["internal_write"], scope: "public", payload_class: "standard", classification: "write" },
  { name: "db.query", tags: [], scope: "internal", payload_class: "standard", classification: "read" },
  { name: "db.execute", tags: ["internal_write"], scope: "internal", payload_class: "restricted", classification: "write" },
  { name: "slack.post_message", tags: ["network_egress"], scope: "public", payload_class: "standard", classification: "write" },
  { name: "slack.delete_message", tags: ["admin", "network_egress"], scope: "internal", payload_class: "standard", classification: "admin" },
];

const filesystemTools: ToolEntry[] = [
  { name: "read_file", tags: [], scope: "public", payload_class: "standard", classification: "read" },
  { name: "write_file", tags: ["internal_write"], scope: "public", payload_class: "standard", classification: "write" },
  { name: "list_directory", tags: [], scope: "public", payload_class: "standard", classification: "read" },
  { name: "delete_file", tags: ["admin", "internal_write"], scope: "restricted", payload_class: "standard", classification: "admin" },
  { name: "create_directory", tags: ["internal_write"], scope: "public", payload_class: "standard", classification: "write" },
  { name: "search_files", tags: [], scope: "public", payload_class: "standard", classification: "read" },
];

export const MOCK_CONNECTION_DETAILS: Record<string, ConnectionDetail> = {
  everything: {
    ...MOCK_CONNECTIONS[0],
    tools: everythingTools,
  },
  "filesystem-mock": {
    ...MOCK_CONNECTIONS[1],
    tools: filesystemTools,
  },
};

// ─── Roles ────────────────────────────────────────────────────────────────────

export const MOCK_ROLES: Role[] = [
  {
    name: "support-read",
    rules: [
      {
        name: "Allow read-only DB queries",
        effect: "allow",
        resources: ["db.query"],
        verbs: ["invoke"],
        constraints: { sql_intent: ["select", "with"] },
      },
      {
        name: "Allow Slack messaging",
        effect: "allow",
        resources: ["slack.post_message"],
        verbs: ["invoke"],
      },
      {
        effect: "allow",
        resources: ["github.create_issue"],
        verbs: ["invoke"],
      },
    ],
  },
  {
    name: "github-viewer",
    rules: [
      {
        name: "Allow GitHub searches",
        effect: "allow",
        resources: ["server:github"],
        verbs: ["discover", "invoke"],
        constraints: {},
      },
    ],
  },
  {
    name: "github-admin-guard",
    rules: [
      {
        name: "Block destructive GitHub ops",
        effect: "deny",
        resources: ["github.delete_branch", "github.delete_repo", "github.force_push"],
        verbs: ["invoke"],
      },
    ],
  },
  {
    name: "dev-full",
    rules: [
      {
        name: "Allow all GitHub tools",
        effect: "allow",
        resources: ["server:github"],
        verbs: ["invoke", "discover"],
      },
      {
        effect: "allow",
        resources: ["*"],
        verbs: ["discover"],
      },
    ],
  },
  {
    name: "crm-admin",
    rules: [
      {
        name: "Full CRM access",
        effect: "allow",
        resources: ["server:crm"],
        verbs: ["invoke", "discover", "admin"],
      },
    ],
  },
  {
    name: "deny-all-db-writes",
    rules: [
      {
        name: "Block all DB mutations",
        effect: "deny",
        resources: ["db.execute", "db.delete", "db.update"],
        verbs: ["invoke"],
      },
    ],
  },
];

// ─── Bindings ─────────────────────────────────────────────────────────────────

export const MOCK_BINDINGS: Binding[] = [
  { agent: "support-bot", roles: ["support-read", "github-viewer"], scopes: ["customer_data", "support"] },
  { agent: "code-agent", roles: ["dev-full", "github-viewer"], scopes: ["codebase", "ci"] },
  { agent: "crm-agent", roles: ["crm-admin"], scopes: ["crm", "customer_data"] },
];

// ─── Sessions ─────────────────────────────────────────────────────────────────

export const MOCK_SESSIONS: Session[] = [
  {
    id: "gw-1716210129000000000",
    agent_id: "support-bot",
    started_at: new Date(Date.now() - 600_000).toISOString(),
    event_count: 24,
    denied_count: 3,
    findings_count: 1,
    risk_score: 0.35,
    disposition: "active",
  },
  {
    id: "gw-1716209500000000000",
    agent_id: "code-agent",
    started_at: new Date(Date.now() - 1_800_000).toISOString(),
    event_count: 41,
    denied_count: 1,
    findings_count: 0,
    risk_score: 0.12,
    disposition: "closed",
  },
  {
    id: "gw-1716208000000000000",
    agent_id: "crm-agent",
    started_at: new Date(Date.now() - 7_200_000).toISOString(),
    event_count: 15,
    denied_count: 0,
    findings_count: 0,
    risk_score: 0.05,
    disposition: "closed",
  },
];

// ─── Decisions ────────────────────────────────────────────────────────────────

function makeDecision(
  overrides: Partial<DecisionRow> & { ts?: string }
): DecisionRow {
  return {
    ts: new Date(Date.now() - Math.random() * 3_600_000).toISOString(),
    session_id: "gw-1716210129000000000",
    agent_id: "support-bot",
    tool_name: "echo",
    direction: "request",
    allowed: true,
    reason: "allow",
    constraint: "",
    matched_role: "support-read",
    matched_rule: 0,
    matched_rule_name: "",
    required_verb: "invoke",
    granted_verb: "invoke",
    evaluated_scopes: ["support"],
    latency_ms: null,
    request_id: String(Math.floor(Math.random() * 1000)),
    event_seq: Math.floor(Math.random() * 100),
    payload_excerpt: "",
    findings: [],
    schema_version: 1,
    ...overrides,
  };
}

export const MOCK_DECISIONS: DecisionRow[] = [
  makeDecision({ tool_name: "echo", allowed: true, matched_role: "support-read", matched_rule_name: "Allow read-only DB queries", event_seq: 1, ts: new Date(Date.now() - 10_000).toISOString() }),
  makeDecision({ tool_name: "db.query", allowed: true, matched_role: "support-read", matched_rule_name: "Allow read-only DB queries", event_seq: 2, ts: new Date(Date.now() - 30_000).toISOString(), payload_excerpt: "SELECT * FROM tickets WHERE status='open'" }),
  makeDecision({ tool_name: "github.delete_branch", allowed: false, reason: "explicit_deny", matched_role: "github-admin-guard", matched_rule_name: "Block destructive GitHub ops", event_seq: 3, agent_id: "support-bot", ts: new Date(Date.now() - 60_000).toISOString() }),
  makeDecision({ tool_name: "slack.post_message", allowed: true, matched_role: "support-read", matched_rule_name: "Allow Slack messaging", event_seq: 4, ts: new Date(Date.now() - 90_000).toISOString() }),
  makeDecision({ tool_name: "db.execute", allowed: false, reason: "explicit_deny", matched_role: "deny-all-db-writes", matched_rule_name: "Block all DB mutations", event_seq: 5, agent_id: "code-agent", session_id: "gw-1716209500000000000", ts: new Date(Date.now() - 120_000).toISOString(), payload_excerpt: "DELETE FROM users WHERE id=42" }),
  makeDecision({ tool_name: "github.search_code", allowed: true, matched_role: "github-viewer", event_seq: 6, agent_id: "code-agent", session_id: "gw-1716209500000000000", ts: new Date(Date.now() - 150_000).toISOString() }),
  makeDecision({ tool_name: "github.push_commit", allowed: true, matched_role: "dev-full", matched_rule_name: "Allow all GitHub tools", event_seq: 7, agent_id: "code-agent", session_id: "gw-1716209500000000000", ts: new Date(Date.now() - 180_000).toISOString() }),
  makeDecision({ tool_name: "crm.list_contacts", allowed: true, matched_role: "crm-admin", matched_rule_name: "Full CRM access", event_seq: 8, agent_id: "crm-agent", session_id: "gw-1716208000000000000", ts: new Date(Date.now() - 3_600_000).toISOString() }),
  makeDecision({ tool_name: "db.query", allowed: true, matched_role: "support-read", event_seq: 9, ts: new Date(Date.now() - 200_000).toISOString(), direction: "response", latency_ms: 38.2 }),
  makeDecision({ tool_name: "longRunningOperation", allowed: true, matched_role: "dev-full", event_seq: 10, agent_id: "code-agent", session_id: "gw-1716209500000000000", ts: new Date(Date.now() - 240_000).toISOString(), latency_ms: 1240.5, direction: "response" }),
  makeDecision({ tool_name: "sampleLLM", allowed: false, reason: "no_matching_rule", event_seq: 11, agent_id: "support-bot", ts: new Date(Date.now() - 280_000).toISOString() }),
  makeDecision({ tool_name: "echo", allowed: true, event_seq: 12, ts: new Date(Date.now() - 300_000).toISOString(), direction: "response", latency_ms: 12.1 }),
  makeDecision({ tool_name: "github.create_issue", allowed: true, matched_role: "support-read", event_seq: 13, ts: new Date(Date.now() - 320_000).toISOString() }),
  makeDecision({ tool_name: "db.query", allowed: false, reason: "constraint_violation", constraint: "sql_intent=delete", event_seq: 14, ts: new Date(Date.now() - 360_000).toISOString(), payload_excerpt: "DELETE FROM audit_log WHERE ts < '2024-01-01'" }),
  makeDecision({ tool_name: "slack.post_message", allowed: true, event_seq: 15, ts: new Date(Date.now() - 400_000).toISOString(), direction: "response", latency_ms: 55.0 }),
  // More decisions for richer fixture
  makeDecision({ tool_name: "echo", allowed: true, event_seq: 16, ts: new Date(Date.now() - 420_000).toISOString() }),
  makeDecision({ tool_name: "add", allowed: true, event_seq: 17, ts: new Date(Date.now() - 440_000).toISOString() }),
  makeDecision({ tool_name: "getTinyImage", allowed: true, event_seq: 18, ts: new Date(Date.now() - 460_000).toISOString() }),
  makeDecision({ tool_name: "github.delete_repo", allowed: false, reason: "explicit_deny", matched_role: "github-admin-guard", matched_rule_name: "Block destructive GitHub ops", event_seq: 19, agent_id: "code-agent", session_id: "gw-1716209500000000000", ts: new Date(Date.now() - 480_000).toISOString() }),
  makeDecision({ tool_name: "crm.update_contact", allowed: true, matched_role: "crm-admin", matched_rule_name: "Full CRM access", event_seq: 20, agent_id: "crm-agent", session_id: "gw-1716208000000000000", ts: new Date(Date.now() - 3_800_000).toISOString() }),
  // Decisions with findings
  makeDecision({
    tool_name: "db.query",
    allowed: true,
    event_seq: 21,
    direction: "response",
    latency_ms: 92.3,
    ts: new Date(Date.now() - 500_000).toISOString(),
    payload_excerpt: "SELECT credit_card_number FROM users",
    findings: [{ rule_id: "pii_relay", severity: "high", score: 80, message: "Possible PII exfiltration in query result" }],
  }),
  makeDecision({ tool_name: "printEnv", allowed: true, event_seq: 22, ts: new Date(Date.now() - 520_000).toISOString() }),
  makeDecision({ tool_name: "echo", allowed: true, event_seq: 23, ts: new Date(Date.now() - 540_000).toISOString() }),
  makeDecision({ tool_name: "github.search_code", allowed: true, event_seq: 24, ts: new Date(Date.now() - 560_000).toISOString() }),
  makeDecision({ tool_name: "db.execute", allowed: false, reason: "explicit_deny", event_seq: 25, ts: new Date(Date.now() - 580_000).toISOString() }),
  makeDecision({ tool_name: "slack.post_message", allowed: true, event_seq: 26, ts: new Date(Date.now() - 600_000).toISOString() }),
  makeDecision({ tool_name: "crm.list_contacts", allowed: true, event_seq: 27, agent_id: "crm-agent", session_id: "gw-1716208000000000000", ts: new Date(Date.now() - 3_900_000).toISOString() }),
  makeDecision({ tool_name: "echo", allowed: true, event_seq: 28, ts: new Date(Date.now() - 620_000).toISOString() }),
  makeDecision({ tool_name: "github.push_commit", allowed: true, agent_id: "code-agent", session_id: "gw-1716209500000000000", event_seq: 29, ts: new Date(Date.now() - 640_000).toISOString() }),
  makeDecision({ tool_name: "add", allowed: true, event_seq: 30, ts: new Date(Date.now() - 660_000).toISOString() }),
  // 20 more for a total of 50
  ...Array.from({ length: 20 }, (_, i) => makeDecision({
    event_seq: 31 + i,
    ts: new Date(Date.now() - (680_000 + i * 20_000)).toISOString(),
    tool_name: ["echo", "db.query", "github.search_code", "slack.post_message", "add"][i % 5],
    allowed: i % 7 !== 0,
    reason: i % 7 === 0 ? "explicit_deny" : "allow",
    matched_role: i % 7 === 0 ? "github-admin-guard" : "support-read",
  })),
];

// Populate recent_denials for agents
const denials = MOCK_DECISIONS.filter((d) => !d.allowed);
MOCK_AGENT_DETAILS["support-bot"].recent_denials = denials.filter(
  (d) => d.agent_id === "support-bot"
).slice(0, 20);
MOCK_AGENT_DETAILS["code-agent"].recent_denials = denials.filter(
  (d) => d.agent_id === "code-agent"
).slice(0, 20);

// ─── Mock roles store (mutable for PUT simulation) ───────────────────────────

let _rolesStore: Role[] = [...MOCK_ROLES];

export function getMockRoles(): Role[] {
  return _rolesStore;
}

export function putMockRole(name: string, role: Role): RolePutResponse {
  // Basic validation
  const errors: string[] = [];
  for (const rule of role.rules) {
    if (!["allow", "deny"].includes(rule.effect)) {
      errors.push(`Rule effect must be 'allow' or 'deny', got: ${rule.effect}`);
    }
    if (!rule.resources || rule.resources.length === 0) {
      errors.push("Each rule must have at least one resource");
    }
    if (!rule.verbs || rule.verbs.length === 0) {
      errors.push("Each rule must have at least one verb");
    }
  }
  if (errors.length > 0) {
    return { ok: false, errors };
  }
  const idx = _rolesStore.findIndex((r) => r.name === name);
  if (idx >= 0) {
    _rolesStore = _rolesStore.map((r) => (r.name === name ? role : r));
  } else {
    _rolesStore = [..._rolesStore, role];
  }
  return { ok: true };
}

// ─── Mock WebSocket event emitter ─────────────────────────────────────────────

type WSEventListener = (frame: WSDecisionFrame | WSFindingFrame) => void;
const wsListeners = new Set<WSEventListener>();

const LIVE_TOOLS = [
  "echo", "db.query", "github.search_code", "slack.post_message",
  "add", "github.push_commit", "crm.list_contacts", "longRunningOperation",
];
const LIVE_AGENTS = ["support-bot", "code-agent", "crm-agent"];
const LIVE_SESSIONS = [
  "gw-1716210129000000000",
  "gw-1716209500000000000",
  "gw-1716208000000000000",
];

let _liveSeq = 100;
let _liveInterval: ReturnType<typeof setInterval> | null = null;

function startLiveEmitter() {
  if (_liveInterval) return;
  _liveInterval = setInterval(() => {
    if (wsListeners.size === 0) return;
    _liveSeq++;
    const toolIdx = _liveSeq % LIVE_TOOLS.length;
    const agentIdx = Math.floor(_liveSeq / 3) % LIVE_AGENTS.length;
    const sessionIdx = agentIdx;
    const isDeny = _liveSeq % 9 === 0;
    const isFinding = _liveSeq % 13 === 0;

    const decision: DecisionRow = {
      ts: new Date().toISOString(),
      session_id: LIVE_SESSIONS[sessionIdx],
      agent_id: LIVE_AGENTS[agentIdx],
      tool_name: LIVE_TOOLS[toolIdx],
      direction: "request",
      allowed: !isDeny,
      reason: isDeny ? "explicit_deny" : "allow",
      constraint: "",
      matched_role: isDeny ? "github-admin-guard" : "support-read",
      matched_rule: 0,
      matched_rule_name: isDeny ? "Block destructive GitHub ops" : "Allow read-only DB queries",
      required_verb: "invoke",
      granted_verb: isDeny ? "" : "invoke",
      evaluated_scopes: ["support"],
      latency_ms: isDeny ? null : Math.round(Math.random() * 200 * 10) / 10,
      request_id: String(_liveSeq),
      event_seq: _liveSeq,
      payload_excerpt: toolIdx === 1 ? "SELECT * FROM tickets LIMIT 10" : "",
      findings: isFinding
        ? [{ rule_id: "anomaly_burst", severity: "medium", score: 45, message: "Unusual call frequency" }]
        : [],
      schema_version: 1,
    };

    const decisionFrame: WSDecisionFrame = { type: "decision", data: decision };
    wsListeners.forEach((l) => l(decisionFrame));

    if (isFinding) {
      const findingFrame: WSFindingFrame = {
        type: "finding",
        data: {
          rule_id: "anomaly_burst",
          severity: "medium",
          score: 45,
          message: "Unusual call frequency",
          session_id: LIVE_SESSIONS[sessionIdx],
          event_seq: _liveSeq,
        },
      };
      setTimeout(() => wsListeners.forEach((l) => l(findingFrame)), 50);
    }
  }, 2000);
}

export function addWSListener(listener: WSEventListener): () => void {
  wsListeners.add(listener);
  startLiveEmitter();
  return () => wsListeners.delete(listener);
}

export function getMockDecisions(limit = 100, since?: string): DecisionsResponse {
  let items = [...MOCK_DECISIONS].sort(
    (a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()
  );
  if (since) {
    const sinceMs = new Date(since).getTime();
    items = items.filter((d) => new Date(d.ts).getTime() > sinceMs);
  }
  const sliced = items.slice(0, limit);
  const hasMore = items.length > limit;
  return {
    items: sliced,
    next_since: hasMore ? sliced[sliced.length - 1]?.ts : undefined,
    has_more: hasMore,
  };
}

// ---------------------------------------------------------------------------
// Router mock data
// ---------------------------------------------------------------------------

const TASK_TYPES = [
  "code",
  "classification",
  "rag",
  "summarization",
  "conversation",
  "vision",
  "other",
] as const;
type TaskType = (typeof TASK_TYPES)[number];

const COMPLEXITY_LEVELS = ["low", "medium", "high"] as const;

interface ModelSpec {
  model: string;
  promptPerM: number;
  completionPerM: number;
}

const MODEL_SPECS: ModelSpec[] = [
  { model: "openai/gpt-4o-mini", promptPerM: 0.15, completionPerM: 0.60 },
  { model: "anthropic/claude-sonnet-4.6", promptPerM: 3.00, completionPerM: 15.00 },
  { model: "anthropic/claude-haiku-4.5", promptPerM: 1.00, completionPerM: 5.00 },
  { model: "google/gemini-flash-latest", promptPerM: 1.50, completionPerM: 6.00 },
  { model: "meta-llama/llama-3.2-3b-instruct:free", promptPerM: 0.0, completionPerM: 0.0 },
  { model: "meta-llama/llama-3.2-3b-instruct", promptPerM: 0.051, completionPerM: 0.051 },
];

const BASELINE_SPEC: ModelSpec = { model: "openai/gpt-4o", promptPerM: 2.50, completionPerM: 10.00 };

const RULE_NAMES_BY_TASK: Record<TaskType, string> = {
  code: "High-complexity code",
  classification: "Cheap classification",
  rag: "Short conversation",
  summarization: "Summarization",
  conversation: "Short conversation",
  vision: "Vision requests",
  other: "<default>",
};

const MODEL_BY_TASK: Record<TaskType, ModelSpec> = {
  code: MODEL_SPECS[1],           // claude-sonnet-4.6
  classification: MODEL_SPECS[4], // llama free
  rag: MODEL_SPECS[0],            // gpt-4o-mini
  summarization: MODEL_SPECS[2],  // claude-haiku-4.5
  conversation: MODEL_SPECS[0],   // gpt-4o-mini
  vision: MODEL_SPECS[3],         // gemini-flash
  other: MODEL_SPECS[0],          // gpt-4o-mini
};

const REASONINGS: Record<TaskType, string> = {
  code: "User is requesting code generation or debugging — high complexity coding task.",
  classification: "User is asking to classify or label text — trivial single-step task.",
  rag: "User is asking a question grounded in a provided passage.",
  summarization: "User is requesting a summary of a longer piece of text.",
  conversation: "Open-ended conversational request without a specific task.",
  vision: "Request includes image content or asks to analyze a visual.",
  other: "Does not fit any category cleanly.",
};

const PROMPT_EXCERPTS: Record<TaskType, string> = {
  code: "Write a Python function that implements a binary search tree with insert, delete, and search operations.",
  classification: "Is this email spam? 'You won a free iPhone! Click here.'",
  rag: "Based on the following passage, what was the company's Q3 revenue?",
  summarization: "Summarize the following article in three bullet points.",
  conversation: "What's a good weekend trip from Berlin for under 200 euros?",
  vision: "I'm uploading a screenshot of an error dialog. Please describe what it says.",
  other: "Please help me with this unusual request.",
};

let _routingReqCounter = 1000;

function makeRoutingDecision(
  taskOverride?: TaskType,
  tsOffset?: number
): RoutingDecision {
  _routingReqCounter++;
  const task = taskOverride ?? TASK_TYPES[_routingReqCounter % TASK_TYPES.length];
  const complexityIdx = _routingReqCounter % COMPLEXITY_LEVELS.length;
  const complexity = COMPLEXITY_LEVELS[complexityIdx];
  const targetSpec = MODEL_BY_TASK[task];
  const capabilities: string[] = task === "vision" ? ["vision"] : task === "code" && complexity === "high" ? ["reasoning"] : [];

  const promptTokens = 80 + (_routingReqCounter % 400);
  const completionTokens = 20 + (_routingReqCounter % 200);

  const classifierLatencyMs = 350 + (_routingReqCounter % 500);
  const classifierCostUsd = (200 / 1_000_000) * 0.15 + (80 / 1_000_000) * 0.60;

  const forwardLatencyMs = 200 + (_routingReqCounter % 1200);
  const forwardCostUsd =
    (promptTokens / 1_000_000) * targetSpec.promptPerM +
    (completionTokens / 1_000_000) * targetSpec.completionPerM;

  const totalCostUsd = classifierCostUsd + forwardCostUsd;
  const baselineCostUsd =
    (promptTokens / 1_000_000) * BASELINE_SPEC.promptPerM +
    (completionTokens / 1_000_000) * BASELINE_SPEC.completionPerM;
  const savingsUsd = baselineCostUsd - totalCostUsd;

  return {
    ts: new Date(Date.now() - (tsOffset ?? Math.random() * 3_600_000)).toISOString(),
    request_id: `req-mock-${_routingReqCounter}`,
    schema_version: 1,
    classifier_model: "openai/gpt-4o-mini",
    classifier_latency_ms: classifierLatencyMs,
    classifier_cost_usd: classifierCostUsd,
    classifier_output: {
      task,
      complexity,
      capabilities,
      reasoning: REASONINGS[task],
    },
    matched_rule_name: RULE_NAMES_BY_TASK[task],
    target_model: targetSpec.model,
    forward_latency_ms: forwardLatencyMs,
    forward_cost_usd: forwardCostUsd,
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_latency_ms: classifierLatencyMs + forwardLatencyMs,
    total_cost_usd: totalCostUsd,
    baseline_cost_usd: baselineCostUsd,
    savings_usd: savingsUsd,
  };
}

export const MOCK_ROUTING_DECISIONS: RoutingDecision[] = [
  makeRoutingDecision("code", 10_000),
  makeRoutingDecision("classification", 25_000),
  makeRoutingDecision("rag", 50_000),
  makeRoutingDecision("summarization", 75_000),
  makeRoutingDecision("conversation", 100_000),
  makeRoutingDecision("vision", 130_000),
  makeRoutingDecision("code", 160_000),
  makeRoutingDecision("classification", 190_000),
  makeRoutingDecision("other", 220_000),
  makeRoutingDecision("code", 250_000),
  makeRoutingDecision("rag", 280_000),
  makeRoutingDecision("summarization", 310_000),
  makeRoutingDecision("conversation", 340_000),
  makeRoutingDecision("code", 370_000),
  makeRoutingDecision("classification", 400_000),
  makeRoutingDecision("vision", 430_000),
  makeRoutingDecision("rag", 460_000),
  makeRoutingDecision("code", 490_000),
  makeRoutingDecision("conversation", 520_000),
  makeRoutingDecision("other", 550_000),
  makeRoutingDecision("summarization", 580_000),
  makeRoutingDecision("classification", 610_000),
  makeRoutingDecision("code", 640_000),
  makeRoutingDecision("rag", 670_000),
  makeRoutingDecision("conversation", 700_000),
  makeRoutingDecision("vision", 730_000),
  makeRoutingDecision("code", 760_000),
  makeRoutingDecision("classification", 790_000),
  makeRoutingDecision("summarization", 820_000),
  makeRoutingDecision("other", 850_000),
];

export const MOCK_ROUTER_POLICY_RAW = `schema_version: 1

classifier:
  model: openai/gpt-4o-mini
  timeout_ms: 1500
  max_tokens: 150

routes:
  - name: "Vision requests"
    if:
      capabilities_include: vision
    target: google/gemini-flash-latest
    fallback: [openai/gpt-4o-mini]
    reason: "Gemini Flash handles vision cheaply with low latency."

  - name: "High-complexity code"
    if:
      task: code
      complexity: [medium, high]
    target: anthropic/claude-sonnet-4.6
    fallback: [anthropic/claude-haiku-4.5, openai/gpt-4o-mini]
    reason: "Sonnet 4.6 leads on multi-file code generation."

  - name: "Cheap classification"
    if:
      task: classification
      complexity: low
    target: meta-llama/llama-3.2-3b-instruct:free
    fallback: [meta-llama/llama-3.2-3b-instruct, openai/gpt-4o-mini]
    reason: "Free-tier 3B model for trivial labeling."

  - name: "Short conversation"
    if:
      task: conversation
      complexity: [low, medium]
    target: openai/gpt-4o-mini
    reason: "Default cheap model handles casual chat well."

  - name: "Summarization"
    if:
      task: summarization
    target: anthropic/claude-haiku-4.5
    fallback: [openai/gpt-4o-mini]
    reason: "Haiku is well-tuned for summarization at low cost."

default:
  target: openai/gpt-4o-mini
  fallback: [anthropic/claude-haiku-4.5]
  reason: "Reliable, cheap fallback for anything not matched."

baseline:
  model: openai/gpt-4o
`;

export const MOCK_ROUTER_POLICY: RouterPolicyView = {
  schema_version: 1,
  classifier: { model: "openai/gpt-4o-mini", timeout_ms: 1500, max_tokens: 150 },
  baseline: { model: "openai/gpt-4o" },
  routes: [
    {
      name: "Vision requests",
      if: { capabilities_include: "vision" },
      target: "google/gemini-flash-latest",
      fallback: ["openai/gpt-4o-mini"],
      reason: "Gemini Flash handles vision cheaply with low latency.",
    },
    {
      name: "High-complexity code",
      if: { task: "code", complexity: ["medium", "high"] },
      target: "anthropic/claude-sonnet-4.6",
      fallback: ["anthropic/claude-haiku-4.5", "openai/gpt-4o-mini"],
      reason: "Sonnet 4.6 leads on multi-file code generation.",
    },
    {
      name: "Cheap classification",
      if: { task: "classification", complexity: "low" },
      target: "meta-llama/llama-3.2-3b-instruct:free",
      fallback: ["meta-llama/llama-3.2-3b-instruct", "openai/gpt-4o-mini"],
      reason: "Free-tier 3B model for trivial labeling.",
    },
    {
      name: "Short conversation",
      if: { task: "conversation", complexity: ["low", "medium"] },
      target: "openai/gpt-4o-mini",
      reason: "Default cheap model handles casual chat well.",
    },
    {
      name: "Summarization",
      if: { task: "summarization" },
      target: "anthropic/claude-haiku-4.5",
      fallback: ["openai/gpt-4o-mini"],
      reason: "Haiku is well-tuned for summarization at low cost.",
    },
  ],
  default: {
    target: "openai/gpt-4o-mini",
    fallback: ["anthropic/claude-haiku-4.5"],
    reason: "Reliable, cheap fallback for anything not matched.",
  },
};

function computeMockRouterStats(): RouterStats {
  const decisions = MOCK_ROUTING_DECISIONS;
  const totalCalls = decisions.length;
  const totalCostUsd = decisions.reduce((s, d) => s + d.total_cost_usd, 0);
  const baselineCostUsd = decisions.reduce((s, d) => s + d.baseline_cost_usd, 0);
  const savingsUsd = baselineCostUsd - totalCostUsd;
  const savingsPct = baselineCostUsd > 0 ? (savingsUsd / baselineCostUsd) * 100 : 0;
  const avgClassifierMs = decisions.reduce((s, d) => s + d.classifier_latency_ms, 0) / totalCalls;
  const avgForwardMs = decisions.reduce((s, d) => s + d.forward_latency_ms, 0) / totalCalls;
  const avgTotalMs = decisions.reduce((s, d) => s + d.total_latency_ms, 0) / totalCalls;

  const perTask: Record<string, number> = {};
  const perModelMap: Record<string, { count: number; totalCost: number; totalLatency: number }> = {};
  for (const d of decisions) {
    const task = d.classifier_output.task;
    perTask[task] = (perTask[task] ?? 0) + 1;
    const m = d.target_model;
    if (!perModelMap[m]) perModelMap[m] = { count: 0, totalCost: 0, totalLatency: 0 };
    perModelMap[m].count++;
    perModelMap[m].totalCost += d.forward_cost_usd;
    perModelMap[m].totalLatency += d.total_latency_ms;
  }

  const perModel: RouterStats["per_model"] = {};
  for (const [model, stat] of Object.entries(perModelMap)) {
    perModel[model] = {
      count: stat.count,
      cost_usd: stat.totalCost,
      avg_latency_ms: stat.totalLatency / stat.count,
    };
  }

  return {
    window_seconds: 3600,
    total_calls: totalCalls,
    total_cost_usd: totalCostUsd,
    baseline_cost_usd: baselineCostUsd,
    savings_usd: savingsUsd,
    savings_pct: savingsPct,
    avg_classifier_ms: avgClassifierMs,
    avg_forward_ms: avgForwardMs,
    avg_total_ms: avgTotalMs,
    per_task: perTask,
    per_model: perModel,
  };
}

export const MOCK_ROUTER_STATS: RouterStats = computeMockRouterStats();

export function getMockRouterDecisions(
  limit = 100,
  since?: string
): RouterDecisionsResponse {
  let items = [...MOCK_ROUTING_DECISIONS].sort(
    (a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()
  );
  if (since) {
    const sinceMs = new Date(since).getTime();
    items = items.filter((d) => new Date(d.ts).getTime() > sinceMs);
  }
  const sliced = items.slice(0, limit);
  const hasMore = items.length > limit;
  return {
    items: sliced,
    next_since: hasMore ? sliced[sliced.length - 1]?.ts : undefined,
    has_more: hasMore,
  };
}

export function putMockRouterPolicy(
  _yaml: string
): RouterPolicyPutResponse {
  // Basic validation: must contain "schema_version" and "default"
  if (!_yaml.includes("schema_version") || !_yaml.includes("default")) {
    return {
      ok: false,
      errors: [
        "Missing required field: schema_version",
        "Missing required field: default.target",
      ],
    };
  }
  return { ok: true };
}

// ─── Mock Router WebSocket event emitter ─────────────────────────────────────

type RouterWSEventListener = (frame: WSRoutingDecisionFrame) => void;
const routerWsListeners = new Set<RouterWSEventListener>();

const LIVE_TASKS: TaskType[] = [
  "code",
  "classification",
  "rag",
  "summarization",
  "conversation",
  "vision",
  "other",
];
let _liveRoutingSeq = 2000;
let _liveRoutingInterval: ReturnType<typeof setInterval> | null = null;

function startRouterLiveEmitter() {
  if (_liveRoutingInterval) return;
  _liveRoutingInterval = setInterval(() => {
    if (routerWsListeners.size === 0) return;
    _liveRoutingSeq++;
    const task = LIVE_TASKS[_liveRoutingSeq % LIVE_TASKS.length];
    const decision = makeRoutingDecision(task, 0);
    // Override ts to now
    decision.ts = new Date().toISOString();
    decision.request_id = `req-live-${_liveRoutingSeq}`;

    const frame: WSRoutingDecisionFrame = { type: "routing_decision", data: decision };
    routerWsListeners.forEach((l) => l(frame));
  }, 2500);
}

export function addRouterWSListener(listener: RouterWSEventListener): () => void {
  routerWsListeners.add(listener);
  startRouterLiveEmitter();
  return () => routerWsListeners.delete(listener);
}
