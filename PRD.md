# Flint — Product Requirements Document

**Version:** 1.0
**Date:** 2026-04-22
**Status:** Active

---

## Executive Summary

Flint is an inline MCP (Model Context Protocol) security gateway. It sits between AI agents and MCP servers, enforcing Kubernetes-style RBAC and behavioral analysis on every tool call — in real time, with zero changes to the upstream MCP server or the agent.

The core value proposition: **you attach Flint to any existing MCP server and immediately get per-agent access control, audit trails, and behavioral anomaly detection.** No forking. No config changes on the MCP server. No SDK modifications.

---

## Problem

MCP servers expose powerful tools (database queries, filesystem access, CRM lookups, code execution) to AI agents. Today there is no standard mechanism to:

1. Restrict which agents can call which tools
2. Constrain what arguments those calls can use (e.g., only SELECT queries, only `/workspace/` paths)
3. Record a complete, tamper-evident audit trail of every tool call
4. Detect behavioral anomalies (data exfiltration, scope hopping, probing) in real time
5. Filter the tool list an agent sees so it can't discover tools it has no access to

The result: every agent that can reach an MCP server has unrestricted access to every tool it exposes, with no logging and no enforcement.

---

## Solution

Flint is a transparent proxy. The agent talks to Flint; Flint talks to the MCP server. Every `tools/call` passes through `Evaluate()` before reaching upstream. Denied calls return a JSON-RPC error to the agent and are never sent upstream.

```
Agent  ──JSON-RPC──►  Flint Gateway  ──JSON-RPC──►  MCP Server
                           │
                    Evaluate() [RBAC]
                    Behavioral Engine
                    Audit Trail
```

---

## Goals

### Phase 1 (RBAC Core) — Complete the authorization library
- `engine/authz` is a fully tested, production-ready Go package
- Every reason code has an explicit test
- Policy loading validates all errors in a single pass
- The gateway proxy (`cmd/gateway`) works end-to-end against any stdio MCP server

### Phase 2 (Gateway + Management) — Make it operable
- Operators can attach Flint to any existing MCP server with a single command
- RBAC config can be managed without restarting the gateway (hot reload)
- Per-agent permission summary is queryable via CLI or API
- `tools/list` filtering is working (agents only see tools they can discover)

### Phase 3 (Multi-Server + UI) — Scale to real deployments
- Single Flint gateway can front multiple upstream MCP servers
- Web UI for policy management (create/edit roles, bindings, scopes)
- Real-time event dashboard (decisions, findings, risk scores)
- Export audit trail to JSONL, S3, or webhook

---

## Non-Goals (v1)

- ABAC (attribute-based access control) — RBAC covers v1 scope; constraints handle fine-grained argument checks
- Explicit deny rules — additive grants only; to restrict, create a role that excludes the tool
- Role inheritance — flat roles, explicit bindings; no role-of-roles
- Multi-tenant policy namespacing — single policy file per gateway instance for now
- Rate limiting — not in scope; separate concern
- mTLS between gateway and upstream — transport security is out of scope for v1

---

## Architecture

### Component Map

```
flint/
├── engine/
│   ├── session/
│   │   ├── types.go          ← PolicyDecision, SessionEvent, Verb constants
│   │   └── registry.go       ← Tool registry (tags → verb inference)
│   ├── authz/
│   │   ├── loader.go         ← LoadPolicy() — reads roles.yaml + bindings.yaml
│   │   ├── authz.go          ← Evaluate() — pure function, no I/O
│   │   ├── discover.go       ← CanDiscover() — tools/list filtering
│   │   └── authz_test.go     ← All tests
│   ├── fingerprint/          ← Behavioral fingerprinting
│   ├── lineage/              ← Call chain lineage
│   ├── risk/                 ← Risk scoring
│   ├── rules/                ← Behavioral rules
│   └── engine.go             ← ProcessEvent() — wires RBAC + behavioral engine
├── cmd/
│   ├── gateway/
│   │   ├── main.go           ← CLI entry point
│   │   └── proxy.go          ← MCP proxy (fromAgent, fromUpstream)
│   └── replay/               ← Trace replay for testing
└── config/
    ├── roles.yaml
    └── bindings.yaml
```

### Data Flow

```
Agent tools/call
      │
      ▼
proxy.fromAgent()
      │
      ├─ parse JSON-RPC message
      ├─ build SessionEvent (agentID, toolName, payload, timestamp, seq)
      │
      ▼
engine.ProcessEvent()
      │
      ├─ authz.Evaluate(policy, agentID, evt) → PolicyDecision
      │       │
      │       ├─ nil policy → allowed (passthrough/dev mode)
      │       ├─ no binding → denied (no_binding)
      │       ├─ scope mismatch → denied (scope_mismatch)
      │       ├─ no matching rule → denied (no_matching_rule)
      │       ├─ verb too low → denied (verb_insufficient)
      │       ├─ constraint fail → denied (constraint_violation)
      │       └─ all pass → allowed
      │
      ├─ record PolicyDecision in SessionState
      │
      ├─ if denied → DeniedRequestIDs[requestID] = true
      │              return (no behavioral engine)
      │
      └─ if allowed → lineage, fingerprint, rules, risk scoring
                      return Findings

proxy.handleToolsCall()
      │
      ├─ if denied → JSON-RPC error -32001 "flint: <reason>"
      └─ if allowed → forward to upstream MCP server
```

---

## Permission Model

### Concepts

| Concept | What it is |
|---------|-----------|
| Agent | Named identity. `support-bot`, `code-agent`. The unit of authorization. |
| Role | Reusable bundle of rules. Rules name resources, grant verbs, optionally constrain arguments. |
| Binding | Connects an agent to a list of roles within a set of scopes. |
| Scope | Isolation boundary. `database`, `customer_data`, `support`. Binding must include event scope or `*`. |
| Rule | Resources (tool names or `*`) + MaxVerb + optional argument constraints. |

### Verb Hierarchy

```
discover(0) < read(1) < write(2) < execute(3) < admin(4)
```

Higher verbs imply lower ones. A grant of `execute` satisfies `read` and `discover` requirements. Default deny — no binding means no access.

**Practical mapping for v1:**
- `discover` — agent can see the tool in `tools/list` but cannot call it
- `read` — agent can call the tool (inferred for most tools)
- `execute` — required for tools tagged `external_write` or `network_egress`
- `write` — reserved for future internal mutation semantics
- `admin` — reserved for management operations

### Constraints

Argument-level restrictions on top of verb grants.

| Constraint | What it checks | Fields it inspects |
|------------|---------------|-------------------|
| `sql_intent` | First keyword of the query field | `query`, `sql` |
| `path_prefix` | Path field must start with an allowed prefix | `path`, `file`, `filepath`, `file_path`, `filename` |

**Evaluation rules:**
- AND across constraint types — all must pass
- OR within a type — any entry in the allowlist passes
- Missing field + strict mode (default) → `constraint_unverifiable` → denied
- Missing field + permissive mode → passes with warning logged
- Unknown constraint type → **load-time error** (not runtime)

### Reason Codes

Every `PolicyDecision` carries exactly one reason:

| Reason | Meaning |
|--------|---------|
| `allowed` | All checks passed |
| `no_policy` | No policy loaded — passthrough/dev mode |
| `no_principal` | Empty `agentID` — unauthenticated |
| `no_binding` | Agent has no binding entry |
| `scope_mismatch` | Event scope not in agent's binding scopes |
| `no_matching_rule` | Tool not covered by any rule in agent's roles |
| `verb_insufficient` | Tool covered but grant level too low |
| `constraint_violation` | Verb sufficient but argument constraint failed |
| `constraint_unverifiable` | Constraint couldn't be checked (missing field, strict mode) |

**Denial precedence** (when multiple denials from different rules):
```
1. constraint_unverifiable  (strictest signal)
2. constraint_violation
3. verb_insufficient
4. no_matching_rule         (loosest signal)
```

---

## Detailed Requirements

### Phase 1 — RBAC Library Completion

**Status: ~80% done. Gaps documented in `plan.md`.**

#### P1.1 — Complete Test Coverage

Every reason code must have at least one explicit named test in `TestEvaluate`:

- [x] `allowed`
- [x] `no_policy`
- [x] `no_binding`
- [ ] `no_principal` — `agentID == ""` → denied, not passthrough
- [x] `scope_mismatch`
- [x] `no_matching_rule`
- [ ] `verb_insufficient` — resource matched, grant level too low
- [x] `constraint_violation`
- [ ] `constraint_unverifiable` — missing field + strict mode

Critical correctness tests (none currently exist):

- [ ] **Additive roles**: role A constraint fails, role B allows → `allowed`
- [ ] **Additive roles**: role A verb insufficient, role B sufficient → `allowed`
- [ ] **Denial precedence**: role A `verb_insufficient`, role B `constraint_violation` → reported as `constraint_violation`
- [ ] **Duplicate agent bindings**: two entries for same agent → roles and scopes merged
- [ ] **Scope normalization**: `Customer_Data` binding matches `customer_data` event scope
- [ ] **Discover-only role**: role with `MaxVerb=discover` attempting invoke → `verb_insufficient`
- [ ] **Empty scope on event**: event with no scope, binding with explicit scopes → `scope_mismatch`
- [ ] **Wildcard scope**: binding `scopes: ["*"]` allows any event scope — isolated test
- [ ] **Path prefix second alias**: `file_path` field hit (not just `path`)
- [ ] **Path prefix no alias**: no recognized path field → `constraint_unverifiable`
- [ ] **`MatchedRole` and `MatchedRule`** populated on allow decision
- [ ] **`GrantedVerb`** populated on `verb_insufficient` denial

#### P1.2 — Loader Fixes

- [ ] **Unknown constraint type at load time** → error (currently silently skipped at runtime)
- [ ] **Duplicate agent entries** → merge roles and scopes (currently last-write-wins silently)
- [ ] **Collect all validation errors** — use `errors.Join`; don't fail on first non-structural error
- [ ] **`TestLoadPolicy/compiled_contents`** — verify `MaxVerb`, constraint values, resource sets, not just counts
- [ ] **Validate at load time**: invalid verb names, empty resource lists, empty agent names

#### P1.3 — Evaluator Fixes

- [ ] **Unknown constraint → fail closed**: add `default: return false` to `evalConstraints` switch
- [ ] **`constraint_unverifiable`**: missing payload field in strict mode produces this reason, not a pass
- [ ] **`agentID == ""`** → `no_principal` denial, not passthrough (currently passthrough in existing code)
- [ ] **`GrantedVerb` on all denials**: `constraint_violation` and `no_matching_rule` cases should populate it consistently
- [ ] **`MatchedRole` + `MatchedRule`** in `PolicyDecision` struct and populated on allow

#### P1.4 — `write` Verb Decision

Pick one and document + test it:
- Option A: Define `internal_write` tag → maps to `write` in `inferVerb`
- Option B: Document `write` as reserved; add test confirming no tag produces it

#### P1.5 — Definition of Done

- [ ] `go test ./engine/authz/... -race -count=1` passes clean
- [ ] All four replay fixtures produce expected counts (see `plan.md` table)
- [ ] Every reason code has an explicit test
- [ ] Additive-roles path confirmed by test
- [ ] Loader tests verify compiled field values
- [ ] Duplicate bindings handled and tested
- [ ] Unknown constraint types → load-time error, tested

---

### Phase 2 — Gateway + Management

**Status: Gateway proxy exists (`cmd/gateway`). Management layer not started.**

#### P2.1 — Gateway Hardening

- [ ] **Hot reload**: `SIGHUP` triggers `LoadPolicy()` without dropping connections in flight
- [ ] **Health check endpoint**: `GET /healthz` returns `{"status":"ok","policy_loaded":true,"agents":N}`
- [ ] **Startup validation**: if policy file exists but fails validation, exit 1 with all errors printed (don't start in passthrough mode silently)
- [ ] **Graceful shutdown**: `SIGTERM` drains in-flight requests before exit
- [ ] **Stderr structured logging**: replace `fmt.Fprintf(os.Stderr, ...)` with structured JSON log lines for production use

#### P2.2 — Attach to Existing MCPs

The primary use case: attach Flint to any stdio MCP server with one command.

```bash
# Before Flint
npx -y @modelcontextprotocol/server-everything

# After Flint (same server, now gated)
flint-gateway --agent support-bot \
  --roles config/roles.yaml \
  --bindings config/bindings.yaml \
  -- npx -y @modelcontextprotocol/server-everything
```

The MCP client (Claude Desktop, cursor, etc.) points to `flint-gateway` instead of the upstream server. The upstream command is unchanged.

**Requirements:**
- [ ] Works with any stdio MCP server (npx, python, binary)
- [ ] Passes through all non-`tools/call` messages transparently
- [ ] `tools/list` response filtered to only tools the agent has `discover` or higher on (already implemented via `CanDiscover`)
- [ ] Agent ID passed via `--agent` flag or `FLINT_AGENT_ID` env var
- [ ] Policy path defaults to `config/roles.yaml` + `config/bindings.yaml` relative to CWD

#### P2.3 — Permission Query CLI

```bash
# What can this agent do?
flint-policy check --agent support-bot --tool db.execute_sql --payload '{"query":"SELECT 1"}'
# → ALLOWED  reason=allowed  matched_role=sql-readonly  matched_rule=0

flint-policy check --agent support-bot --tool admin.delete_all
# → DENIED   reason=no_matching_rule

# List all tools an agent can call
flint-policy list-tools --agent support-bot
# → db.execute_sql (invoke, constraint: sql_intent=[select])
# → support.read_ticket (invoke)
# → crm.lookup_customer (invoke)

# List all agents and their roles
flint-policy list-agents
# → support-bot   roles=[sql-readonly, support-agent]  scopes=[customer_data, support]
# → code-agent    roles=[code-reader]                  scopes=[codebase]
```

#### P2.4 — Audit Log Export

- [ ] Every `PolicyDecision` written to JSONL file (configurable path, default `flint-audit.jsonl`)
- [ ] Each line is a self-contained JSON object — no context needed to read it
- [ ] Fields: `timestamp`, `session_id`, `agent_id`, `tool_name`, `required_verb`, `granted_verb`, `allowed`, `reason`, `constraint`, `matched_role`, `matched_rule`, `evaluated_scopes`
- [ ] Log rotation: new file per session or per day (configurable)

---

### Phase 3 — Multi-Server + UI

**Status: Not started. Design only.**

#### P3.1 — Multi-Server Gateway

Single `flint-gateway` process fronting multiple upstream MCP servers.

```yaml
# flint.yaml
servers:
  - name: everything
    command: ["npx", "-y", "@modelcontextprotocol/server-everything"]
  - name: filesystem
    command: ["python", "-m", "mcp_server_filesystem", "/workspace"]

agents:
  - id: support-bot
    servers: [everything]
  - id: code-agent
    servers: [filesystem]
```

One agent can reach multiple servers. The tool namespace is flat — tool names must be unique across all servers a given agent has access to (or prefixed by server name).

#### P3.2 — Management API

REST API for reading and writing policy at runtime.

```
GET  /api/v1/agents                    → list all agents with roles and scopes
GET  /api/v1/agents/:id/permissions    → list effective permissions for agent
POST /api/v1/agents/:id/check          → simulate Evaluate() for a given tool + payload
GET  /api/v1/roles                     → list all roles
POST /api/v1/roles                     → create role
PUT  /api/v1/roles/:name               → update role (hot-reloads policy)
GET  /api/v1/decisions?agent=&limit=   → recent PolicyDecisions
```

#### P3.3 — Web UI

- Agent list with permission summary
- Role editor (add/remove rules, set verbs, configure constraints)
- Binding editor (assign roles to agents, set scopes)
- Live decision feed (ALLOWED/DENIED stream, filterable by agent)
- Risk score dashboard per session
- Finding timeline with rule provenance

---

## Integration — Attaching to Existing MCPs

This is the core go-to-market motion. The integration is zero-change for the upstream server.

### Claude Desktop Integration

```json
// ~/.config/claude-desktop/claude_desktop_config.json  (macOS)
{
  "mcpServers": {
    "everything-gated": {
      "command": "flint-gateway",
      "args": [
        "--agent", "support-bot",
        "--roles", "/path/to/config/roles.yaml",
        "--bindings", "/path/to/config/bindings.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-everything"
      ]
    }
  }
}
```

### Cursor / VS Code Integration

Same pattern — any MCP host that accepts a `command` + `args` configuration works.

### Programmatic (SDK)

```go
policy, _ := authz.LoadPolicy("roles.yaml", "bindings.yaml")
eng := engine.New(sessionID, nil, policy)

evt := session.SessionEvent{
    AgentID:  "my-agent",
    ToolName: "db.execute_sql",
    Payload:  map[string]any{"query": "SELECT * FROM users"},
}
eng.ProcessEvent(evt)
```

---

## Config Reference

### `roles.yaml`

```yaml
roles:
  - name: sql-readonly
    rules:
      - resources: ["db.execute_sql"]
        verbs: [invoke]
        constraints:
          sql_intent: [select, with]

  - name: support-agent
    rules:
      - resources: ["support.read_ticket", "crm.lookup_customer"]
        verbs: [invoke]
      - resources: ["support.post_reply"]
        verbs: [invoke]

  - name: code-reader
    rules:
      - resources: ["fs.read_file", "fs.list_dir"]
        verbs: [invoke]
        constraints:
          path_prefix: ["/workspace/", "/repo/"]
```

### `bindings.yaml`

```yaml
bindings:
  # Duplicate entries for same agent are merged (roles and scopes unioned)
  - agent: support-bot
    roles: [sql-readonly, support-agent]
    scopes: [customer_data, support]

  - agent: code-agent
    roles: [code-reader]
    scopes: [codebase]

  # Wildcard scope — agent can operate in any scope
  - agent: admin-agent
    roles: [sql-readonly, support-agent, code-reader]
    scopes: ["*"]
```

### Scope Normalization

- Lowercased at load time and eval time
- Leading/trailing whitespace stripped
- Exact match only — `customer_data` does not match `customer_data/eu`
- No hierarchy in v1

---

## Testing Strategy

### Unit Tests (`engine/authz/authz_test.go`)

Table-driven tests for every code path in `Evaluate()`, `LoadPolicy()`, and `CanDiscover()`.

**Minimum test coverage for Phase 1 completion:**
- Every reason code has an explicit `wantReason` test
- Additive-roles correctness (both verb and constraint variants)
- Denial precedence ordering
- All constraint behaviors (sql_intent, path_prefix, aliases, strict/permissive)
- Loader: compiled field values, not just counts
- Loader: all error collection cases (unknown constraint, dangling ref, invalid verb, empty agent)

### Integration Tests (replay traces)

Four RBAC fixtures in `traces/`:

| Fixture | Events | Expected |
|---------|--------|----------|
| `rbac_support_bot_allow.json` | 4 tool calls | 4 allowed, 0 denied |
| `rbac_sql_select_allowed.json` | 2 tool calls | 2 allowed, 0 denied |
| `rbac_support_bot_sql_blocked.json` | 3 tool calls | 2 allowed, 1 denied (constraint_violation) |
| `rbac_no_binding.json` | 1 tool call | 0 allowed, 1 denied (no_binding) |

All pass with `flint-replay --rbac`. Disposition stays `allow` on all — RBAC violations do not set behavioral disposition.

### End-to-End Tests

Manual protocol-level test against a real MCP server:
1. Start `flint-gateway --agent support-bot -- npx -y @modelcontextprotocol/server-everything`
2. Send `tools/list` — verify filtered to only `support-bot`'s tools
3. Send `tools/call` for an allowed tool — verify forwarded and response returned
4. Send `tools/call` for a denied tool — verify JSON-RPC error `-32001` returned, upstream never sees the call
5. Send `tools/call` for an allowed tool with a constraint violation — verify denied

### Race Condition Tests

```bash
go test ./engine/authz/... -race -count=1
go test ./... -race -count=1
```

Must pass clean.

---

## Timeline

### Week 1 (April 22–28) — Phase 1 Completion

**Goal:** `go test ./engine/authz/... -race -count=1` passes with full coverage. All four replay traces pass.

| Day | Task |
|-----|------|
| Mon–Tue | Fix evaluator: `no_principal`, `constraint_unverifiable`, unknown constraint → fail closed, `GrantedVerb` consistency |
| Tue–Wed | Fix loader: duplicate agent merge, collect-all-errors, load-time unknown constraint validation |
| Wed–Thu | Add missing test cases (all reason codes, additive roles, denial precedence, scope edge cases) |
| Thu | Add loader content tests (`compiled_contents`), resolve `write` verb |
| Fri | Run all replay traces, fix any failures, tag Phase 1 complete |

### Week 2 (April 29–May 5) — Gateway Hardening

**Goal:** `flint-gateway` is production-worthy for single-agent, single-server use.

| Day | Task |
|-----|------|
| Mon | Structured logging (replace ad-hoc `fmt.Fprintf` with JSON log lines) |
| Tue | `SIGHUP` hot reload |
| Wed | Health check endpoint (`/healthz`) |
| Thu | `flint-policy check` CLI command |
| Fri | `flint-policy list-tools` and `list-agents` CLI commands |

### Week 3 (May 6–12) — Audit + Integration Testing

**Goal:** Audit log working. Claude Desktop integration tested end-to-end.

| Day | Task |
|-----|------|
| Mon | JSONL audit log writer |
| Tue | End-to-end test: Claude Desktop + `flint-gateway` + real MCP server |
| Wed | `tools/list` filtering verified in live integration |
| Thu | Multi-agent scenario test (different agents, different permissions, same gateway) |
| Fri | Documentation: integration guide, config reference, troubleshooting |

### Week 4 (May 13–19) — Phase 2 Completion + Phase 3 Scoping

**Goal:** Phase 2 shipped. Phase 3 architecture decided.

| Day | Task |
|-----|------|
| Mon–Tue | Startup validation, graceful shutdown, env var support for agent ID |
| Wed | Management API (read-only endpoints first: GET agents, GET roles, GET decisions) |
| Thu | Phase 3 architecture decision: single binary multi-server vs. separate processes |
| Fri | Phase 3 kickoff: data model for multi-server routing |

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Upstream MCP server uses non-stdio transport (HTTP, SSE) | Medium | High | v1 scoped to stdio only; HTTP proxy is Phase 3 |
| Policy reload races with in-flight evaluations | Medium | Medium | Lock policy pointer; swap atomically on `SIGHUP`; don't mutate in place |
| Agent ID spoofing (agent sends wrong ID in payload) | High | High | Agent ID comes from gateway CLI flag, not from the MCP message stream; agent cannot override it |
| Constraint missing-field behavior causes false denials | Medium | Medium | Implement permissive mode; document strict-as-default; add clear error messages |
| `tools/list` filter doesn't match `tools/call` gate | Low | High | Both use same `CanDiscover` / `Evaluate` functions over the same policy object |

---

## Success Metrics

### Phase 1
- `go test ./engine/authz/... -race -count=1` passes with 0 failures
- All 9 reason codes have explicit tests
- All 4 replay traces produce expected output
- 0 known gaps in `plan.md` remain open

### Phase 2
- `flint-gateway` can be attached to `@modelcontextprotocol/server-everything` and enforce policy correctly
- Claude Desktop can use a policy-gated MCP server transparently
- `flint-policy check` returns correct allow/deny for any agent + tool + payload combination
- Audit JSONL is written and readable without context

### Phase 3
- Single gateway process fronts ≥2 upstream MCP servers simultaneously
- Policy changes via management API take effect within 1 second without dropping connections
- Web UI allows a non-engineer operator to create a binding and verify it works

---

## Open Questions

1. **`write` verb**: define an `internal_write` tag or document as reserved? Decision needed this week.
2. **Permissive mode syntax**: how should operators express it in `roles.yaml`? Inline per constraint? Global policy default? Recommend: per-constraint inline, e.g., `sql_intent: {values: [select], mode: permissive}`.
3. **Multi-server tool namespacing**: if two MCP servers both expose a tool named `search`, how does a policy rule reference one vs. the other? Options: `server_name.tool_name` prefix, or require unique tool names across servers an agent can access.
4. **Agent ID in Claude Desktop**: Claude Desktop doesn't currently pass agent metadata into MCP — the `--agent` flag has to be set statically in the config. This is acceptable for v1 but limits dynamic multi-agent scenarios.
5. **Behavioral disposition on RBAC denial**: currently stays `allow`. Should repeated RBAC denials (probing) escalate disposition? Design for Phase 3.
