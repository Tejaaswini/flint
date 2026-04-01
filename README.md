# Flint

Session firewall for MCP-connected agents.

Flint gives you K8s-style access control over which agents can use which tools, and detects dangerous multi-step behavior across a session - even when every individual call is authorized.

## The problem

MCP servers expose tools. Agents call them. There is no standard enforcement layer between the two.

Without one:
- Any agent can call any tool regardless of what it's supposed to do.
- An authorized agent can read secrets via one tool and leak them through another.
- Prompt injection attacks can chain valid tool calls into an exfiltration sequence.
- Bulk extraction via pagination looks routine on a per-request basis.

These are session-level threats. Per-request inspection misses them by design.

## What Flint does

**Layer 1 - RBAC.** Define which agents can call which tools, at which scope, down to specific argument constraints.

```yaml
roles:
  - name: sql-readonly
    rules:
      - resources: ["db.execute_sql"]
        verbs: [invoke]
        constraints:
          sql_intent: [select]

bindings:
  - agent: support-bot
    roles: [sql-readonly, support-agent]
    scopes: [support, customer_data]
```

Agents, roles, bindings, scopes, verbs, constraints — the same primitives as Kubernetes RBAC. Default deny. If you haven't granted it, it doesn't happen.

**Layer 2 - Behavioral analysis.** Tracks data flow across tool calls within a session. Detects when authorized actions chain into an attack.

```
Event 1: agent reads support ticket        ← allowed by RBAC
Event 2: agent executes SQL, gets API keys ← allowed by RBAC
Event 3: agent posts keys to public thread ← allowed by RBAC

Every call passed RBAC. Flint's behavior engine links the
restricted SQL response to the egress request via token
matching and flags the session.
```

The two layers are independent signals. RBAC catches unauthorized calls. The behavioral engine catches authorized calls that chain into attacks.

## Quick start

```bash
go build -o flint-replay ./cmd/replay

# Run all demo traces
./flint-replay traces/rbac_demo_allow.json
./flint-replay traces/rbac_demo_sql_blocked.json
./flint-replay traces/rbac_demo_no_binding.json

# Run a specific trace file
./flint-replay traces/supabase_cursor_exfil.json
```

Flint loads `config/roles.yaml` and `config/bindings.yaml` automatically. If they're not found, it runs in passthrough mode (RBAC skipped, behavioral engine still active).

## Permission model

Five concepts, same structure as Kubernetes RBAC:

| Concept | Purpose |
|---------|---------|
| **Agent** | Named identity (`support-bot`, `code-agent`) |
| **Role** | Reusable permission bundle |
| **Binding** | Connects an agent to roles within scopes |
| **Scope** | Isolation boundary (`customer_data`, `code`, `support`) |
| **Rule** | Resources + verb + optional constraints |

Three verbs: `discover` (can see the tool exists), `invoke` (can call it), `admin` (reserved for management operations).

Roles compose. Multiple bindings for the same agent are merged additively - same as Kubernetes. Constraints drill into tool arguments: restrict SQL to `SELECT` only, restrict filesystem access to specific path prefixes.

Every authorization decision is recorded with full provenance — which agent, which tool, which role and rule produced the decision, which constraint failed.

## Detection rules

6 rules implemented, covering known MCP attack patterns:

| Rule | Detects |
|------|---------|
| `secret_relay` | Secret token from a restricted response relayed to an egress tool |
| `restricted_read_external_write` | Restricted data flowing to an external write path |
| `pagination_exfiltration` | Repeated calls with monotonic paging parameters |
| `cross_scope_data_movement` | Data from one scope used in another |
| `tool_poisoning_indicator` | Instruction-like content in tool responses |
| `filesystem_traversal_sequence` | File operations escalating toward sensitive paths |

Rules operate over ordered session events and data lineage edges built from token matching and field overlap across payloads.

## Architecture

```
Request
  → RBAC gate (engine/authz)
      ↓ denied → recorded in PolicyDecisions, dropped
      ↓ allowed
  → Behavioral engine
      → Fingerprint extractor
      → Lineage builder
      → Rule engine
      → Risk scorer
  → SessionState
      ├── PolicyDecisions   RBAC audit trail (all decisions)
      ├── Events            allowed events only
      ├── Edges             data lineage graph
      ├── Findings          behavioral findings
      └── RiskScore
```

```
flint/
  cmd/
    replay/         # trace replay CLI
  engine/
    authz/          # RBAC evaluator (pure function, immutable compiled policy)
    session/        # session state and types
    fingerprint/    # token extractor and field hasher
    lineage/        # causal edge builder
    rules/          # behavioral rule evaluator
    risk/           # cumulative risk scorer
  pkg/
    trace/          # trace file loader
  config/
    roles.yaml      # role definitions
    bindings.yaml   # agent-role-scope bindings
  traces/           # JSON session fixtures
  tools.yaml        # tool registry with tags and scopes
```

The engine is importable as a Go library. Call `engine.ProcessEvent(evt)` from your own agent framework without deploying a gateway proxy.

## What Flint is not

- Not a generic API gateway.
- Not an agent orchestration framework.
- Not an observability platform.

## Status

**Done:** RBAC evaluator, behavioral engine, replay CLI, detection rules (6/10).

**Next:** Inline MCP gateway proxy (`cmd/gateway`) — the enforcement point that intercepts live traffic between agents and MCP servers.

**Later:** Remaining detection rules, response redaction, PII classification, approval workflows, audit export, operator UI.
