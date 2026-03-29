# Flint

Session firewall for MCP-connected agents.

Flint gives you k8s-level access control over which agents can use which tools, and detects dangerous multi-step behavior across a session — even when every individual call is authorized.

## The problem

MCP gateways can proxy traffic and apply per-request policies. What they can't do:

- Stop an authorized agent from reading secrets via one tool and leaking them through another.
- Detect pagination-based bulk extraction where each call looks routine.
- Catch prompt injection attacks that chain valid tool calls into an exfiltration sequence.

These are session-level threats. Per-request inspection misses them by design.

## What Flint does

**Layer 1 - Granular access control.** Define who can do what, at which scope, down to specific tool arguments.

```yaml
roles:
  - name: sql-readonly
    rules:
      - resources: ["db.execute_sql"]
        verbs: ["discover", "read"]
        constraints:
          sql_intent: ["select"]

bindings:
  - agent: support-bot
    roles: [sql-readonly, support-agent]
    scopes: [support, customer_data]
```

Agents, roles, bindings, scopes, verbs, and constraints — the same primitives as Kubernetes RBAC. Default deny. If you don't grant it, it doesn't exist. Agents without `discover` permission on a tool don't even see it in `tools/list`.

**Layer 2 - Session behavioral analysis.** Tracks data flow across tool calls within a session. Detects when authorized actions chain into an attack.

```
Event 1: agent reads support ticket        ← allowed
Event 2: agent executes SQL, gets API keys ← allowed  
Event 3: agent posts keys to public thread ← allowed

Every call passed RBAC. Flint's behavior engine links the
restricted SQL response to the egress request via token
matching and terminates the session.
```

The behavior engine builds a causal graph per session — which data came from where, where it's going, and whether that movement pattern matches known attack signatures.

## How it works

```
Request
  → Agent identity resolution
  → Permission check (RBAC)
  → Session tracker
  → Fingerprint extractor
  → Lineage builder
  → Rule engine (sync fast-path + async broad rules)
  → Allow / Block / Pause / Terminate
```

The same engine processes live gateway traffic and recorded trace files. The replay harness is the test suite, the dev loop, and the attack simulation tool.

## Quick start

```bash
go build -o flint-replay main.go
./flint-replay
```

Runs embedded traces: a Supabase-style exfiltration attack (terminated) and a benign code search (clean pass).

```bash
./flint-replay traces/supabase_cursor.json
```

Run against a specific trace file.

## Permission model

Five concepts, same structure as Kubernetes RBAC:

| Concept | Purpose |
|---------|---------|
| **Agent** | Named identity (sales-copilot, support-bot) |
| **Role** | Reusable permission bundle with rules |
| **Binding** | Connects an agent to roles within scopes |
| **Scope** | Isolation boundary (customer_data, code, billing) |
| **Rule** | Resources + verbs + optional constraints |

Five verbs: `discover` (can see the tool), `read`, `write`, `execute` (side-effects like sending email), `admin`.

Roles compose. Agents get multiple role bindings. Scopes isolate. Constraints drill into tool arguments — restrict SQL to SELECT only, restrict filesystem to specific path prefixes, restrict Slack to specific channels.

## Detection rules

Flint ships with a rule pack covering known MCP attack patterns:

| Rule | Detects |
|------|---------|
| secret_relay | Secret token from restricted response relayed to egress tool |
| restricted_read_external_write | Restricted data flowing to external write path |
| pagination_exfiltration | Repeated calls with monotonic paging parameters |
| cross_scope_data_movement | Data from one scope used in another without policy |
| tool_poisoning_indicator | Instruction-like content in tool metadata |
| privilege_escalation_chain | Read result informing unexpected write operation |
| filesystem_traversal_sequence | File operations escalating toward sensitive paths |
| sql_mutation_after_read | Write/DDL following a read against same data source |
| rapid_tool_switching | Abnormal oscillation between source and egress tools |
| instruction_injection_echo | External content influencing later tool selection |

Rules are YAML-defined pattern matchers over ordered session events and data lineage edges. Not a general-purpose policy language. Not Turing-complete.

## Architecture

```
flint/
  cmd/
    replay/         # trace replay CLI
    gateway/        # inline MCP proxy
  engine/
    session/        # session tracker + state
    fingerprint/    # token extractor + field hasher
    lineage/        # causal edge builder
    rules/          # sequence rule evaluator
    risk/           # cumulative risk scorer
    authz/          # permission evaluator
  pkg/
    mcp/            # JSON-RPC types and parser
    trace/          # trace file loader
  rules/            # YAML detection rules
  traces/           # JSON session fixtures
  config/
    roles.yaml      # role definitions
    bindings.yaml   # agent-role-scope bindings
    tools.yaml      # tool registry with tags and scopes
```

The engine is importable as a Go library. You can call `engine.ProcessEvent(evt)` from your own agent framework without deploying the gateway proxy.

## What Flint is not

- Not a generic API gateway with MCP bolted on.
- Not an agent orchestration framework.
- Not an observability dashboard.
- Not a privacy compliance platform (yet — planned for a later phase).

## Roadmap

**Now:** Replay harness, behavior engine, RBAC evaluator, detection rules.
**Next:** Inline gateway shell with live traffic enforcement.
**Later:** Response redaction, PII classification, PIA-aware tool governance, approval workflows, audit export, operator UI.
