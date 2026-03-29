# Flint

A behavioral session firewall for MCP-connected agents.

Flint detects dangerous multi-step behavior across an MCP session — even when each individual tool call looks valid in isolation. The unit of analysis is the **session**, not the request.

---

## What it does

Most MCP security tools inspect individual requests. Flint inspects behavioral chains. It tracks how data flows between tool calls and fires detection rules when it observes attack patterns like:

- Secret exfiltration (restricted token read → egress write)
- Cross-scope data movement (restricted source → external destination)
- Bulk data harvesting via pagination loops
- Tool poisoning, privilege escalation, filesystem traversal (coming in v1 rule pack)

---

## How it works

Every tool call and response is ingested as a `SessionEvent`. As events arrive:

1. **Fingerprint Extractor** scans payloads for secrets (regex patterns) and hashes field values for non-secret data tracking.
2. **Lineage Builder** indexes response data and, on each new request, checks whether any prior response data appears in it. Matches become causal edges (`exact_token_match`, `field_value_overlap`).
3. **Rule Engine** evaluates detection rules against the current event and all accumulated edges.
4. **Risk Scorer** accumulates a score and escalates the session disposition: `allow → warn → pause → terminate`.

---

## Build and run

**Requirements**: Go 1.21+

```bash
# Build
go build -o flint-replay main.go

# Run with embedded demo traces
./flint-replay

# Run with an external trace file
./flint-replay traces/my-session.json
```

Exit code `1` if any session disposition is `terminate` or `pause`.

---

## Demo traces

Two traces are embedded in the binary:

**`supabase_cursor_exfil`** — Attack scenario. An agent reads a support ticket containing an injected SQL instruction, executes the query to extract live API keys, then posts those keys to the support thread. Flint catches the token relay and terminates the session.

**`benign_code_search`** — Normal workflow. Agent searches GitHub for a function and reads the file. No restricted data touched, no egress tools called. Session allowed.

---

## Detection rules (v1)

| Rule | Severity | Action | Description |
|------|----------|--------|-------------|
| `secret_relay` | critical | terminate | Known secret token from a restricted response relayed to an egress tool |
| `restricted_read_external_write` | critical | pause | Any restricted response data (not just secrets) flowing to an external write |
| `pagination_exfiltration` | high | warn | Same data-source tool called 3+ times with monotonically increasing pagination field |

---

## Trace file format

External traces are JSON files with this shape:

```json
{
  "name": "my_trace",
  "description": "What this session represents",
  "session_id": "sess_001",
  "events": [
    {
      "session_id": "sess_001",
      "event_seq": 1,
      "timestamp": "2024-01-15T14:00:00Z",
      "direction": "request",
      "method": "tools/call",
      "tool_name": "db.execute_sql",
      "payload": { "query": "SELECT * FROM users" }
    },
    {
      "session_id": "sess_001",
      "event_seq": 2,
      "direction": "response",
      "method": "tools/call",
      "tool_name": "db.execute_sql",
      "payload": { "rows": [...] }
    }
  ]
}
```

`tool_tags`, `scope`, and `payload_class` are optional — the tool registry fills them in automatically for known tools.

---

## Tool registry

The registry maps tool names to metadata (tags, scope, payload class). Currently hardcoded in `main.go`. Built-in tools:

| Tool | Tags | Scope |
|------|------|-------|
| `crm.lookup_customer` | data_source, restricted | restricted |
| `crm.get_integration_tokens` | data_source, restricted | restricted |
| `db.execute_sql` | data_source, sql, restricted | restricted |
| `slack.post_message` | external_write, network_egress | internal |
| `github.search_code` | data_source | internal |
| `support.read_ticket` | data_source, external_data | internal |
| `support.post_reply` | external_write, network_egress | internal |
| `fs.read_file` | data_source, filesystem | internal |

Tools not in the registry are processed without enrichment — tags and scope must be present in the event itself.

---

## Project status

**Week 1 (current):** Single-file monolith. Event schema, replay CLI, session tracker, fingerprint extractor, lineage builder, 3 rules, 2 embedded traces.

**Week 2:** Lineage improvements, full sync/async rule evaluation split, risk scorer refinement, Supabase live trace replay.

**Week 3:** Benign trace suite, false-positive tuning, expanded rule pack.

**Week 4:** Gateway shell — inline MCP proxy for live traffic interception.

---

## Design principles

- The behavior engine is the product. The gateway is a delivery mechanism.
- Replay harness and live gateway use the exact same engine code path.
- False positives are worse than false negatives in v1. Be conservative.
- No external dependencies. Go stdlib only.
- Hot path latency budget: <20ms added per event.
