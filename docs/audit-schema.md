# Flint Audit Schema

Flint writes a JSONL audit log at the path configured by `FLINT_AUDIT_PATH`
(default: `flint-audit.jsonl`). Each line is a JSON object conforming to the
`DecisionRow` type in `pkg/api/types.go`.

---

## Schema versions

| Version | Date introduced | Summary |
|---------|----------------|---------|
| v1 | 2026-05-xx | Initial schema: RBAC decisions, findings without action field |
| v2 | 2026-06-03 | Adds `findings[].action` and `enforced_action`; `AuditSchemaVersion = 2` |

---

## v2 fields (added 2026-06-03)

### `findings[].action` (string, optional)

The intended enforcement response for this individual finding.

Values: `"warn"` | `"pause"` | `"terminate"`

On v1 rows this field is absent (empty string on unmarshal). The control plane
normalises empty to `"warn"` on read. The UI should display `"warn"` for any
finding row with a missing action.

### `enforced_action` (string, optional)

What the gateway actually did for this event. Set on both request and response
audit rows.

Values:
- `"allow"` — request allowed, no enforcement action
- `"observed"` — response forwarded without enforcement (findings are observe-only; P1.9 wires blocking)
- `"blocked"` — request denied by RBAC gate
- `"warn"` / `"pause"` / `"terminate"` — reserved for when P1.9 enforcement is wired

On v1 rows this field is absent. The control plane normalises empty to
`"observed"` on read.

---

## Backward compatibility

Old v1 lines on disk remain readable. The control plane reads and normalises
them on the fly:

```go
if row.SchemaVersion < 2 {
    if row.EnforcedAction == "" {
        row.EnforcedAction = "observed"
    }
    for i := range row.Findings {
        if row.Findings[i].Action == "" {
            row.Findings[i].Action = "warn"
        }
    }
}
```

No migration of existing files is required. New rows written after this change
carry `schema_version: 2`.

---

## Wire format example (v2)

```json
{
  "ts": "2026-06-03T14:00:04Z",
  "session_id": "sess_attack_001",
  "agent_id": "support-bot",
  "tool_name": "db.execute_sql",
  "direction": "response",
  "allowed": true,
  "reason": "",
  "event_seq": 4,
  "findings": [
    {
      "rule_id": "credential_exposure",
      "severity": "high",
      "score": 60,
      "message": "Credential-shaped token (supabase_service_role) in db.execute_sql response (event 4)",
      "action": "warn"
    }
  ],
  "schema_version": 2,
  "enforced_action": "observed"
}
```

---

## `event_seq` invariant

`event_seq` is a per-session, monotonically increasing integer assigned by the
writer (live gateway) or preserved from the source trace (replay). It is stable
across runs for the same trace file. Labels join by `(session_id, event_seq)`.

A trace file with N events must cover `event_seq` 1..N with no gaps, no
duplicates, and ascending order.

**Writers:**
- Live gateway: `seqCounter` is per-`Proxy`, atomic, starts at 1. Two call
  sites (request at `handleToolsCall`, response at `handleToolsCallResponse`)
  share a single counter. No collision possible within a session.
- Replay: preserves `event_seq` from input JSON, sorts ascending before feeding
  to the engine. Stable across runs for the same input file.
- Control plane: read-only, never assigns.
