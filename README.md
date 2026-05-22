# Flint

**A policy engine for AI traffic.** One engine, two surfaces:

- **`cmd/gateway/`** — an inline MCP security gateway. Sits between an AI agent (Claude Desktop, Cursor, custom) and an MCP server. Enforces K8s-style RBAC + deny rules + behavioral analysis on every tool call. Zero changes to either side.
- **`cmd/router/`** — a task-aware LLM router on top of OpenRouter. Classifies each prompt, picks a model by declarative policy (cost ceiling, latency budget, required capabilities), and ships every routing decision through the same dashboard.

Both binaries share:

- the same engine packages (`engine/authz/` for RBAC, `engine/routing/` for model selection)
- the same JSONL audit format
- the same control plane (`cmd/control/` — REST + WebSocket)
- the same dashboard (`ui/` — React + TS + Tailwind)

Tool calls and model calls are the same shape of problem: policy in, evaluated decision out, audited. The engine is the durable primitive; the surfaces are configurations of it.

---

## Why this exists

AI agents talk to two kinds of things:

1. **Tools** (databases, GitHub, filesystems, web APIs) via MCP servers.
2. **Models** (GPT, Claude, Llama, Gemini) via APIs like OpenRouter.

Both edges deserve governance. Today the tool edge has no standard enforcement layer at all — agents have ambient authority over whatever an MCP server exposes. The model edge has cost runaway problems — auto-routers are generic and don't know which prompts deserve which models.

Flint addresses both with the same machinery: a small, pure policy engine that you point at a YAML rulebook, plus an inline proxy that consults it on every call, plus a dashboard that makes the decisions visible.

---

## Architecture

```
                   ┌──────────────────────────────────────────┐
                   │   ui/   (React + TS, on :5173 in dev)    │
                   │   7 screens: Connections · Agents ·      │
                   │   Sessions/Live · Roles · Router Live ·  │
                   │   Router Routes · Connection Detail      │
                   └─────────────────┬────────────────────────┘
                                     │  HTTP + WebSocket
                   ┌─────────────────▼────────────────────────┐
                   │   cmd/control/    (Go, on :7475)         │
                   │   REST API, WS live feed, YAML editor,   │
                   │   audit query, hot-reload coordinator    │
                   └────┬────────────────────────────┬────────┘
                        │ tails JSONL                │ tails JSONL
            ┌───────────▼──────────┐   ┌─────────────▼─────────────┐
            │  flint-audit.jsonl   │   │  router-audit.jsonl       │
            └───────────▲──────────┘   └─────────────▲─────────────┘
                        │                            │
            ┌───────────┴──────────┐   ┌─────────────┴─────────────┐
            │  cmd/gateway/         │   │  cmd/router/             │
            │  stdio MCP proxy      │   │  OpenAI-compat on :7478  │
            │  + sidecar :7476      │   │  + sidecar :7479         │
            └───────────┬──────────┘   └─────────────┬─────────────┘
                        │  stdio                     │  HTTPS
            ┌───────────▼──────────┐   ┌─────────────▼─────────────┐
            │  upstream MCP server │   │  OpenRouter API           │
            │  (any stdio MCP)     │   │  (any model OpenRouter    │
            │                      │   │   exposes)                │
            └──────────────────────┘   └───────────────────────────┘
```

The control plane and the two surfaces are decoupled by the JSONL files (read side) and small sidecar HTTP endpoints (write side: SIGHUP-equivalent reload). The engine is in-process Go inside each surface; no shared memory, no shared lock, no shared mutability outside of `atomic.Pointer` policy holders.

---

## What's in the box

### Engine (`engine/`)

Pure Go. No I/O. No global state.

- `engine/authz/` — RBAC + deny rules + server-prefixed selectors (`server:github` expands at load time to the union of tools whose names start with `github.`), constraint evaluation (`sql_intent`, `path_prefix`), atomic `PolicyHolder` for hot reload.
- `engine/routing/` — first-match-wins policy evaluator over classifier output, match conditions (`task`, `complexity`, `capabilities_include`, `messages_min_length`), fallback chains, same `PolicyHolder` pattern.
- `engine/session/` — locked data types (`SessionEvent`, `PolicyDecision`, `Finding`, `SessionState`).
- `engine/lineage/`, `engine/rules/`, `engine/risk/`, `engine/fingerprint/` — behavioral rule set for tool-call sessions: secret relay, scope hopping, pagination exfiltration, tool poisoning, filesystem traversal.

Tests: ~40 cases under `go test ./engine/... -race`. Covers reason-code precedence, deny semantics, additive role evaluation, server selector resolution, concurrent atomic swap.

### MCP gateway (`cmd/gateway/`)

Inline stdio proxy. Drops in between any MCP client (Claude Desktop, Cursor) and any stdio MCP server (anything launched with `npx`, `python`, a binary).

- JSONL audit, schema-versioned, `f.Sync()`'d per row (forensic-grade durability)
- SIGHUP reload (atomic policy pointer swap, in-flight requests finish on the policy they started with)
- SIGTERM graceful drain (up to 5s for in-flight `tools/call` responses)
- HTTP sidecar (`/healthz`, `/reload`) on a separate port
- Structured JSON logs to stderr; agent identity is set at gateway launch (uncheatable from the message stream)

### LLM router (`cmd/router/`)

OpenAI-compatible drop-in for `openrouter.ai/api/v1`. Three-stage pipeline per request:

1. **Classify** — cheap call (`openai/gpt-4o-mini` by default, JSON mode) → `{task, complexity, capabilities, reasoning}`. ~$0.0001 / ~1.3s.
2. **Match** — first rule in `config/router-policy.yaml` whose `if` block satisfies the classifier output. Returns target model + fallback chain.
3. **Forward** — POST to OpenRouter with the chosen model. Captures `usage.cost` directly from the response; falls back to a local pricing table only when the upstream provider didn't populate cost.

Every decision lands in `router-audit.jsonl` with classifier cost, forward cost, **counterfactual baseline cost** (what `openai/gpt-4o` would have cost — configurable), and the savings delta. Streaming (`stream: true`) returns 501 for v1; pipeline is shaped to accept it without surgery.

### Control plane (`cmd/control/`)

Localhost-only Go HTTP + WS server. Tails both audit files via fsnotify (500ms poll fallback). Endpoints:

```
GET  /api/v1/agents · /agents/:id                     # MCP side
GET  /api/v1/connections · /connections/:name
GET  /api/v1/roles · PUT /api/v1/roles/:name
GET  /api/v1/bindings · /api/v1/sessions · /sessions/:id · /sessions/:id/events
GET  /api/v1/decisions?limit=&since=
WS   /api/v1/stream                                   # live gateway decisions

GET  /api/v1/router/policy · /policy/raw              # router side
PUT  /api/v1/router/policy                            # YAML body, validates, atomic write, gateway reload
GET  /api/v1/router/decisions?limit=&since=
GET  /api/v1/router/stats?window=session|24h|1h
WS   /api/v1/router/stream                            # live routing decisions

GET  /healthz
```

PUT roles + PUT router-policy both do YAML round-trip via `yaml.v3` Node API to preserve indentation and ordering, atomic `os.CreateTemp` + `os.Rename`, then POST `/reload` to the relevant surface's sidecar.

### Dashboard (`ui/`)

Vite + React 18 + TypeScript + Tailwind + shadcn/ui. Seven screens, all desktop (≥1280px). Mocks live behind a single env-var flag (`VITE_USE_MOCK=true`) so the UI can be developed offline.

- **Connections / Connection detail** — upstream MCP servers, tools, health
- **Agents** — effective permissions per agent (allow/deny derivation, recent denials)
- **Sessions / Live** — real-time decision feed; red on deny, green on allow, amber banner on behavioral finding
- **Roles editor** — YAML-like policy editor with composable rules + Allow/Deny effect toggles
- **Router Live** — live routing feed with classifier reasoning, target model, cost vs. baseline, savings %
- **Router Routes** — policy editor (YAML), rule-by-rule visual breakdown, save → hot reload

---

## Quick start

### Prerequisites

- Go 1.21+
- Node 18+ / npm 9+
- macOS or Linux (signal handling + fsnotify)
- For the router: an OpenRouter API key in `.env.local`
  ```bash
  echo 'OPENROUTER_API_KEY=sk-or-v1-...' > .env.local
  ```
  Free-tier keys work; paid models are reachable. The file is gitignored.

### Run the MCP gateway demo

```bash
make demo
```

Boots gateway + control plane + UI, plus a scripted MCP agent (`scripts/sample_agent.mjs`) that fires a mix of allowed and denied calls against `@modelcontextprotocol/server-everything`. Browser opens to the live feed.

### Run the OpenRouter router demo

```bash
make demo-router
```

Boots router + control plane + UI, then fires `scripts/router-workload.mjs` — 13 mixed prompts (classification, code, RAG, summarization, reasoning, vision-hint, tool-use). Browser opens to `/router/live`. The workload takes ~45 seconds; total cost under $0.02.

Ctrl-C stops everything. `make kill` cleans up if anything was orphaned.

### Run the tests

```bash
make test                          # everything, race-enabled
go test ./engine/... -race         # engine packages
go test ./cmd/control/... -race    # control plane (gateway + router endpoints)
cd ui && npm run typecheck         # UI types
```

---

## Configuration files

| File | What it controls |
|---|---|
| `config/roles.yaml` · `bindings.yaml` | MCP gateway RBAC for the production tool registry |
| `config/roles.demo.yaml` · `bindings.demo.yaml` · `tools.demo.yaml` | Demo configs aligned to `server-everything`'s tool names |
| `config/router-policy.yaml` | Router rules: classifier model, baseline, ordered routes, default + fallback |
| `config/pricing.json` | Local pricing fallback used when OpenRouter doesn't populate `usage.cost` |

All hot-reloadable. Edit on disk + `kill -HUP $pid` (or use the dashboard's Save button).

---

## Design decisions worth knowing

- **Engine purity.** `engine/authz/` and `engine/routing/` do no I/O. The loader is the only file-touching code. Hot reload is a pointer swap. Tests don't need fixtures.
- **Default deny.** No binding means no access in RBAC. No matching route means default model in the router.
- **Deny wins globally.** An explicit deny rule overrides any allow that would have matched. `explicit_deny` sits above all other denial reasons in the precedence ladder.
- **Identity is uncheatable.** Gateway agent ID comes from the `--agent` flag or `FLINT_AGENT_ID` env var, never the MCP message stream.
- **Cost transparency.** The router shows the real cost vs the baseline cost vs the savings on every call. When the classifier picks an expensive model and that's the right call (e.g. high-complexity code), the savings line goes negative and the dashboard says so explicitly. No hidden tradeoffs.
- **API keys never logged.** The OpenRouter key is read from env, masked to last-4 in any debug output.

---

## Status

| Layer | State |
|---|---|
| Engine (authz + routing) | complete, tested with `-race` |
| MCP gateway | complete; structured logging, audit JSONL, hot reload, graceful drain |
| LLM router | complete; classifier + policy + OpenRouter forwarder + cost capture |
| Control plane | complete for both surfaces; REST + WS |
| Dashboard | 7 screens implemented; desktop-only |
| Demo workloads | `make demo` (MCP) and `make demo-router` (LLM) end-to-end |

Out of scope this build:
- Streaming responses on the router (returns 501 today)
- Embedding-based semantic cache for the router
- Predicate constraints (`!=`, glob `**`, OR via `|`) for RBAC
- Multi-upstream gateway (single upstream this build)
- Authentication on the control plane / router (localhost-only by default)
- Mobile UI breakpoints

---

## Repo layout

```
flint/
├── cmd/
│   ├── gateway/     # MCP stdio proxy
│   ├── router/      # OpenAI-compatible LLM router
│   ├── control/     # HTTP + WS control plane
│   └── replay/      # offline trace replay
├── engine/
│   ├── authz/       # RBAC policy + evaluator + holder
│   ├── routing/     # routing policy + evaluator + holder
│   ├── session/     # locked data types
│   ├── lineage/ rules/ risk/ fingerprint/   # behavioral
│   └── engine.go    # top-level Engine struct
├── pkg/api/         # wire types shared by gateway, router, control, UI
├── ui/              # Vite + React + TS dashboard
├── config/          # YAML configs (production + demo)
├── scripts/         # demo runners + synthetic workloads
├── go.mod · go.sum · Makefile · main.go
└── tools.yaml · tools.demo.yaml
```
