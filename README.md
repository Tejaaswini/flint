# Flint

**An open-source MCP security gateway for local AI agents.**

Drops inline between any MCP client (Claude Desktop, Cursor, custom agents) and any stdio MCP server. Enforces declarative RBAC, explicit deny rules, and behavioral checks on every tool call. No client changes. No cloud dependency. No SaaS account.

---

## Why this exists

AI agents on your laptop now have ambient authority over whatever an MCP server exposes — your filesystem, your shell, your GitHub, your database. The current answers all live in someone else's box:

| Option | What it is | Why it doesn't fit local dev |
|---|---|---|
| Lasso Security, HiddenLayer, Pillar | Enterprise AI runtime security SaaS | Cloud-coupled, paid, sends tool-call data to a vendor |
| Cloudflare MCP Portals, IBM mcp-context-forge, Microsoft mcp-gateway, Kuadrant mcp-gateway | K8s / hosted MCP control planes | Built for remote MCP at org scale, not the laptop |
| Anthropic Claude Cowork RBAC | Permissions inside Anthropic's product | Doesn't govern Cursor, Claude Desktop, or any other agent |
| Nothing | The default | Most local MCP servers run wide open |

Flint sits in the gap: a local-first, OSS proxy you can drop in front of any stdio MCP server and govern with a YAML policy.

---

## What it does

Three layers, applied to every `tools/call`:

1. **RBAC** — K8s-style roles, bindings, scopes, verbs. Server-prefixed selectors (`server:github` expands at load time to every tool whose name starts with `github.`). Default deny. **Enforces — denied calls never reach the upstream.**
2. **Deny rules with global precedence** — an explicit deny overrides any allow that would have matched. `explicit_deny` sits above all other denial reasons in the precedence ladder. **Enforces.**
3. **Behavioral checks** — native, in-process, no external calls: secret relay, cross-scope data movement, pagination exfiltration, tool poisoning, filesystem traversal. **Observes today — findings are scored, audited, and surfaced on the dashboard; per-finding enforcement (`terminate`/`pause` actions) is a Phase 1 item, not live yet.**

Plus the operational pieces you'd expect from a forensic-grade tool:

- **Hot reload** via SIGHUP — atomic policy pointer swap, in-flight requests finish on the policy they started with.
- **Graceful drain** on SIGTERM — up to 5s for in-flight `tools/call` responses.
- **JSONL audit log**, schema-versioned, `f.Sync()`'d per row (so a crash doesn't lose the last decision).
- **Localhost-only control plane** + React dashboard on `:7475` / `:5173`.
- **Structured JSON logs** to stderr; agent identity is set at gateway launch and is uncheatable from the message stream.

---

## Quick start

### Prerequisites
- Go 1.21+
- Node 18+ / npm 9+
- macOS or Linux (signal handling + fsnotify)

### Build and run the demo

```bash
make build      # builds gateway, router, control plane, and UI
make demo       # starts gateway + control plane + UI + a scripted agent
```

That boots the gateway in front of `@modelcontextprotocol/server-everything`, fires a mix of allowed and denied calls from `scripts/sample_agent.mjs`, and opens your browser to the live decision feed at `http://127.0.0.1:5173/sessions`.

Look for:
- **Green rows** — allowed (`echo`, `add`, `longRunningOperation`)
- **Red rows** — denied (`printEnv` — blocked by a deny rule on the `restricted` tag)
- **Yellow banner** — a behavioral finding (e.g. secret relay across a tool chain)

### Use Flint in front of Claude Desktop

Edit your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "your-server": {
      "command": "/path/to/flint/bin/flint-gateway",
      "args": [
        "--agent", "claude-desktop",
        "--roles", "/path/to/flint/config/roles.yaml",
        "--bindings", "/path/to/flint/config/bindings.yaml",
        "--tools", "/path/to/flint/tools.yaml",
        "--audit", "/path/to/flint/flint-audit.jsonl",
        "--",
        "npx", "@your-org/your-mcp-server"
      ]
    }
  }
}
```

Flint will start the upstream MCP server itself, proxy stdio in both directions, and enforce your policy on every `tools/call`.

### Use Flint in front of Cursor

Same shape — Cursor's MCP config takes a `command` + `args`. Point `command` at `bin/flint-gateway` and put the actual server command after `--`.

### Run the tests

```bash
make test                              # everything, race-enabled
go test ./engine/... -race -count=1    # engine packages
go test ./cmd/control/... -race        # control plane endpoints
cd ui && npm run typecheck             # UI types
```

---

## Architecture

```
                   ┌──────────────────────────────────────────┐
                   │   ui/   (React + TS, on :5173 in dev)    │
                   │   Decision feed · Roles editor · Agents  │
                   │   · Connections · Sessions · (Router*)   │
                   └─────────────────┬────────────────────────┘
                                     │  HTTP + WebSocket
                   ┌─────────────────▼────────────────────────┐
                   │   cmd/control/    (Go, on :7475)         │
                   │   REST API, WS live feed, YAML editor,   │
                   │   audit query, hot-reload coordinator    │
                   └─────────────────┬────────────────────────┘
                                     │  tails JSONL
                            ┌────────▼─────────┐
                            │ flint-audit.jsonl│
                            └────────▲─────────┘
                                     │
                            ┌────────┴─────────┐
                            │  cmd/gateway/    │
                            │  stdio MCP proxy │
                            │  + sidecar :7476 │
                            └────────┬─────────┘
                                     │  stdio
                            ┌────────▼─────────┐
                            │ upstream MCP svr │
                            │ (any stdio MCP)  │
                            └──────────────────┘
```

The gateway and the control plane are decoupled by the JSONL file (read side) and a small sidecar HTTP endpoint (write side: SIGHUP-equivalent reload). The engine is pure Go, in-process inside the gateway; no shared memory, no shared lock, no shared mutability outside of an `atomic.Pointer` policy holder.

*Router surface is documented separately below.*

---

## What's in the box

### Engine (`engine/`)

Pure Go. No I/O. No global state.

- `engine/authz/` — RBAC + deny rules + server-prefixed selectors, constraint evaluation (`sql_intent`, `path_prefix`), atomic `PolicyHolder` for hot reload.
- `engine/session/` — locked data types (`SessionEvent`, `PolicyDecision`, `Finding`, `SessionState`).
- `engine/lineage/`, `engine/rules/`, `engine/risk/`, `engine/fingerprint/` — behavioral rule set for tool-call sessions.

~42 test cases in `engine/authz/` + ~15 in `engine/routing/`, all `-race` clean. Covers reason-code precedence, deny semantics, additive role evaluation, server selector resolution, concurrent atomic swap, router first-match-wins + atomic swap. Behavioral packages (`lineage`, `rules`, `risk`, `fingerprint`) are currently exercised only via the gateway integration path; direct unit tests are tracked in the concerns ledger.

### Gateway (`cmd/gateway/`)

Inline stdio proxy. Drops in between any MCP client (Claude Desktop, Cursor) and any stdio MCP server (anything launched with `npx`, `python`, a binary). Operates entirely on your machine — no network calls except what the upstream MCP server itself makes.

### Control plane (`cmd/control/`)

Localhost-only Go HTTP + WS server. Tails the audit file via fsnotify (500ms poll fallback). REST endpoints for agents, connections, roles, bindings, sessions, decisions. WS at `/api/v1/stream` for live decisions. PUT roles does YAML round-trip via `yaml.v3` Node API to preserve indentation and comments, atomic `os.CreateTemp` + `os.Rename`, then POST `/reload` to the gateway sidecar.

### Dashboard (`ui/`)

Vite + React 18 + TypeScript + Tailwind + shadcn/ui. Desktop-only (≥1280px). Mocks live behind a single env-var flag (`VITE_USE_MOCK=true`) so the UI can be developed offline.

---

## Configuration files

| File | What it controls |
|---|---|
| `config/roles.yaml` · `bindings.yaml` | Production RBAC for your tool registry |
| `config/roles.demo.yaml` · `bindings.demo.yaml` · `tools.demo.yaml` | Demo configs aligned to `server-everything`'s tool names |
| `config/router-policy.yaml` | Router rules (see "Also included" below) |
| `config/pricing.json` | Local pricing fallback for the router |

All hot-reloadable. Edit on disk + `kill -HUP $pid` (or use the dashboard's Save button).

---

## Design decisions worth knowing

- **Engine purity.** `engine/authz/` does no I/O. The loader is the only file-touching code. Hot reload is a pointer swap. Tests don't need fixtures.
- **Default deny.** No binding means no access.
- **Deny wins globally.** An explicit deny rule overrides any allow.
- **Identity is uncheatable.** Gateway agent ID comes from the `--agent` flag or `FLINT_AGENT_ID` env var, never the MCP message stream.
- **API keys never logged.** Any sensitive value read from env is masked to last-4 in debug output.

---

## Also included: cost-aware LLM routing

Flint ships with a second binary, `cmd/router/`, that does task-aware LLM routing on top of OpenRouter. It uses the same engine architecture (declarative YAML policy, hot reload, JSONL audit) and the same dashboard.

What it does: classifies each prompt (`{task, complexity, capabilities, reasoning}`) with a cheap LLM call (~$0.0001 / ~1.3s), evaluates a first-match-wins YAML policy, forwards to the chosen model on OpenRouter. Reports **counterfactual baseline cost** — "what if every request went via `gpt-4o`" — alongside the actual spend, so the savings number is concrete and per-call.

What it isn't: a replacement for [LiteLLM](https://github.com/BerriAI/litellm) (43k+ stars), [Portkey](https://portkey.ai/), [Martian](https://withmartian.com/), or [OpenRouter's own free Auto Router](https://openrouter.ai/docs/guides/routing/routers/auto-router). Those have more features, more models, more polish, and far more resources behind them. Flint's router exists because the gateway engine works equally well on model calls, and the counterfactual-savings UX isn't built into the alternatives we found.

Use it if: you want to govern LLM cost the same way you govern MCP tool calls — one engine, one rulebook, one dashboard.

Try it:

```bash
make demo-router        # router + control plane + UI + 13 mixed prompts
```

Opens to `http://127.0.0.1:5173/router/live`. Total cost <$0.02.

---

## What this is NOT

Given how crowded the adjacent spaces are, worth saying explicitly:

- **Not a replacement for LiteLLM, Portkey, Martian, or OpenRouter's Auto Router.** If you need a production LLM gateway with 100+ providers, semantic caching, evals, and 24/7 support — use one of those.
- **Not an enterprise MCP control plane.** Cloudflare, IBM, Microsoft, Kuadrant, TrueFoundry target K8s and hosted MCP for orgs. Flint targets laptops and stdio.
- **Not a cloud SaaS.** Lasso, HiddenLayer, Pillar are vendor-coupled and require sending data off your machine. Flint runs entirely on your machine.
- **Not a guardrails / eval / observability product.** Guardrails AI, NeMo Guardrails, Braintrust, Langfuse, Helicone do that better. Flint is upstream of them — it decides whether the call happens at all.

---

## Status

| Layer | State |
|---|---|
| Engine (authz) | complete, tested with `-race` |
| MCP gateway | complete; structured logging, audit JSONL, hot reload, graceful drain |
| Control plane | complete; REST + WS |
| Dashboard | functional, currently being reorganized for clearer IA |
| LLM router (companion) | working; cost capture verified; positioned as a feature, not a peer |
| Behavioral rules | computed, scored, audited; per-finding enforcement deferred to Phase 1 |
| Threat model documentation | not yet written |
| Distribution materials (Claude Desktop / Cursor walkthroughs) | not yet written |

Out of scope for this build:
- Streaming responses on the router (returns 501 today)
- Multi-upstream gateway (single upstream this build)
- Authentication on the control plane (localhost-only by default)
- Mobile UI breakpoints

---

## Repo layout

```
flint/
├── cmd/
│   ├── gateway/     # MCP stdio proxy (primary surface)
│   ├── router/      # Cost-aware LLM routing companion
│   ├── control/     # HTTP + WS control plane
│   └── replay/      # offline trace replay
├── engine/
│   ├── authz/       # RBAC policy + evaluator + holder
│   ├── routing/     # routing policy + evaluator + holder (used by cmd/router)
│   ├── session/     # locked data types
│   ├── lineage/ rules/ risk/ fingerprint/   # behavioral
│   └── engine.go    # gateway engine
├── pkg/api/         # wire types shared by gateway, router, control, UI
├── pkg/trace/       # session trace helpers
├── ui/              # Vite + React + TS dashboard
├── config/          # YAML configs (production + demo)
├── scripts/         # demo runners + synthetic workloads
├── go.mod · go.sum · Makefile
└── tools.yaml · tools.demo.yaml
```

---

## License

MIT.
