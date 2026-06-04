# Flint — A policy engine for AI traffic, shipped twice

**Author:** Tejaaswini Narendran · **Date:** 2026-05-21

This repo is two interconnected products built on one engine. I built it as part of my application to **OpenRouter**.

## TL;DR

I built a **task-aware LLM router on top of OpenRouter** that classifies each prompt, picks a model by policy, and ships every routing decision through a live observability dashboard.

A 13-call mixed workload (classification, code, RAG, summarization, reasoning) costs **$0.014** through the router versus **$0.023** if every call went to `gpt-4o`. **38.6% savings, observable in real time, no client changes.**

That router is one of two surfaces sitting on top of a single policy engine I built. The other surface — **Flint** — is an MCP security gateway that does the same job for tool calls instead of model calls. **One engine, two specializations.**

## Why this matters for OpenRouter

OpenRouter's `auto` router is generic — it picks a model from a static preference list. **Real teams need different things from different prompts in the same workload**: cheap classification, fast summarization, large-context refactoring, multimodal reasoning. The auto router can't tell them apart.

This router:

1. **Classifies the prompt** with a cheap call (`openai/gpt-4o-mini`, JSON mode) into `{task, complexity, capabilities}`. ~$0.0001 per classification, ~1.3s latency.
2. **Matches a policy rule** (declarative YAML, first-match-wins, hot-reloadable). Default rules cover code, classification, RAG, summarization, conversation, vision.
3. **Forwards to OpenRouter** with the chosen model. Captures `usage.cost` from the response (real money, not estimated).
4. **Logs everything** to a JSONL audit file: classifier output + cost + matched rule + target model + forward cost + baseline counterfactual + savings. The dashboard tails it live.

The whole pipeline is observable in the dashboard's Router Live screen — every call shows its classifier reasoning, the rule that fired, the model picked, and the savings vs. baseline.

## What's actually built

| Layer | Component | Lines | Purpose |
|---|---|---|---|
| **Pipeline** | `cmd/router/` (Go) | ~1500 | OpenAI-compatible API on `:7478`, classifier → policy → OpenRouter forwarder |
| **Engine** | `engine/routing/` (Go) | ~600 | Pure policy types + evaluator + atomic hot-reload holder |
| **Engine** | `engine/authz/` (Go) | ~800 | Pure RBAC for MCP — same machinery, different schema |
| **API** | `pkg/api/router.go` (Go) | ~150 | Shared wire types — `RoutingDecision`, `RouterPolicy`, `RouterStats` |
| **Control plane** | `cmd/control/handlers_router.go` (Go) | ~450 | REST + WS endpoints for the dashboard |
| **UI** | `ui/src/routes/router-{live,routes}.tsx` (TS) | ~600 | Live feed with cost-vs-baseline strikethrough + YAML policy editor |

All in one repo. Both products run from `make demo` (Flint MCP gateway) or `make demo-router` (OpenRouter router) or both side-by-side.

## Engineering details worth noting

- **OpenRouter API integration**: typed Go client, `Authorization: Bearer` from env, `HTTP-Referer` + `X-Title` set. Reads `usage.cost` directly (most reliable signal — OpenRouter normalizes across providers). Falls back to a local pricing table only when `cost` is absent.
- **Cost transparency**: every routing decision carries both `total_cost_usd` (what we spent) and `baseline_cost_usd` (what `gpt-4o` would have cost). The savings line is honest about edge cases — when the classifier picks Sonnet for high-complexity code, savings can go negative, and the dashboard shows that explicitly. Cost vs. quality tradeoff is visible, not hidden.
- **Hot-reload policy**: edit `config/router-policy.yaml`, save in the UI → atomic file write → POST to router sidecar → `atomic.Pointer[Policy]` swap. In-flight requests finish on the policy they started with. No dropped connections, no restart.
- **Security**: the OpenRouter API key reads from `OPENROUTER_API_KEY` env, never logs (masked as `sk-or-...01a5` in debug output, verified at runtime). WS upgrades validate `Origin` against an allowlist. Localhost-only by default.
- **Observability**: every decision is one JSONL line, schema-versioned for forward-compat, `f.Sync()`'d for durability. Control plane tails via fsnotify + 500ms poll fallback, fans frames out over WS with non-blocking publish.
- **Tests**: `go test ./... -race` passes — engine evaluator coverage for every match condition, atomic policy swap concurrency test, HTTP round-trip tests for the control plane.

## How the same engine governs MCP tool calls (Flint)

Flint sits between AI agents and MCP servers. It does RBAC + deny rules + behavioral analysis on every tool call — same machinery, different vocabulary:

```
                 ┌───────────────┐                   ┌──────────────┐
LLM call ─────►  │ flint-router  │ ─────► OpenRouter │              │
                 │   :7478       │                   │  Dashboard   │
                 └───────┬───────┘                   │  Router Live │
                         │ JSONL audit                │  Router      │
                         ▼                          ◄─┤  Routes      │
                 ┌────────────────────┐               │  Connections │
                 │  flint-control     │ ─────► REST + │  Agents      │
                 │   :7475            │     WebSocket │  Sessions    │
                 └────────────────────┘             ◄─┤  Roles       │
                         ▲                            │              │
                         │ JSONL audit                └──────────────┘
                 ┌───────┴───────┐
MCP call ─────►  │ flint-gateway │ ─────► npx mcp-server-everything
                 │   :7476       │
                 └───────────────┘
```

Both binaries write to the **same audit format and the same control plane**. The dashboard has two sets of screens. The engine has two top-level packages (`engine/authz`, `engine/routing`) that share patterns (atomic policy holder, deny precedence, YAML round-trip, evaluator purity, audit JSONL with schema version) without sharing code paths they shouldn't.

This isn't a coincidence — it's the bet. **Governing AI traffic is a unified problem.** Tool calls and model calls need the same shape of policy, the same shape of audit, the same shape of operator UI. Different vocabulary, same engine.

## How to run

```bash
git clone https://github.com/Tejaaswini/flint
cd flint
echo 'OPENROUTER_API_KEY=sk-or-v1-...' > .env.local

make demo-router                 # router + dashboard + workload
# opens http://127.0.0.1:5173/router/live
```

`DEMO.md` has the full guide for both surfaces and how to interact via curl.

## What's not here (yet)

This is a 24-hour focused build. Not in scope:

- **Streaming responses** — the router returns 501 on `stream: true`. The pipeline is designed to accommodate streaming without surgery; ~half-day to add.
- **Embedding-based semantic cache** — would compound the savings significantly. Natural next step.
- **Per-user / per-team policy** — single-tenant for the demo.
- **Authentication on the router** — localhost-only. Production would add an API key dance at the router boundary.

## Where I'd take this with OpenRouter

The router is the inline data plane. The dashboard is the operator surface. The engine is the policy primitive. What's missing is **the catalog**:

- a public catalog of policies people can clone (`@finance/cost-strict`, `@infra/fast-classification`, `@research/best-quality`),
- a runtime that can compose policies (org rule + team rule + user override),
- a feedback loop where output quality (from evals or human signals) re-trains the classifier.

That's a Cloudflare-for-LLM-routing shape. OpenRouter is the right team for it — you already own the model breadth, the cost normalization, the credit infrastructure. The wedge that's missing is the policy layer where customers can write their preferences down in a way that compounds with usage.

## Contact

- **Email:** tejnaren07@gmail.com
- **Repo:** github.com/Tejaaswini/flint (this repo)
- **Devlogs:** `devlogs/` — full build log (planning → implementation → reviews → fixes), including the architectural decisions and tradeoffs documented at the time they were made.
