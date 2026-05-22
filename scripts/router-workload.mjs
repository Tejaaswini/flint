#!/usr/bin/env node
// router-workload.mjs — synthetic mixed workload that drives the OpenRouter
// task-aware router. The router classifies each prompt, picks a target model,
// forwards to OpenRouter, and writes a RoutingDecision per call.
//
// Sends to http://127.0.0.1:7478/v1/chat/completions. The `model` field in
// each request is informational — the router overrides it based on its policy.
//
// Total cost when run end-to-end: well under $0.05 (the classifier dominates;
// each routing call is also small).

const ROUTER_URL = process.env.ROUTER_URL || 'http://127.0.0.1:7478/v1/chat/completions';
const DELAY_MS = parseInt(process.env.DELAY_MS || '1800', 10);
const STEADY_LOOP = process.env.STEADY_LOOP === 'true';

// ----------------------------------------------------------------------------
// Workload definition
// ----------------------------------------------------------------------------

const workload = [
  // ── Cheap classification (should route to a small model) ──────────────────
  {
    label: 'classify spam',
    body: {
      model: 'auto',
      max_tokens: 30,
      messages: [
        { role: 'system', content: 'Answer with one word: spam or not_spam.' },
        { role: 'user', content: 'Subject: WIN A FREE IPHONE — Click here now!!!' },
      ],
    },
  },
  {
    label: 'classify sentiment',
    body: {
      model: 'auto',
      max_tokens: 30,
      messages: [
        { role: 'system', content: 'Reply with one word: positive, negative, or neutral.' },
        { role: 'user', content: 'I really did not enjoy the meal, the soup was cold and the service slow.' },
      ],
    },
  },

  // ── Short summarization (low-cost target) ─────────────────────────────────
  {
    label: 'short summary',
    body: {
      model: 'auto',
      max_tokens: 80,
      messages: [
        { role: 'user', content: 'Summarize in one sentence: The OpenRouter platform aggregates dozens of LLM providers behind a unified OpenAI-compatible API, letting developers swap models without rewriting code. It exposes cost, latency, and token usage on every call.' },
      ],
    },
  },

  // ── Code generation, short (medium complexity) ────────────────────────────
  {
    label: 'simple code',
    body: {
      model: 'auto',
      max_tokens: 200,
      messages: [
        { role: 'user', content: 'Write a Python function `is_palindrome(s: str) -> bool` that ignores case and non-alphanumeric characters.' },
      ],
    },
  },
  {
    label: 'rest endpoint',
    body: {
      model: 'auto',
      max_tokens: 250,
      messages: [
        { role: 'user', content: 'Write a Go HTTP handler that returns the current time as JSON with field "now".' },
      ],
    },
  },

  // ── Code generation, high complexity (should route to bigger model) ───────
  {
    label: 'algorithmic code',
    body: {
      model: 'auto',
      max_tokens: 400,
      messages: [
        { role: 'user', content: 'Implement a Python class `LRUCache(capacity)` with get/put operations in O(1) average time. Include a doctest and reason through the invariants you need to maintain.' },
      ],
    },
  },
  {
    label: 'refactor with constraints',
    body: {
      model: 'auto',
      max_tokens: 500,
      messages: [
        { role: 'user', content: 'Refactor this synchronous Python function to be fully async without changing its external behavior, and explain the tradeoffs. Code: def fetch_user(uid): r = requests.get(f"/api/users/{uid}"); return r.json() if r.ok else None' },
      ],
    },
  },

  // ── RAG / Q&A (medium-cost target) ────────────────────────────────────────
  {
    label: 'rag question',
    body: {
      model: 'auto',
      max_tokens: 200,
      messages: [
        { role: 'system', content: 'Answer using only the provided passage.' },
        { role: 'user', content: 'Passage: "Flint is an inline MCP security gateway. It enforces RBAC and behavioral rules on every tool call between an AI agent and an MCP server, with zero changes to either side." Question: What does Flint enforce, and on what?' },
      ],
    },
  },

  // ── Conversation (default route, cheap) ───────────────────────────────────
  {
    label: 'casual chat',
    body: {
      model: 'auto',
      max_tokens: 100,
      messages: [
        { role: 'user', content: 'Whats a fun weekend activity for someone who likes hiking but lives in a city?' },
      ],
    },
  },

  // ── Vision-tagged (no actual image — classifier should still flag the capability) ─
  {
    label: 'vision describe (text hint only)',
    body: {
      model: 'auto',
      max_tokens: 150,
      messages: [
        { role: 'user', content: '[Image attached: a screenshot of a code editor] Describe what is shown in the image, including the language and any visible function signatures.' },
      ],
    },
  },

  // ── Long-context summarization ────────────────────────────────────────────
  {
    label: 'longer summary',
    body: {
      model: 'auto',
      max_tokens: 200,
      messages: [
        { role: 'user', content: 'Summarize the key tradeoffs in this design note: ' +
          'Hot reload in a stateful proxy is hard because in-flight requests must finish on the policy that was active when they started. ' +
          'An atomic pointer swap solves this if every request captures its own snapshot at entry. ' +
          'The cost is a brief window during which two policies are concurrently in effect for different requests. ' +
          'For most observability needs this is acceptable, but it means a denied call appearing in the audit log may not match the current policy on disk. ' +
          'Mitigations include stamping a policy hash on every decision and exposing recent policy versions through the control plane.' },
      ],
    },
  },

  // ── Multi-step reasoning (high complexity) ────────────────────────────────
  {
    label: 'reasoning',
    body: {
      model: 'auto',
      max_tokens: 350,
      messages: [
        { role: 'user', content: 'Three switches are downstairs and three bulbs are upstairs. You can only go upstairs once. How do you determine which switch controls which bulb? Explain your method step by step.' },
      ],
    },
  },

  // ── Tool-use intent (capability tag should fire) ──────────────────────────
  {
    label: 'tool use hint',
    body: {
      model: 'auto',
      max_tokens: 200,
      messages: [
        { role: 'user', content: 'Using the get_weather and search_flights tools, plan a 3-day trip to Lisbon next weekend.' },
      ],
    },
  },
];

// ----------------------------------------------------------------------------
// Driver
// ----------------------------------------------------------------------------

const log = (...args) => console.log('[workload]', ...args);
const err = (...args) => console.error('[workload]', ...args);

async function fire(label, body, idx) {
  const t0 = Date.now();
  try {
    const res = await fetch(ROUTER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const dur = Date.now() - t0;
    if (!res.ok) {
      const text = await res.text();
      err(`${idx + 1}/${workload.length} ${label} -> ${res.status} (${dur}ms): ${text.slice(0, 200)}`);
      return;
    }
    const data = await res.json();
    const usage = data.usage || {};
    const targetModel = data.model || '<unknown>';
    const firstChar = (data.choices?.[0]?.message?.content || '').slice(0, 60).replace(/\n/g, ' ');
    log(`${idx + 1}/${workload.length} ${label}`);
    log(`  → ${targetModel}  (${dur}ms, ${usage.prompt_tokens || '?'}/${usage.completion_tokens || '?'} tokens)`);
    log(`  ↳ "${firstChar}..."`);
  } catch (e) {
    err(`${idx + 1}/${workload.length} ${label} -> network error: ${e.message}`);
  }
}

async function runOnce() {
  log(`firing ${workload.length} calls against ${ROUTER_URL}`);
  for (let i = 0; i < workload.length; i++) {
    await fire(workload[i].label, workload[i].body, i);
    if (i < workload.length - 1) {
      await new Promise(r => setTimeout(r, DELAY_MS));
    }
  }
  log('workload complete');
}

async function main() {
  await runOnce();
  if (STEADY_LOOP) {
    log('entering steady-state loop (Ctrl-C to stop)');
    while (true) {
      await new Promise(r => setTimeout(r, 4000));
      const idx = Math.floor(Math.random() * workload.length);
      await fire(workload[idx].label, workload[idx].body, idx);
    }
  }
}

main().catch(e => { err(e); process.exit(1); });
