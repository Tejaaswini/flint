#!/usr/bin/env bash
# router-demo.sh — boot the OpenRouter task-aware router stack and fire a
# scripted workload. Mirrors scripts/demo.sh but for the LLM router surface.
#
# Stack:
#   1. control plane   → 127.0.0.1:7475   (HTTP REST + WS, extended w/ router endpoints)
#   2. router          → 127.0.0.1:7478   (OpenAI-compatible API; forwards to OpenRouter)
#                        127.0.0.1:7479   (sidecar healthz + reload)
#   3. UI dev server   → 127.0.0.1:5173   (Vite)
#   4. workload driver → fires ~13 mixed calls into the router
#
# Audit log: ./router-audit.jsonl (cleared on each run).
# Secrets:   ./.env.local must contain OPENROUTER_API_KEY=sk-or-v1-...

set -euo pipefail

cd "$(dirname "$0")/.."

# ----- prereqs ---------------------------------------------------------------
command -v node >/dev/null || { echo "node required"; exit 1; }

if [[ ! -f .env.local ]]; then
  echo "missing .env.local with OPENROUTER_API_KEY=..."
  exit 1
fi

# shellcheck disable=SC1091
set -a
source .env.local
set +a

if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo ".env.local does not export OPENROUTER_API_KEY"
  exit 1
fi

if [[ ! -x ./bin/flint-router ]] || [[ ! -x ./bin/flint-control ]]; then
  echo "binaries missing — run 'make build-router' first"
  exit 1
fi

# ----- fresh audit log -------------------------------------------------------
: > router-audit.jsonl
echo "[demo-router] cleared router-audit.jsonl"
: > flint-audit.jsonl
echo "[demo-router] cleared flint-audit.jsonl"

# ----- start control plane ---------------------------------------------------
# (uses defaults for gateway policy paths; only the router fields matter for this demo)
./bin/flint-control \
    --addr 127.0.0.1:7475 \
    --roles config/roles.demo.yaml \
    --bindings config/bindings.demo.yaml \
    --tools tools.demo.yaml \
    --audit flint-audit.jsonl \
    --gateway-url http://127.0.0.1:7476 \
    --router-policy config/router-policy.yaml \
    --router-audit router-audit.jsonl \
    --router-url http://127.0.0.1:7479 \
    > .demo-control.log 2>&1 &
CONTROL_PID=$!
echo "[demo-router] control plane pid=$CONTROL_PID (log: .demo-control.log)"

# ----- start router ----------------------------------------------------------
./bin/flint-router \
    --addr 127.0.0.1:7478 \
    --policy config/router-policy.yaml \
    --audit router-audit.jsonl \
    --http-addr 127.0.0.1:7479 \
    --openrouter-base https://openrouter.ai/api/v1 \
    > .demo-router.log 2>&1 &
ROUTER_PID=$!
echo "[demo-router] router pid=$ROUTER_PID (log: .demo-router.log)"

# ----- start UI dev server ---------------------------------------------------
( cd ui && [[ -d node_modules ]] || npm install --silent ) >> .demo-ui.log 2>&1
( cd ui && npm run dev -- --host 127.0.0.1 --port 5173 ) > .demo-ui.log 2>&1 &
UI_PID=$!
echo "[demo-router] ui pid=$UI_PID (log: .demo-ui.log)"

# ----- wait for ports --------------------------------------------------------
echo "[demo-router] waiting for control plane..."
./scripts/wait-port.sh 7475 20
echo "[demo-router] waiting for router..."
./scripts/wait-port.sh 7478 20
echo "[demo-router] waiting for router sidecar..."
./scripts/wait-port.sh 7479 20
echo "[demo-router] waiting for UI..."
./scripts/wait-port.sh 5173 45

# ----- cleanup ---------------------------------------------------------------
cleanup() {
  echo
  echo "[demo-router] shutting down..."
  kill "$UI_PID" "$ROUTER_PID" "$CONTROL_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "[demo-router] done"
}
trap cleanup EXIT INT TERM

# ----- open browser ----------------------------------------------------------
( sleep 1 && open "http://127.0.0.1:5173/router/live" ) &

# ----- fire workload after a brief warmup -----------------------------------
( sleep 4 && node scripts/router-workload.mjs ) &

echo
echo "Flint OpenRouter router demo running:"
echo "  Live feed:   http://127.0.0.1:5173/router/live"
echo "  Routes:      http://127.0.0.1:5173/router/routes"
echo "  REST:        http://127.0.0.1:7475/api/v1/router/policy"
echo "  WS:          ws://127.0.0.1:7475/api/v1/router/stream"
echo "  Router HTTP: http://127.0.0.1:7478/v1/chat/completions"
echo "  Sidecar:     http://127.0.0.1:7479/healthz"
echo
echo "Press Ctrl-C to stop."
wait
