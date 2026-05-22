#!/usr/bin/env bash
# demo.sh — boot the full Flint stack against @modelcontextprotocol/server-everything
# and open the dashboard in a browser.
#
# Components started:
#   1. control plane  → 127.0.0.1:7475  (HTTP REST + WS)
#   2. gateway        → 127.0.0.1:7476  (sidecar healthz + reload)
#                       stdio fed by scripts/sample_agent.mjs
#                       stdio piped out to /dev/null (responses ignored in demo)
#   3. UI dev server  → 127.0.0.1:5173  (Vite)
#
# Audit log: ./flint-audit.jsonl (cleared on each demo run).
# Logs: .demo-control.log, .demo-gateway.log, .demo-ui.log in CWD.

set -euo pipefail

cd "$(dirname "$0")/.."

# ----- prereqs ---------------------------------------------------------------
command -v node >/dev/null || { echo "node required (see https://nodejs.org)"; exit 1; }
command -v npx  >/dev/null || { echo "npx required"; exit 1; }

if [[ ! -x ./bin/flint-gateway ]] || [[ ! -x ./bin/flint-control ]]; then
  echo "binaries missing — run 'make build' first"
  exit 1
fi

# ----- fresh audit log -------------------------------------------------------
: > flint-audit.jsonl
echo "[demo] cleared flint-audit.jsonl"

# ----- start control plane ---------------------------------------------------
./bin/flint-control \
    --addr 127.0.0.1:7475 \
    --roles config/roles.demo.yaml \
    --bindings config/bindings.demo.yaml \
    --tools tools.demo.yaml \
    --audit flint-audit.jsonl \
    --gateway-url http://127.0.0.1:7476 \
    > .demo-control.log 2>&1 &
CONTROL_PID=$!
echo "[demo] control plane pid=$CONTROL_PID (log: .demo-control.log)"

# ----- start gateway with the sample agent driving its stdin -----------------
# The sample agent's stdout becomes the gateway's agent-side stdin.
# The gateway proxies into `npx server-everything`. Gateway stdout would normally
# go back to the agent; we discard it here since the sample agent doesn't read.
( node scripts/sample_agent.mjs | \
    ./bin/flint-gateway \
      --agent support-bot \
      --roles config/roles.demo.yaml \
      --bindings config/bindings.demo.yaml \
      --tools tools.demo.yaml \
      --audit flint-audit.jsonl \
      --http-addr 127.0.0.1:7476 \
      -- npx -y @modelcontextprotocol/server-everything \
      > /dev/null
) > .demo-gateway.log 2>&1 &
GATEWAY_PID=$!
echo "[demo] gateway pid=$GATEWAY_PID (log: .demo-gateway.log)"

# ----- start UI dev server ---------------------------------------------------
( cd ui && [[ -d node_modules ]] || npm install --silent ) >> .demo-ui.log 2>&1
( cd ui && npm run dev -- --host 127.0.0.1 --port 5173 ) > .demo-ui.log 2>&1 &
UI_PID=$!
echo "[demo] ui pid=$UI_PID (log: .demo-ui.log)"

# ----- wait for ports --------------------------------------------------------
echo "[demo] waiting for control plane..."
./scripts/wait-port.sh 7475 20
echo "[demo] waiting for gateway sidecar..."
./scripts/wait-port.sh 7476 20
echo "[demo] waiting for UI..."
./scripts/wait-port.sh 5173 45

# ----- cleanup ---------------------------------------------------------------
cleanup() {
  echo
  echo "[demo] shutting down..."
  kill "$UI_PID" "$GATEWAY_PID" "$CONTROL_PID" 2>/dev/null || true
  # children of gateway: node sample_agent + npx server-everything
  pkill -P "$GATEWAY_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "[demo] done"
}
trap cleanup EXIT INT TERM

# ----- open browser ----------------------------------------------------------
( sleep 1 && open http://127.0.0.1:5173 ) &

echo
echo "Flint demo running:"
echo "  Dashboard:  http://127.0.0.1:5173"
echo "  REST API:   http://127.0.0.1:7475/api/v1/agents"
echo "  WS stream:  ws://127.0.0.1:7475/api/v1/stream"
echo "  Healthz:    http://127.0.0.1:7476/healthz (gateway)"
echo
echo "Press Ctrl-C to stop."
wait
