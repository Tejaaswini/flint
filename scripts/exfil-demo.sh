#!/usr/bin/env bash
# exfil-demo.sh — A/B demo for Flint's credential-exfil detection + enforcement.
#
# Default mode: ENFORCE (--enforce-mode block).
# Pass --observe-only to run in observe mode (findings fire but gateway passes through).
#
# Components started:
#   1. control plane  → 127.0.0.1:7475  (HTTP REST + WS)
#   2. gateway        → 127.0.0.1:7476  (sidecar healthz + reload)
#                       upstream: node scripts/vulnerable-mcp.mjs
#                       stdin fed by: node scripts/exfil_agent.mjs
#                       responses discarded (/dev/null) — agent is write-only
#   3. UI dev server  → 127.0.0.1:5173  (Vite)
#
# Audit log: ./flint-audit.jsonl (cleared on each demo run).
# Logs: .demo-control.log, .demo-gateway.log, .demo-ui.log in CWD.

set -euo pipefail

cd "$(dirname "$0")/.."

# ----- port-collision guard --------------------------------------------------
# If a prior demo stack (demo.sh or an earlier exfil-demo.sh run) is already
# holding ports 7475/7476/5173, kill it now so our processes can bind cleanly.
# pkill exits non-zero when no process matched — || true prevents set -e from
# aborting the script in that case (cold-start scenario).
pkill -f flint-gateway 2>/dev/null || true
pkill -f flint-control 2>/dev/null || true
pkill -f "vite" 2>/dev/null || true
pkill -f vulnerable-mcp.mjs 2>/dev/null || true
pkill -f exfil_agent.mjs 2>/dev/null || true
sleep 0.5

# ----- parse flags -----------------------------------------------------------
OBSERVE_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --observe-only) OBSERVE_ONLY=true ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

if $OBSERVE_ONLY; then
  ENFORCE_MODE="observe"
else
  ENFORCE_MODE="block"
fi

# ----- prereqs ---------------------------------------------------------------
command -v node >/dev/null || { echo "node required (see https://nodejs.org)"; exit 1; }

if [[ ! -x ./bin/flint-gateway ]] || [[ ! -x ./bin/flint-control ]]; then
  echo "binaries missing — run 'make build' first"
  exit 1
fi

# ----- fresh audit log -------------------------------------------------------
: > flint-audit.jsonl
echo "[exfil-demo] cleared flint-audit.jsonl"

# ----- cleanup ---------------------------------------------------------------
cleanup() {
  echo
  echo "[exfil-demo] shutting down..."
  kill "$UI_PID" "$GATEWAY_PID" "$CONTROL_PID" 2>/dev/null || true
  # children of gateway: node exfil_agent + node vulnerable-mcp
  pkill -P "$GATEWAY_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "[exfil-demo] done"
}
trap cleanup EXIT INT TERM

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
echo "[exfil-demo] control plane pid=$CONTROL_PID (log: .demo-control.log)"

# ----- start gateway with the attack agent driving its stdin -----------------
# The attack agent's stdout → gateway's agent-side stdin.
# The gateway proxies into the vulnerable MCP server.
# Gateway stdout (responses to agent) → /dev/null (agent is write-only, matches demo.sh).
( node scripts/exfil_agent.mjs | \
    ./bin/flint-gateway \
      --agent exfil-demo-bot \
      --enforce-mode "$ENFORCE_MODE" \
      --roles config/roles.demo.yaml \
      --bindings config/bindings.demo.yaml \
      --tools tools.demo.yaml \
      --audit flint-audit.jsonl \
      --http-addr 127.0.0.1:7476 \
      -- node scripts/vulnerable-mcp.mjs \
      > /dev/null
) > .demo-gateway.log 2>&1 &
GATEWAY_PID=$!
echo "[exfil-demo] gateway pid=$GATEWAY_PID (log: .demo-gateway.log)"

# ----- start UI dev server ---------------------------------------------------
( cd ui && [[ -d node_modules ]] || npm install --silent ) >> .demo-ui.log 2>&1
( cd ui && npm run dev -- --host 127.0.0.1 --port 5173 ) > .demo-ui.log 2>&1 &
UI_PID=$!
echo "[exfil-demo] ui pid=$UI_PID (log: .demo-ui.log)"

# ----- wait for ports --------------------------------------------------------
echo "[exfil-demo] waiting for control plane..."
./scripts/wait-port.sh 7475 20
echo "[exfil-demo] waiting for gateway sidecar..."
./scripts/wait-port.sh 7476 20
echo "[exfil-demo] waiting for UI..."
./scripts/wait-port.sh 5173 45

# ----- open browser ----------------------------------------------------------
( sleep 1 && open http://127.0.0.1:5173/sessions ) &

echo
echo "Flint exfil demo running:"
echo "  Dashboard:  http://127.0.0.1:5173"
echo "  REST API:   http://127.0.0.1:7475/api/v1/agents"
echo "  WS stream:  ws://127.0.0.1:7475/api/v1/stream"
echo "  Healthz:    http://127.0.0.1:7476/healthz (gateway)"
echo

if $OBSERVE_ONLY; then
  echo "Flint exfil demo running in OBSERVE-ONLY mode."
  echo "Findings will fire but the gateway will NOT block. The webhook POST will \"succeed\"."
else
  echo "Flint exfil demo running in ENFORCE mode (default)."
  echo "Re-run with --observe-only to see the same attack succeed without enforcement."
fi

echo
echo "Press Ctrl-C to stop."
wait
