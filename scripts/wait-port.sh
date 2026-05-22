#!/usr/bin/env bash
# wait-port.sh — block until a TCP port on 127.0.0.1 accepts connections, or time out.
# Usage: wait-port.sh <port> [timeout_seconds]

set -euo pipefail

port="${1:?usage: wait-port.sh <port> [timeout]}"
timeout="${2:-30}"

for i in $(seq 1 "$timeout"); do
  if nc -z 127.0.0.1 "$port" 2>/dev/null; then
    exit 0
  fi
  sleep 1
done

echo "wait-port: timed out waiting for 127.0.0.1:$port after ${timeout}s" >&2
exit 1
