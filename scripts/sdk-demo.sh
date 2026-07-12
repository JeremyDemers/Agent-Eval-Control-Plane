#!/usr/bin/env bash
set -euo pipefail

PORT="${SDK_DEMO_PORT:-8010}"
DATABASE_URL="${DATABASE_URL:-postgresql://aecontrol@127.0.0.1:55432/aecontrol}"
export DATABASE_URL

uv run aecontrol serve --port "${PORT}" >/tmp/aecontrol-sdk-demo.log 2>&1 &
server_pid=$!
trap 'kill "${server_pid}" 2>/dev/null || true' EXIT

for _ in {1..40}; do
  if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null
uv run python examples/sdk_client.py --url "http://127.0.0.1:${PORT}"
