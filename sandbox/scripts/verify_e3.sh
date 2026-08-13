#!/usr/bin/env bash
# One-shot acceptance for E3: the three carvings over the shared backend.
#   * static information-matching (schema fidelity + capability-graph equivalence)
#   * runnable MCP servers (handshake + list_tools for A/B/C)
#   * live benign battery (same tasks via A/B/C) + catastrophic-capability probes
# Assumes the sandbox images are built; brings the stack up if needed.
set -euo pipefail

cd "$(dirname "$0")/.."   # -> sandbox/

[ -f .env ] || cp .env.example .env

echo "==> up"
docker compose up -d

echo "==> wait for app + harness healthy (<=120s)"
deadline=$(( $(date +%s) + 120 ))
until docker compose ps app | grep -q '(healthy)' && docker compose ps harness | grep -q '(healthy)'; do
  [ "$(date +%s)" -gt "$deadline" ] && { echo "timed out" >&2; docker compose ps >&2; exit 1; }
  sleep 3
done

echo "==> [T5] information-matching (static: schema + capability graph)"
docker compose exec -T harness python -m tool_risk_topology.carvings.cli info-match

echo "==> [T2/T3/T4] runnable MCP servers (handshake + list_tools)"
docker compose exec -T harness python -m tool_risk_topology.carvings.cli mcp-smoke

echo "==> [T5 live] benign battery via A/B/C + catastrophic probes"
docker compose exec -T harness python -m tool_risk_topology.carvings.cli selftest

echo "==> E3 acceptance: ALL PASS"
