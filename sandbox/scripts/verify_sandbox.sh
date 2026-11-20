#!/usr/bin/env bash
# One-shot acceptance: build, bring the stack up healthy, and run every
# gate — network isolation (T2), harness self-test across all effect channels
# (T3/T5/T6), and the Inspect skeleton eval (T4).
set -euo pipefail

cd "$(dirname "$0")/.."   # -> sandbox/

[ -f .env ] || cp .env.example .env

echo "==> build"
docker compose build

echo "==> up"
docker compose up -d

echo "==> wait for app + harness to become healthy (<=120s)"
deadline=$(( $(date +%s) + 120 ))
until docker compose ps app | grep -q '(healthy)' && docker compose ps harness | grep -q '(healthy)'; do
  if [ "$(date +%s)" -gt "$deadline" ]; then
    echo "timed out waiting for health" >&2
    docker compose ps >&2
    exit 1
  fi
  sleep 3
done

echo "==> [T1] service status"
docker compose ps --format 'table {{.Service}}\t{{.Status}}'

echo "==> [T2] egress / isolation test"
./scripts/egress_test.sh

echo "==> [T3/T5/T6] harness self-test (benign + attack episodes)"
docker compose exec -T harness python -m tool_risk_topology.harness.cli selftest

echo "==> [T4] inspect_ai skeleton eval"
docker compose exec -T harness python -m tool_risk_topology.harness.inspect_task --seed 0

echo "==> acceptance: ALL PASS"
