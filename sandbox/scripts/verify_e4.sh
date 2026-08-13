#!/usr/bin/env bash
# One-shot acceptance for E4: policies + monitor + audit.
#   * π_H solves the benign task suite under A/B/C (usefulness)
#   * π_A achieves the sentinel under A/B/C (attacker strength logged)
#   * monitor scores at h ∈ {1, T, chokepoint}; audit threshold θ_β + safety
# Machinery only — the statistical H-* verdicts are E6.
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

echo "==> [E4] control self-test (policies + monitor + audit)"
docker compose exec -T harness python -m tool_risk_topology.control.cli selftest

echo "==> E4 acceptance: ALL PASS"
