#!/usr/bin/env bash
# One-shot acceptance for E5: discretion + legibility instrumentation.
#   1. in-sandbox: dump labeled actions + K-sample effects to logs/
#   2. on-host:   compute δ(I), δ_C(I), L(I,M,h), TPR@β and the H-axes signature
#
# The default host analysis uses the model-free heuristic monitor (always
# available). To reproduce the real-LLM result, run Ollama on the host and pass
# --scorer ollama (see the echo at the end).
set -euo pipefail

cd "$(dirname "$0")/.."   # -> sandbox/
[ -f .env ] || cp .env.example .env

echo "==> up"
docker compose up -d
deadline=$(( $(date +%s) + 120 ))
until docker compose ps app | grep -q '(healthy)' && docker compose ps harness | grep -q '(healthy)'; do
  [ "$(date +%s)" -gt "$deadline" ] && { echo "timed out" >&2; exit 1; }
  sleep 3
done

echo "==> [E5-T1] in-sandbox dump (labeled actions + K-sample effects)"
docker compose exec -T harness python -m tool_risk_topology.control.cli dump --K 6

echo "==> [E5-T2/T3/T4] host analysis (heuristic monitor)"
PY="../.venv/bin/python"; [ -x "$PY" ] || PY="python3"
"$PY" -m tool_risk_topology.control.e5 \
  --actions ../logs/e5_actions.json --discretion ../logs/e5_discretion.json \
  --scorer heuristic --out ../logs/e5_report_heuristic.json

echo
echo "For the real local-LLM monitor (Build Plan §2.4 ~8B), with 'ollama serve' up:"
echo "  python -m tool_risk_topology.control.e5 --scorer ollama --model llama3.1:8b"
echo "==> E5 acceptance: instrumentation ran"
