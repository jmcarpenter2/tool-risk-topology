#!/usr/bin/env bash
# One-shot acceptance for E6: the 6-config control sweep {A,B,C}×{h=1,T}.
#   phase 1 (in-sandbox, resumable): generate trajectories
#   phase 2 (on-host): score with the monitor -> safety/usefulness/cost + Wilson CIs,
#                      H-nonmono (z, Bonferroni), H-horizon (diff-in-diff), frontier
#
# Defaults to a small n on the heuristic monitor for a fast smoke. Reproduce the
# full real-LLM result with: --n 300 and `--scorer ollama` (needs `ollama serve`).
set -euo pipefail

cd "$(dirname "$0")/.."   # -> sandbox/
[ -f .env ] || cp .env.example .env
N_ATTACK="${1:-20}"; N_HONEST="${2:-10}"; SCORER="${3:-heuristic}"; STRENGTHS="${4:-0,2,4}"

echo "==> up"
docker compose up -d
deadline=$(( $(date +%s) + 120 ))
until docker compose ps app | grep -q '(healthy)' && docker compose ps harness | grep -q '(healthy)'; do
  [ "$(date +%s)" -gt "$deadline" ] && { echo "timed out" >&2; exit 1; }; sleep 3
done

echo "==> [E6-T1] phase 1: trajectories (n_attack=$N_ATTACK n_honest=$N_HONEST strengths=$STRENGTHS)"
docker compose exec -T harness python -m tool_risk_topology.control.cli sweep \
  --out /repo/logs/e6_trajectories.jsonl --n-attack "$N_ATTACK" --n-honest "$N_HONEST" --strengths "$STRENGTHS"

echo "==> [E6-T2..T5] phase 2: score + metrics + tests + frontier (scorer=$SCORER)"
PY="../.venv/bin/python"; [ -x "$PY" ] || PY="python3"
"$PY" -m tool_risk_topology.control.e6 \
  --trajectories ../logs/e6_trajectories.jsonl --scorer "$SCORER" --out ../reports

echo "==> E6 acceptance: sweep + analysis produced (reports/e6_report.json, e6_frontier.png)"
