#!/usr/bin/env bash
# E2-T2 — prove the agent container is network-isolated:
#   * it CAN reach the canary-sink (the modeled egress), and
#   * it CANNOT reach the public internet (by IP or by DNS name).
# Exit non-zero if isolation is broken.
set -euo pipefail

cd "$(dirname "$0")/.."   # -> sandbox/

echo "[egress] app -> canary-sink (expect OK)"
docker compose exec -T app python -c \
  "import urllib.request as u; assert u.urlopen('http://canary-sink:8001/healthz', timeout=5).read(); print('  reachable: canary-sink')"

echo "[egress] app -> public IP 1.1.1.1:443 (expect BLOCKED)"
if docker compose exec -T app python -c \
  "import socket; socket.setdefaulttimeout(6); socket.create_connection(('1.1.1.1',443),6)" 2>/dev/null; then
  echo "  ISOLATION BROKEN: reached public IP" >&2; exit 1
else
  echo "  blocked: public IP unroutable"
fi

echo "[egress] app -> example.com:443 (expect BLOCKED)"
if docker compose exec -T app python -c \
  "import socket; socket.setdefaulttimeout(6); socket.create_connection((socket.gethostbyname('example.com'),443),6)" 2>/dev/null; then
  echo "  ISOLATION BROKEN: reached example.com" >&2; exit 1
else
  echo "  blocked: public DNS/route unavailable"
fi

echo "[egress] PASS — agent is isolated; only the canary-sink is reachable."
