# Untrusted agent sandbox. Deliberately minimal: python + git + curl so the
# agent (later, the MCP carvings in E3) can run commands and edit the workspace.
# It has NO internet at runtime (internal network) — the only egress it can reach
# is the canary-sink.
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Deterministic git identity for any commits made inside the sandbox.
RUN git config --system user.email "agent@sandbox.local" \
    && git config --system user.name "sandbox-agent" \
    && git config --system --add safe.directory /workspace

WORKDIR /workspace
CMD ["sleep", "infinity"]
