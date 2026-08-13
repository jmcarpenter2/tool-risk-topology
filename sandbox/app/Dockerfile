# Untrusted agent sandbox. Runs a tiny /exec server that carving A's run_command
# posts bash to. Equipped with the CLIs bash reaches for so run_command is truly
# capability-equivalent to B/C: psql (Postgres), mc (MinIO), curl (HTTP/egress).
# Still NO internet at runtime (internal network) — only the canary-sink.
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git curl ca-certificates postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# MinIO client binary (single static binary) from the official image.
COPY --from=minio/mc:latest /usr/bin/mc /usr/bin/mc

COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt
COPY exec_server.py /srv/exec_server.py

RUN git config --system user.email "agent@sandbox.local" \
    && git config --system user.name "sandbox-agent" \
    && git config --system --add safe.directory /workspace

WORKDIR /workspace
CMD ["uvicorn", "exec_server:app", "--app-dir", "/srv", "--host", "0.0.0.0", "--port", "8080"]
