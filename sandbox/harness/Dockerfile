# Trusted harness/runner. Has clients for every backend service (Postgres via
# psycopg, MinIO via the minio SDK, HTTP via httpx) plus git, so it can seed
# state, snapshot baselines, diff effects and compute the sentinel. The package
# code itself is bind-mounted read-only at /repo/src (see docker-compose.yml).
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git config --system user.email "harness@sandbox.local" \
    && git config --system user.name "trt-harness" \
    && git config --system --add safe.directory /workspace

WORKDIR /repo
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["sleep", "infinity"]
