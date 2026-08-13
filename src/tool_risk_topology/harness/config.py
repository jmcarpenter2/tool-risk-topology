"""Service connection config for the harness, read from the environment.

The env var names match those set on the `harness` service in
``sandbox/docker-compose.yml``. Defaults mirror ``sandbox/.env.example`` so the
harness also runs against a locally port-forwarded stack if desired.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ServiceConfig:
    pg_host: str = "postgres"
    pg_port: int = 5432
    pg_db: str = "sandbox"
    pg_user: str = "sandbox"
    pg_password: str = "sandbox_pw"

    minio_endpoint: str = "minio:9000"
    minio_access_key: str = "sandbox"
    minio_secret_key: str = "sandbox_pw"
    minio_bucket: str = "working"

    internal_api_url: str = "http://internal-api:8000"
    canary_sink_url: str = "http://canary-sink:8001"

    workspace_dir: str = "/workspace"

    @classmethod
    def from_env(cls, env=None) -> "ServiceConfig":
        e = os.environ if env is None else env
        return cls(
            pg_host=e.get("POSTGRES_HOST", "postgres"),
            pg_port=int(e.get("POSTGRES_PORT", "5432")),
            pg_db=e.get("POSTGRES_DB", "sandbox"),
            pg_user=e.get("POSTGRES_USER", "sandbox"),
            pg_password=e.get("POSTGRES_PASSWORD", "sandbox_pw"),
            minio_endpoint=e.get("MINIO_ENDPOINT", "minio:9000"),
            minio_access_key=e.get("MINIO_ACCESS_KEY", "sandbox"),
            minio_secret_key=e.get("MINIO_SECRET_KEY", "sandbox_pw"),
            minio_bucket=e.get("MINIO_BUCKET", "working"),
            internal_api_url=e.get("INTERNAL_API_URL", "http://internal-api:8000"),
            canary_sink_url=e.get("CANARY_SINK_URL", "http://canary-sink:8001"),
            workspace_dir=e.get("WORKSPACE_DIR", "/workspace"),
        )

    def identity(self) -> dict:
        """Non-secret fields that identify a run (for the config hash)."""
        return {
            "pg": f"{self.pg_host}:{self.pg_port}/{self.pg_db}",
            "minio": f"{self.minio_endpoint}/{self.minio_bucket}",
            "internal_api": self.internal_api_url,
            "canary_sink": self.canary_sink_url,
            "workspace": self.workspace_dir,
        }

    def config_hash(self, seed: int = 0) -> str:
        payload = {"config": self.identity(), "seed": seed}
        blob = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()[:16]
