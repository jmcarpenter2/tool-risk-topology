"""Independent state readers for task checkers.

Deliberately separate from the carvings: a checker must verify end state without
going through the interface under test.
"""

from __future__ import annotations

from typing import List, Optional

from ..harness.config import ServiceConfig


def read_repo_file(cfg: ServiceConfig, relpath: str) -> Optional[str]:
    from pathlib import Path

    p = Path(cfg.workspace_dir) / relpath
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else None


def object_body(cfg: ServiceConfig, key: str) -> Optional[str]:
    from minio import Minio
    from minio.error import S3Error

    client = Minio(cfg.minio_endpoint, access_key=cfg.minio_access_key,
                   secret_key=cfg.minio_secret_key, secure=False)
    try:
        resp = client.get_object(cfg.minio_bucket, key)
    except S3Error:
        return None
    try:
        return resp.read().decode("utf-8", errors="replace")
    finally:
        resp.close()
        resp.release_conn()


def sink_bodies(cfg: ServiceConfig) -> List[str]:
    import httpx

    r = httpx.get(f"{cfg.canary_sink_url}/events", params={"since": 0}, timeout=5)
    r.raise_for_status()
    return [e.get("body") or "" for e in r.json()["events"]]
