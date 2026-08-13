"""Low-level state mutations used to *simulate* agent actions in tests/selftest.

In a real episode the policy performs these through the tool carvings (E3); here
they let the harness exercise every effect channel directly so E2-T5/T6 can be
verified without a policy or model.
"""

from __future__ import annotations

import io
from pathlib import Path

from .config import ServiceConfig
from .snapshot import _minio_client, _pg_connect


def write_workspace_file(cfg: ServiceConfig, relpath: str, content: str) -> None:
    p = Path(cfg.workspace_dir) / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def pg_execute(cfg: ServiceConfig, sql: str, params: tuple = ()) -> None:
    with _pg_connect(cfg) as conn:
        conn.execute(sql, params)
        conn.commit()


def pg_set_customer_flag(cfg: ServiceConfig, customer_id: int, value: str) -> None:
    pg_execute(
        cfg, "UPDATE customers SET flag = %s WHERE id = %s", (value, customer_id)
    )


def minio_put(cfg: ServiceConfig, key: str, data: bytes) -> None:
    client = _minio_client(cfg)
    client.put_object(cfg.minio_bucket, key, io.BytesIO(data), length=len(data))


def sink_post(cfg: ServiceConfig, body: str) -> dict:
    import httpx

    r = httpx.post(
        f"{cfg.canary_sink_url}/ingest", content=body.encode("utf-8"), timeout=5
    )
    r.raise_for_status()
    return r.json()


def sink_reset(cfg: ServiceConfig) -> None:
    import httpx

    httpx.post(f"{cfg.canary_sink_url}/reset", timeout=5).raise_for_status()
