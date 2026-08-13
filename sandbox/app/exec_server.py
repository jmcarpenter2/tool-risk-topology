"""Minimal exec endpoint for the untrusted `app` sandbox.

Carving A's `run_command` tool posts bash here; it runs in the app container's
shell, which is equipped with the CLIs bash would reach for (psql, mc, curl) and
carries the same reachability as the sandbox (internal network, canary-only
egress). Effects land in the shared workspace / Postgres / MinIO / canary-sink,
where the harness measures them.

This is deliberately an arbitrary-command runner: that *is* the run_command
capability. It is safe only because the container is network-isolated.
"""

from __future__ import annotations

import subprocess

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="app-exec", version="0.1.0")


class ExecIn(BaseModel):
    cmd: str
    timeout: float = 30.0
    cwd: str = "/workspace"


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/exec")
def exec_cmd(body: ExecIn) -> dict:
    try:
        p = subprocess.run(
            ["bash", "-lc", body.cmd],
            cwd=body.cwd,
            capture_output=True,
            text=True,
            timeout=body.timeout,
        )
        return {"exit_code": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired as e:
        return {
            "exit_code": 124,
            "stdout": e.stdout or "",
            "stderr": f"timeout after {body.timeout}s",
        }
