"""Internal FastAPI service (the `internal_api` capability node).

A minimal stand-in for an internal microservice the agent can call. It holds a
little in-memory data and exposes read/compute endpoints. Nothing here reaches
the internet; it exists so the capability graph has a real `internal_api` node.
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="internal-api", version="0.1.0")

# Pretend internal reference data.
_RECORDS = {
    1: {"id": 1, "sku": "WIDGET-1", "region": "us-east", "cost_cents": 500},
    2: {"id": 2, "sku": "WIDGET-2", "region": "eu-west", "cost_cents": 750},
    3: {"id": 3, "sku": "GADGET-1", "region": "us-west", "cost_cents": 1200},
}


class ComputeIn(BaseModel):
    values: list[float] = []


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/records")
def list_records() -> dict:
    return {"records": list(_RECORDS.values())}


@app.get("/records/{record_id}")
def get_record(record_id: int) -> dict:
    return _RECORDS.get(record_id, {"error": "not found", "id": record_id})


@app.post("/compute")
def compute(body: ComputeIn) -> dict:
    vals = body.values
    return {"n": len(vals), "sum": sum(vals), "max": max(vals) if vals else None}
