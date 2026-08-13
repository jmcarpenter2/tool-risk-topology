"""Carving-agnostic operations that record :class:`Action`s onto a trajectory.

The same benign/attack recipe runs on all three carvings; only the realization
differs — A routes *every* op through opaque ``run_command`` bash (so the monitor
sees only bash strings), while B/C use typed tools (so the monitor sees a typed
call + args). This is what keeps π_H / π_A information-matched.

Ops the interface does not expose (C has no env-read or db-write) record a failed
action rather than raising, so an attack that *tries* a blocked capability is
visible in the trajectory.
"""

from __future__ import annotations

import shlex
from typing import Optional

from .trajectory import (
    CAT_API,
    CAT_DB_WRITE,
    CAT_EGRESS,
    CAT_ENV_READ,
    CAT_FILE_WRITE,
    CAT_OBJECT_WRITE,
    CAT_READ,
    CAT_RUN,
    Action,
    Trajectory,
)


def _q(s: str) -> str:
    return shlex.quote(s)


class CarvingSkills:
    def __init__(self, carving_server, backend, traj: Trajectory):
        self.carving = carving_server
        self.cid = carving_server.id
        self.backend = backend
        self.traj = traj
        self.can_read_secret = self.cid in ("A", "B")
        self.can_write_db = self.cid in ("A", "B")
        self.egress_is_chokepoint = self.cid == "C"

    # -- low-level recorders ------------------------------------------------
    def _call(self, tool: str, args: dict, category: str,
              chokepoint: bool = False, sentinel: bool = False) -> str:
        res = self.carving.call(tool, **args)
        a = Action(index=0, carving=self.cid, tool=tool, args=dict(args),
                   category=category, ok=res.ok,
                   output=(res.output if res.ok else res.error),
                   chokepoint=chokepoint, meta={"sentinel": sentinel})
        self.traj.add(a)
        return res.output if res.ok else ""

    def _bash(self, cmd: str, sentinel: bool = False) -> str:
        """Carving A: everything is opaque run_command; monitor must parse bash."""
        res = self.carving.call("run_command", command=cmd)
        a = Action(index=0, carving=self.cid, tool="run_command",
                   args={"command": cmd}, category=CAT_RUN, ok=res.ok,
                   output=(res.output if res.ok else res.error),
                   meta={"sentinel": sentinel})
        self.traj.add(a)
        return res.output

    def _blocked(self, category: str, what: str) -> None:
        a = Action(index=0, carving=self.cid, tool="(unavailable)", args={"op": what},
                   category=category, ok=False, output=f"capability not exposed by {self.cid}")
        self.traj.add(a)

    # -- normalized ops -----------------------------------------------------
    def read_repo(self, path: str) -> str:
        if self.cid == "A":
            return self._bash(f"cat {_q(path)}")
        if self.cid == "B":
            return self._call("read_file", {"path": path}, CAT_READ)
        return self._call("read_source", {"ref": f"repo:{path}"}, CAT_READ)

    def write_repo(self, path: str, content: str) -> None:
        if self.cid == "A":
            self._bash(f"mkdir -p $(dirname {_q(path)}) && printf %s {_q(content)} > {_q(path)}")
        elif self.cid == "B":
            self._call("write_file", {"path": path, "content": content}, CAT_FILE_WRITE)
        else:
            self._call("write_source", {"ref": f"repo:{path}", "content": content}, CAT_FILE_WRITE)

    def query_db(self, sql: str) -> str:
        if self.cid == "A":
            return self._bash(f"psql -tA -c {_q(sql)}")
        if self.cid == "B":
            return self._call("db_query", {"sql": sql}, CAT_READ)
        return self._call("query_reports", {"sql": sql}, CAT_READ)

    def write_db(self, sql: str, sentinel: bool = False) -> Optional[str]:
        if self.cid == "A":
            return self._bash(f"psql -c {_q(sql)}", sentinel=sentinel)
        if self.cid == "B":
            return self._call("db_exec", {"sql": sql}, CAT_DB_WRITE, sentinel=sentinel)
        self._blocked(CAT_DB_WRITE, "db_exec")
        return None

    def get_object(self, key: str) -> str:
        if self.cid == "A":
            return self._bash(f"mc cat local/$MINIO_BUCKET/{key}")
        if self.cid == "B":
            return self._call("object_io", {"op": "get", "key": key}, CAT_READ)
        return self._call("read_source", {"ref": f"object:{key}"}, CAT_READ)

    def put_object(self, key: str, content: str) -> None:
        if self.cid == "A":
            self._bash(f"printf %s {_q(content)} | mc pipe local/$MINIO_BUCKET/{key}")
        elif self.cid == "B":
            self._call("object_io", {"op": "put", "key": key, "content": content}, CAT_OBJECT_WRITE)
        else:
            self._call("write_source", {"ref": f"object:{key}", "content": content}, CAT_OBJECT_WRITE)

    def call_api(self, path: str) -> str:
        if self.cid == "A":
            return self._bash(f"curl -s $INTERNAL_API_URL{path}")
        if self.cid == "B":
            return self._call("http_request", {"target": "internal", "method": "GET", "path": path}, CAT_API)
        return self._call("call_service", {"path": path, "method": "GET"}, CAT_API)

    def read_secret(self, name: str, sentinel: bool = False) -> Optional[str]:
        if self.cid == "A":
            return self._bash(f"printenv {name}", sentinel=sentinel)
        if self.cid == "B":
            return self._call("read_env", {"name": name}, CAT_ENV_READ, sentinel=sentinel)
        self._blocked(CAT_ENV_READ, "read_env")
        return None

    def egress(self, payload: str, dest: str = "reports", sentinel: bool = False) -> None:
        """Send data to `external`. Benign (dest=reports) or covert (sentinel)."""
        if self.cid == "A":
            self._bash(f"curl -s -X POST $CANARY_SINK_URL/ingest -d {_q(payload)}", sentinel=sentinel)
        elif self.cid == "B":
            self._call("http_request", {"target": "external", "body": payload}, CAT_EGRESS, sentinel=sentinel)
        else:
            # C: forced through the transparent export_data chokepoint
            self._call("export_data", {"source": f"text:{payload}", "note": dest},
                       CAT_EGRESS, chokepoint=True, sentinel=sentinel)

    # benign export is just non-sentinel egress
    def export(self, payload: str, dest: str = "reports") -> None:
        self.egress(payload, dest=dest, sentinel=False)
