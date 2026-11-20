"""pre-episode baseline snapshots for each state channel.

Four channels, each with ``capture`` (snapshot current state) and ``diff``
(compare a before/after pair):

* **repo**     — the git working tree under the workspace (name-status diff);
* **postgres** — rows of every user table (set difference => added/removed);
* **minio**    — object keys + etags in the working bucket;
* **sink**     — the canary-sink event log, scoped by a monotonically-increasing
                 id offset so an episode only sees its own egress.

Snapshots are plain JSON-serializable dicts so a whole :class:`Baseline` round-
trips to disk between the ``baseline`` and ``extract`` CLI steps.

Client libraries (psycopg, minio, httpx) are imported lazily inside the methods
that need them, so this module (and the pure repo/sentinel logic) imports fine
on a host without those packages.
"""

from __future__ import annotations

import subprocess
from typing import Dict, List, Tuple

from .config import ServiceConfig


# --------------------------------------------------------------------------- #
# repo (git working tree)
# --------------------------------------------------------------------------- #
def _git(workspace: str, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", workspace, *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout


class RepoSnapshot:
    """Snapshot/diff the workspace git repo."""

    @staticmethod
    def ensure_repo(workspace: str) -> None:
        try:
            _git(workspace, "rev-parse", "--is-inside-work-tree")
        except subprocess.CalledProcessError:
            _git(workspace, "init", "-q")

    @staticmethod
    def capture(workspace: str) -> dict:
        """Commit the current tree as the baseline and record HEAD."""
        RepoSnapshot.ensure_repo(workspace)
        _git(workspace, "add", "-A")
        # --allow-empty so a clean tree still produces a baseline commit.
        _git(workspace, "commit", "-q", "-m", "episode-baseline", "--allow-empty")
        head = _git(workspace, "rev-parse", "HEAD").strip()
        return {"head": head}

    @staticmethod
    def diff(before: dict, workspace: str) -> dict:
        """Name-status diff of the working tree against the baseline commit."""
        head = before["head"]
        # intent-to-add so untracked files surface as additions in the diff
        _git(workspace, "add", "-A", "-N")
        raw = _git(
            workspace, "diff", "--name-status", "--no-renames", head, "--"
        ).strip()
        added: List[str] = []
        modified: List[str] = []
        deleted: List[str] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            status, _, path = line.partition("\t")
            path = path.strip()
            if status.startswith("A"):
                added.append(path)
            elif status.startswith("D"):
                deleted.append(path)
            else:  # M, T, etc.
                modified.append(path)
        return {
            "added": sorted(added),
            "modified": sorted(modified),
            "deleted": sorted(deleted),
        }


# --------------------------------------------------------------------------- #
# postgres
# --------------------------------------------------------------------------- #
def _pg_connect(cfg: ServiceConfig):
    import psycopg  # lazy

    return psycopg.connect(
        host=cfg.pg_host,
        port=cfg.pg_port,
        dbname=cfg.pg_db,
        user=cfg.pg_user,
        password=cfg.pg_password,
        connect_timeout=5,
    )


def _jsonable(v):
    if isinstance(v, (int, float, str, bool)) or v is None:
        return v
    return str(v)


class PostgresSnapshot:
    @staticmethod
    def capture(cfg: ServiceConfig) -> dict:
        """Snapshot every user table's rows as lists of stringified tuples."""
        tables: Dict[str, List[List]] = {}
        with _pg_connect(cfg) as conn:
            names = [
                r[0]
                for r in conn.execute(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema='public' AND table_type='BASE TABLE' "
                    "ORDER BY table_name"
                ).fetchall()
            ]
            for t in names:
                # identifier is from information_schema, not user input
                rows = conn.execute(f'SELECT * FROM "{t}" ORDER BY 1').fetchall()
                tables[t] = [[_jsonable(v) for v in row] for row in rows]
        return {"tables": tables}

    @staticmethod
    def diff(before: dict, after: dict) -> dict:
        out: Dict[str, dict] = {}
        b_tables = before.get("tables", {})
        a_tables = after.get("tables", {})
        for t in sorted(set(b_tables) | set(a_tables)):
            b_rows = {tuple(r) for r in b_tables.get(t, [])}
            a_rows = {tuple(r) for r in a_tables.get(t, [])}
            added = [list(r) for r in a_rows - b_rows]
            removed = [list(r) for r in b_rows - a_rows]
            if added or removed:
                out[t] = {
                    "added": sorted(added, key=str),
                    "removed": sorted(removed, key=str),
                }
        return out


# --------------------------------------------------------------------------- #
# minio
# --------------------------------------------------------------------------- #
def _minio_client(cfg: ServiceConfig):
    from minio import Minio  # lazy

    return Minio(
        cfg.minio_endpoint,
        access_key=cfg.minio_access_key,
        secret_key=cfg.minio_secret_key,
        secure=False,
    )


class MinioSnapshot:
    @staticmethod
    def capture(cfg: ServiceConfig) -> dict:
        client = _minio_client(cfg)
        objects: Dict[str, str] = {}
        for obj in client.list_objects(cfg.minio_bucket, recursive=True):
            objects[obj.object_name] = obj.etag
        return {"bucket": cfg.minio_bucket, "objects": objects}

    @staticmethod
    def diff(before: dict, after: dict) -> dict:
        b = before.get("objects", {})
        a = after.get("objects", {})
        added = sorted(set(a) - set(b))
        removed = sorted(set(b) - set(a))
        modified = sorted(k for k in set(a) & set(b) if a[k] != b[k])
        return {"added": added, "removed": removed, "modified": modified}


# --------------------------------------------------------------------------- #
# canary-sink
# --------------------------------------------------------------------------- #
class SinkSnapshot:
    @staticmethod
    def capture(cfg: ServiceConfig) -> dict:
        import httpx  # lazy

        r = httpx.get(f"{cfg.canary_sink_url}/events/count", timeout=5)
        r.raise_for_status()
        return {"max_id": int(r.json()["max_id"])}

    @staticmethod
    def diff(before: dict, cfg: ServiceConfig) -> dict:
        """Fetch events with id greater than the baseline offset."""
        import httpx  # lazy

        since = int(before.get("max_id", 0))
        r = httpx.get(
            f"{cfg.canary_sink_url}/events", params={"since": since}, timeout=5
        )
        r.raise_for_status()
        return {"events": r.json()["events"]}
