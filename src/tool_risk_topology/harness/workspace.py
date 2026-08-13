"""Seed the shared workspace repo (the `repo` capability node).

The trusted harness owns the git repo; the untrusted `app` sandbox only edits
the working tree. Seeding is idempotent: it (re)writes the seed files and makes
an initial commit if the repo has none.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .config import ServiceConfig
from .snapshot import RepoSnapshot

SEED_FILES = {
    "README.md": "# Sandbox workspace\n\nSeed repo for tool-risk-topology episodes.\n",
    "data/notes.txt": "initial notes\n",
    "src/app.py": 'def main():\n    print("hello from the sandbox app")\n',
}


def seed_workspace(cfg: ServiceConfig) -> dict:
    ws = Path(cfg.workspace_dir)
    ws.mkdir(parents=True, exist_ok=True)
    for rel, content in SEED_FILES.items():
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    RepoSnapshot.ensure_repo(str(ws))
    subprocess.run(["git", "-C", str(ws), "add", "-A"], check=True)
    # Commit only if there is something to commit (first seed) — otherwise leave
    # history alone so a re-seed is a no-op.
    has_head = (
        subprocess.run(
            ["git", "-C", str(ws), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
        ).returncode
        == 0
    )
    dirty = (
        subprocess.run(
            ["git", "-C", str(ws), "diff", "--cached", "--quiet"],
        ).returncode
        != 0
    )
    if dirty or not has_head:
        subprocess.run(
            ["git", "-C", str(ws), "commit", "-q", "-m", "seed workspace"],
            check=True,
        )
    head = subprocess.run(
        ["git", "-C", str(ws), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return {"workspace": str(ws), "head": head, "files": sorted(SEED_FILES)}


def reset_workspace(cfg: ServiceConfig) -> dict:
    """Per-episode teardown of the repo: wipe the working tree (except .git) and
    re-seed. Combined with sink reset this restores the two channels an episode
    dirties most; a full ephemeral reset is `docker compose down -v`.
    """
    ws = Path(cfg.workspace_dir)
    if ws.exists():
        for child in ws.iterdir():
            if child.name == ".git":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    return seed_workspace(cfg)
