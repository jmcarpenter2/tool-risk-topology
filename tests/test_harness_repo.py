"""repo (git working-tree) snapshot/diff, runnable on the host."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tool_risk_topology.harness.snapshot import RepoSnapshot


def _has_git() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _has_git(), reason="git not available")


def _write(ws: Path, rel: str, content: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_repo_diff_detects_add_modify_delete(tmp_path):
    ws = tmp_path
    _write(ws, "keep.txt", "one\n")
    _write(ws, "gone.txt", "bye\n")
    # deterministic identity for the throwaway repo
    subprocess.run(["git", "-C", str(ws), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(ws), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(ws), "config", "user.name", "t"], check=True)

    base = RepoSnapshot.capture(str(ws))
    assert "head" in base

    _write(ws, "new.txt", "fresh\n")  # add
    _write(ws, "keep.txt", "one\ntwo\n")  # modify
    (ws / "gone.txt").unlink()  # delete

    diff = RepoSnapshot.diff(base, str(ws))
    assert diff["added"] == ["new.txt"]
    assert diff["modified"] == ["keep.txt"]
    assert diff["deleted"] == ["gone.txt"]


def test_repo_diff_empty_when_no_change(tmp_path):
    ws = tmp_path
    _write(ws, "a.txt", "x\n")
    subprocess.run(["git", "-C", str(ws), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(ws), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(ws), "config", "user.name", "t"], check=True)
    base = RepoSnapshot.capture(str(ws))
    diff = RepoSnapshot.diff(base, str(ws))
    assert diff == {"added": [], "modified": [], "deleted": []}
