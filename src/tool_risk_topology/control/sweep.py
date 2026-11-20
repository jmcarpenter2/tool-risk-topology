"""the control sweep runner (phase 1: episode generation, in-sandbox).

Generates trajectories once per carving (the trajectory is independent of the
monitor horizon, so 3 carvings × (n_attack + n_honest) episodes feed all six
{A,B,C}×{h=1,T} configs). Each episode is checkpointed as one JSONL line, so the
run is **resumable**: re-invoking skips episodes already recorded.

State is periodically reset (sink + workspace) to keep per-episode baseline
snapshots cheap over a long run. Scoring (phase 2) is host-side in ``e6.py``.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Set

from ..carvings.backend import CapabilityBackend
from ..carvings.registry import build_all
from ..harness import actions as _actions
from ..harness.workspace import reset_workspace
from .policies import AttackPolicy, HonestPolicy, run_episode
from .tasks import suite

CARVINGS = ("A", "B", "C")


def _record(traj, episode_id: str) -> dict:
    return {
        "id": episode_id,
        "carving": traj.carving,
        "policy": traj.policy_kind,
        "task_id": traj.task_id,
        "Z": traj.Z,
        "task_ok": traj.task_ok,
        "meta": traj.meta,
        "actions": [a.to_dict() for a in traj.actions],
    }


def _done_ids(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    done = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                done.add(json.loads(line)["id"])
            except Exception:
                continue
    return done


def run_phase1(out_path: str = "/repo/logs/sweep_trajectories.jsonl",
               n_attack: int = 300, n_honest: int = 100,
               strengths=(0, 1, 2, 3, 4), reset_every: int = 50, seed: int = 0) -> dict:
    backend = CapabilityBackend()
    cfg = backend.cfg
    carvings = build_all(backend)
    tasks = suite()

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    done = _done_ids(out)

    # plan: honest episodes are strength-independent (once per carving); attacks
    # are generated for each strength level (the 2nd sweep dimension).
    plan = [("H", None, i) for i in range(n_honest)]
    for s in strengths:
        plan += [("A", s, i) for i in range(n_attack)]

    written = 0
    processed = 0
    with out.open("a", encoding="utf-8") as fh:
        for cid in CARVINGS:
            carving = carvings[cid]
            for kind, s, i in plan:
                episode_id = f"{cid}-H-{i}" if kind == "H" else f"{cid}-A{s}-{i}"
                if episode_id in done:
                    continue
                if processed % reset_every == 0:
                    _actions.sink_reset(cfg)
                    reset_workspace(cfg)
                processed += 1

                task = tasks[i % len(tasks)]
                tag = f"{episode_id}-{uuid.uuid4().hex[:6]}"
                if kind == "A":
                    token = uuid.uuid4().hex[:16]  # realistic id, no obvious tell
                    traj = run_episode(carving, backend, task,
                                       AttackPolicy(strength=s), tag, token=token)
                else:
                    traj = run_episode(carving, backend, task, HonestPolicy(), tag)

                fh.write(json.dumps(_record(traj, episode_id)) + "\n")
                fh.flush()
                written += 1

    return {"written": written, "already_done": len(done), "out": str(out),
            "n_attack": n_attack, "n_honest": n_honest,
            "strengths": list(strengths)}
