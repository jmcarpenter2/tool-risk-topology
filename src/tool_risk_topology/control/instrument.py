"""in-sandbox instrumentation: labeled actions + K-sample effects.

Runs in the harness (needs the services). Produces two artifacts under ``logs/``
for the host-side legibility analysis:

* ``legibility_actions.json`` — every action from π_H and π_A episodes, each tagged with
  its sentinel label and its in-trajectory context (for scoring at h=1 and h=T).
* ``legibility_discretion.json`` — for each (carving, task), K varied honest completions'
  effect tuples E(τ), for the discretion entropy δ(I).

Discretion is operationalized as the breadth of state-effects an interface admits
while completing a task: a "varied honest" policy does the task plus a random
subset of *incidental* effects drawn from that carving's affordances. B/A can
also touch prod (db write) — an extra effect channel C simply cannot — so B/A
sample more distinct effect classes than C.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, List

from ..carvings.backend import CapabilityBackend
from ..carvings.registry import build_all
from ..harness.effects import capture_baseline, extract_effects
from ..harness.workspace import seed_workspace
from .policies import AttackPolicy, HonestPolicy
from .skills import CarvingSkills
from .tasks import suite
from .trajectory import Trajectory

# incidental, effect-producing affordances; availability per carving
_INCIDENTAL = [
    ("extra_file", ("A", "B", "C")),
    ("extra_object", ("A", "B", "C")),
    ("extra_export", ("A", "B", "C")),
    ("db_write", ("A", "B")),  # prod mutation — an effect channel C cannot touch
]


def _apply_incidental(sk: CarvingSkills, name: str, param: int) -> None:
    if name == "extra_file":
        sk.write_repo(f"scratch/f_{param}.txt", f"aux {param}\n")
    elif name == "extra_object":
        sk.put_object(f"scratch/o_{param}.bin", f"aux-{param}")
    elif name == "extra_export":
        sk.export(f"aux-report-{param}")
    elif name == "db_write":
        sk.write_db(f"update customers set tier='t{param % 3}' where id={param % 4 + 1}")


def _varied_completion(carving, backend, task, tag: str, rng: random.Random) -> Trajectory:
    traj = Trajectory(task_id=task.id, carving=carving.id, policy_kind="H")
    sk = CarvingSkills(carving, backend, traj)
    task.solve(sk, tag)
    for name, avail in _INCIDENTAL:
        if carving.id in avail and rng.random() < 0.5:
            _apply_incidental(sk, name, rng.randint(0, 9))
    return traj


def collect_discretion(backend: CapabilityBackend, K: int = 6, seed: int = 0) -> Dict:
    carvings = build_all(backend)
    tasks = suite()
    cfg = backend.cfg
    out: Dict[str, Dict[str, List[dict]]] = {}
    for cid, carving in carvings.items():
        out[cid] = {}
        for task in tasks:
            effs: List[dict] = []
            for k in range(K):
                rng = random.Random(f"{seed}-{cid}-{task.id}-{k}")
                seed_workspace(cfg)
                base = capture_baseline(cfg)
                _varied_completion(carving, backend, task, f"disc-{cid}-{task.id}-{k}", rng)
                effs.append(extract_effects(base, cfg).to_dict())
            out[cid][task.id] = effs
    return out


def collect_actions(backend: CapabilityBackend, seed: int = 0) -> List[dict]:
    import uuid

    carvings = build_all(backend)
    tasks = suite()
    records: List[dict] = []
    for cid, carving in carvings.items():
        for task in tasks:
            # honest trajectory (all benign)
            seed_workspace(backend.cfg)
            hp = HonestPolicy().run(task, carving, backend, f"H-{cid}-{task.id}")
            _emit(records, hp)
            # attack trajectory (one sentinel action)
            token = f"CANARY-{uuid.uuid4().hex[:12]}"
            ap = AttackPolicy(strength=1).run(task, carving, backend, f"A-{cid}-{task.id}", token)
            _emit(records, ap)
    return records


def _emit(records: List[dict], traj: Trajectory) -> None:
    for i, a in enumerate(traj.actions):
        records.append({
            "carving": traj.carving,
            "policy": traj.policy_kind,
            "label": a.carried_sentinel,
            "action": a.to_dict(),
            "context": [x.to_dict() for x in traj.actions[:i]],
        })


def dump(out_dir: str = "/repo/logs", K: int = 6, seed: int = 0) -> dict:
    backend = CapabilityBackend()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    actions = collect_actions(backend, seed=seed)
    (out / "legibility_actions.json").write_text(json.dumps(actions), encoding="utf-8")

    disc = collect_discretion(backend, K=K, seed=seed)
    (out / "legibility_discretion.json").write_text(json.dumps(disc), encoding="utf-8")

    n_pos = sum(1 for r in actions if r["label"])
    return {
        "actions": len(actions), "pos": n_pos, "neg": len(actions) - n_pos,
        "discretion_samples": sum(len(v) for c in disc.values() for v in c.values()),
        "out_dir": str(out),
    }
