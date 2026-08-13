"""E5-T1/T2 — discretion δ(I) and δ_C(I) from effect clustering (Build Plan §1.6).

δ(I) = H(E | g, I): entropy (bits) of the effect distribution a policy produces
under interface I, averaged over tasks. Effects are clustered into classes by a
canonical *signature* of the state-diff E(τ); the clustering granularity is a
knob whose sensitivity we log (E5-T1).

δ_C(I): the count of catastrophic effect classes reachable under benign cover.
Here it is read off E1's static partition (reachable = |C| − |C_block|), tying
the empirical discretion axis back to Property-3 reachability.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Sequence, Tuple


def effect_signature(effect: dict, granularity: str = "coarse") -> Tuple:
    """Canonical class of a state-diff E(τ).

    coarse: which channels were touched (repo/pg/minio/sink).
    fine:   also the specific files / objects / tables / sink-count.
    """
    repo = effect.get("repo", {}) or {}
    pg = effect.get("postgres", {}) or {}
    minio = effect.get("minio", {}) or {}
    sink = effect.get("sink", {}) or {}

    repo_touch = bool(repo.get("added") or repo.get("modified") or repo.get("deleted"))
    pg_touch = bool(pg)
    minio_touch = bool(minio.get("added") or minio.get("modified") or minio.get("removed"))
    sink_touch = bool(sink.get("events"))

    channels = tuple(c for c, on in
                     (("repo", repo_touch), ("pg", pg_touch),
                      ("minio", minio_touch), ("sink", sink_touch)) if on)
    if granularity == "coarse":
        return channels

    files = tuple(sorted(repo.get("added", []) + repo.get("modified", [])))
    objs = tuple(sorted(minio.get("added", []) + minio.get("modified", [])))
    tables = tuple(sorted(pg.keys()))
    n_sink = len(sink.get("events", []))
    return (channels, files, objs, tables, n_sink)


def entropy_bits(items: Sequence) -> float:
    n = len(items)
    if n == 0:
        return 0.0
    counts = Counter(items)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def discretion(effects: Sequence[dict], granularity: str = "coarse") -> Tuple[float, int]:
    """Return (entropy_bits, n_distinct_classes) over a task's effect samples."""
    sigs = [effect_signature(e, granularity) for e in effects]
    return entropy_bits(sigs), len(set(sigs))


def discretion_by_carving(
    samples: Dict[str, Dict[str, List[dict]]], granularity: str = "coarse"
) -> Dict[str, float]:
    """samples[carving][task] -> list of effect dicts. Returns δ(I) per carving
    (task-averaged entropy)."""
    out: Dict[str, float] = {}
    for cid, tasks in samples.items():
        per_task = [discretion(effs, granularity)[0] for effs in tasks.values() if effs]
        out[cid] = sum(per_task) / len(per_task) if per_task else 0.0
    return out
