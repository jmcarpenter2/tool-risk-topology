"""baseline capture and effect extraction ``E(τ)``.

A :class:`Baseline` bundles the four channel snapshots taken *before* an episode
plus run identity (config hash + seed). After the episode, :func:`extract_effects`
re-captures each channel and diffs it against the baseline to produce an
:class:`EffectTuple` -- the ``E(τ)`` the sentinel and (later) the discretion/
legibility instrumentation consume.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Union

from .config import ServiceConfig
from .snapshot import MinioSnapshot, PostgresSnapshot, RepoSnapshot, SinkSnapshot

PathLike = Union[str, Path]


@dataclass
class Baseline:
    config_hash: str
    seed: int
    captured_at: float
    repo: dict
    postgres: dict
    minio: dict
    sink: dict

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Baseline":
        return cls(**d)

    def save(self, path: PathLike) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: PathLike) -> "Baseline":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass
class EffectTuple:
    """``E(τ)`` -- the state delta an episode produced across all channels."""

    repo: dict = field(default_factory=dict)
    postgres: dict = field(default_factory=dict)
    minio: dict = field(default_factory=dict)
    sink: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def is_empty(self) -> bool:
        repo_empty = not any(self.repo.get(k) for k in ("added", "modified", "deleted"))
        pg_empty = not self.postgres
        minio_empty = not any(
            self.minio.get(k) for k in ("added", "removed", "modified")
        )
        sink_empty = not self.sink.get("events")
        return repo_empty and pg_empty and minio_empty and sink_empty


def capture_baseline(cfg: ServiceConfig, seed: int = 0) -> Baseline:
    return Baseline(
        config_hash=cfg.config_hash(seed),
        seed=seed,
        captured_at=time.time(),
        repo=RepoSnapshot.capture(cfg.workspace_dir),
        postgres=PostgresSnapshot.capture(cfg),
        minio=MinioSnapshot.capture(cfg),
        sink=SinkSnapshot.capture(cfg),
    )


def extract_effects(baseline: Baseline, cfg: ServiceConfig) -> EffectTuple:
    return EffectTuple(
        repo=RepoSnapshot.diff(baseline.repo, cfg.workspace_dir),
        postgres=PostgresSnapshot.diff(
            baseline.postgres, PostgresSnapshot.capture(cfg)
        ),
        minio=MinioSnapshot.diff(baseline.minio, MinioSnapshot.capture(cfg)),
        sink=SinkSnapshot.diff(baseline.sink, cfg),
    )
