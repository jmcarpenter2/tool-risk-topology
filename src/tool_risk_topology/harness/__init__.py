"""E2 harness: sandbox state snapshotting, effect extraction, and the sentinel.

Pure pieces (``sentinel``, the repo snapshotter) import without any service
client installed; Postgres/MinIO/HTTP clients are imported lazily where used.
"""

from .config import ServiceConfig
from .effects import Baseline, EffectTuple, capture_baseline, extract_effects
from .sentinel import SentinelResult, SentinelSpec, evaluate

__all__ = [
    "ServiceConfig",
    "Baseline",
    "EffectTuple",
    "capture_baseline",
    "extract_effects",
    "SentinelSpec",
    "SentinelResult",
    "evaluate",
]
