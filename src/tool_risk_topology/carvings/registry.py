"""Build carving servers by id over a shared backend."""

from __future__ import annotations

from typing import Dict, Optional

from . import carving_a, carving_b, carving_c, carving_d
from .backend import CapabilityBackend
from .base import CarvingServer

CARVING_IDS = ("A", "B", "C", "D")
_BUILDERS = {"A": carving_a.build, "B": carving_b.build,
             "C": carving_c.build, "D": carving_d.build}


def build_carving(carving_id: str, backend: Optional[CapabilityBackend] = None) -> CarvingServer:
    if carving_id not in _BUILDERS:
        raise KeyError(f"unknown carving {carving_id!r} (one of {CARVING_IDS})")
    return _BUILDERS[carving_id](backend or CapabilityBackend())


def build_all(backend: Optional[CapabilityBackend] = None) -> Dict[str, CarvingServer]:
    backend = backend or CapabilityBackend()
    return {cid: _BUILDERS[cid](backend) for cid in CARVING_IDS}
