"""E1-T1 -- load the capability lattice, catastrophic set ``C`` and benign set.

Reads three YAML files:

* ``capabilities.yaml`` -- typed capability/data-location nodes + labels.
* ``catastrophic.yaml`` -- the catastrophic effect set ``C``, each ``c`` as a
  ``(src, sink)`` pair with a ``kind`` (exfiltration / prod-mutation / ...).
* ``benign_edges.yaml`` -- the benign-required ``src -> sink`` reachabilities
  (the confound control used by the information-matching test).
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

import yaml

from .models import BenignPath, CatastrophicEffect, Lattice, Node

PathLike = Union[str, Path]


def _load_yaml(path: PathLike) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a top-level mapping")
    return data


def load_lattice(
    capabilities_path: PathLike,
    catastrophic_path: PathLike,
    benign_path: PathLike,
) -> Lattice:
    """Build a :class:`Lattice` from the three YAML sources."""
    caps = _load_yaml(capabilities_path)
    cats = _load_yaml(catastrophic_path)
    benign = _load_yaml(benign_path)

    nodes = tuple(
        Node(
            id=n["id"],
            kind=n["kind"],
            label=n.get("label", ""),
            sensitivity=n.get("sensitivity", "internal"),
        )
        for n in caps["nodes"]
    )

    effects = tuple(
        CatastrophicEffect(
            id=e["id"],
            kind=e["kind"],
            src=e["src"],
            sink=e["sink"],
        )
        for e in cats["effects"]
    )

    benign_paths = tuple(
        BenignPath(src=b["src"], sink=b["sink"], note=b.get("note", ""))
        for b in benign["required_paths"]
    )

    lattice = Lattice(nodes=nodes, catastrophic=effects, benign=benign_paths)
    lattice.validate()
    return lattice


def default_data_dir() -> Path:
    """Return the repo's ``data/`` directory (relative to this package)."""
    return Path(__file__).resolve().parents[2] / "data"


def load_default_lattice() -> Lattice:
    """Convenience loader for the bundled sandbox lattice."""
    d = default_data_dir()
    return load_lattice(
        d / "capabilities.yaml",
        d / "catastrophic.yaml",
        d / "benign_edges.yaml",
    )
