"""E1-T2 -- load interface (carving) schemas and check information-matching.

Each interface YAML lists tools with typed ``In``/``Out`` capability labels.
Three carvings ship with the project:

* **A** -- a single opaque ``run_command`` (reads/writes everything).
* **B** -- ~7 atomic primitives (capability-equivalent to A on benign reach).
* **C** -- intent-complete tools + one named ``export_data`` chokepoint.

The information-matching test (E1-T2 / E3-T5) guards against the
granularity-vs-typedness confound: it asserts that every carving realizes the
*same benign task-completion set*. Reach on the catastrophic-only capabilities
is *intentionally* allowed to differ -- that difference is the treatment
(carving C removes catastrophic-only reach and chokes the rest), not a
confound. Equal benign reach is what keeps usefulness matched across carvings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Union

import yaml

from .graph import build_graph, reachable
from .models import Interface, Lattice, Tool

PathLike = Union[str, Path]


def _load_yaml(path: PathLike) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a top-level mapping")
    return data


def load_interface(path: PathLike) -> Interface:
    """Load one carving from YAML."""
    data = _load_yaml(path)
    tools = tuple(
        Tool(
            name=t["name"],
            reads=tuple(t.get("in", []) or []),
            writes=tuple(t.get("out", []) or []),
            chokepoint=bool(t.get("chokepoint", False)),
            description=t.get("description", ""),
        )
        for t in data["tools"]
    )
    return Interface(id=data["id"], label=data.get("label", data["id"]), tools=tools)


def load_default_interfaces() -> Dict[str, Interface]:
    """Load the bundled A/B/C carvings, keyed by id."""
    d = Path(__file__).resolve().parents[2] / "data" / "interfaces"
    out: Dict[str, Interface] = {}
    for name in ("A", "B", "C", "D"):
        iface = load_interface(d / f"{name}.yaml")
        out[iface.id] = iface
    return out


@dataclass
class InfoMatchResult:
    """Outcome of the information-matching / confound-control check."""

    ok: bool
    # interface id -> list of benign (src, sink) pairs it fails to realize
    missing: Dict[str, List[str]]

    def summary(self) -> str:
        if self.ok:
            return "information-matched: all carvings realize the full benign set"
        parts = [
            f"{iface}: missing {', '.join(pairs)}"
            for iface, pairs in self.missing.items()
            if pairs
        ]
        return "NOT information-matched -> " + "; ".join(parts)


def check_information_matching(
    lattice: Lattice, interfaces: Dict[str, Interface]
) -> InfoMatchResult:
    """Assert every carving realizes the full benign task-completion set.

    Returns the per-interface set of benign paths that are *not* reachable.
    An empty set for all interfaces means the carvings are information-matched.
    """
    missing: Dict[str, List[str]] = {}
    all_ok = True
    for iid, iface in interfaces.items():
        g = build_graph(lattice, iface)
        gaps: List[str] = []
        for b in lattice.benign:
            if not reachable(g, b.src, b.sink):
                gaps.append(f"{b.src}->{b.sink}")
        missing[iid] = gaps
        if gaps:
            all_ok = False
    return InfoMatchResult(ok=all_ok, missing=missing)
