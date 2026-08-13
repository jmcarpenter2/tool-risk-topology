"""E3-T5 — information-matching / confound control for the runnable carvings.

Two static checks (no services needed), plus a live battery (see ``selftest``):

1. **schema fidelity** — each runnable carving's per-tool ``In``/``Out`` labels
   match its E1 schema in ``data/interfaces/{A,B,C}.yaml``. This guarantees the
   thing we *run* is the thing E1 *analyzed*.
2. **capability-graph equivalence** — feeding the runnable-derived schemas
   through E1's reachability analysis, all three carvings realize the *same*
   benign task-completion set (controls the granularity-vs-typedness confound).

Together with the live benign battery, this establishes that A/B/C differ only
in interface topology, not in reach.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..graph import build_graph, reachable
from ..lattice import load_default_lattice
from ..models import Interface, Tool
from ..schemas import check_information_matching, load_default_interfaces
from .base import CarvingServer
from .registry import build_all


def runnable_to_interface(server: CarvingServer) -> Interface:
    """Convert a runnable carving's declared schema into an E1 Interface."""
    tools = tuple(
        Tool(
            name=t.name,
            reads=tuple(t.in_labels),
            writes=tuple(t.out_labels),
            chokepoint=t.chokepoint,
        )
        for t in server.tools
    )
    return Interface(id=server.id, label=server.label, tools=tools)


def compare_to_e1(server: CarvingServer, e1_iface: Interface) -> List[str]:
    """Return human-readable mismatches between a runnable carving and its E1 YAML."""
    diffs: List[str] = []
    run_tools = {t.name: t for t in server.tools}
    e1_tools = {t.name: t for t in e1_iface.tools}
    if set(run_tools) != set(e1_tools):
        diffs.append(
            f"{server.id}: tool set differs "
            f"(runnable={sorted(run_tools)} e1={sorted(e1_tools)})"
        )
    for name in set(run_tools) & set(e1_tools):
        r, e = run_tools[name], e1_tools[name]
        if set(r.in_labels) != set(e.reads):
            diffs.append(f"{server.id}.{name}: In {sorted(r.in_labels)} != {sorted(e.reads)}")
        if set(r.out_labels) != set(e.writes):
            diffs.append(f"{server.id}.{name}: Out {sorted(r.out_labels)} != {sorted(e.writes)}")
        if r.chokepoint != e.chokepoint:
            diffs.append(f"{server.id}.{name}: chokepoint {r.chokepoint} != {e.chokepoint}")
    return diffs


@dataclass
class InfoMatchReport:
    schema_ok: bool
    schema_diffs: List[str] = field(default_factory=list)
    graph_ok: bool = False
    graph_summary: str = ""
    missing: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.schema_ok and self.graph_ok

    def summary(self) -> str:
        head = "PASS" if self.passed else "FAIL"
        lines = [f"E3-T5 information-matching: {head}"]
        lines.append(
            "  schema fidelity: "
            + ("OK" if self.schema_ok else "MISMATCH -> " + "; ".join(self.schema_diffs))
        )
        lines.append(f"  graph equivalence: {self.graph_summary}")
        return "\n".join(lines)


def run_info_match() -> InfoMatchReport:
    lattice = load_default_lattice()
    e1_ifaces = load_default_interfaces()
    servers = build_all()  # backend never touched (only schemas inspected)

    # 1. schema fidelity vs E1 YAML
    schema_diffs: List[str] = []
    for cid, server in servers.items():
        schema_diffs.extend(compare_to_e1(server, e1_ifaces[cid]))
    schema_ok = not schema_diffs

    # 2. capability-graph equivalence via E1's analysis, from runnable schemas
    runnable_ifaces = {cid: runnable_to_interface(s) for cid, s in servers.items()}
    info = check_information_matching(lattice, runnable_ifaces)

    return InfoMatchReport(
        schema_ok=schema_ok,
        schema_diffs=schema_diffs,
        graph_ok=info.ok,
        graph_summary=info.summary(),
        missing=info.missing,
    )
