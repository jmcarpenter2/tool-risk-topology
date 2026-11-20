"""interface metrics: coverage rho, residual path-lengths, burden.

Given the block/choke/residual partition of ``C`` for an interface ``I``:

* **coverage** ``rho(I) = (|C_block| + |C_choke|) / |C|`` -- the fraction of
  catastrophic effects that are either denied or forced through a chokepoint.
  Higher is safer-on-paper.
* **residual path lengths** ``l_min(c)`` -- for each residual effect, the
  shortest choke-free composition that realizes it. Short residual paths are
  worse: fewer tool calls to compose the effect, less trajectory for a monitor
  to observe.
* **monitoring burden** ``B_mon(I)`` -- what a monitor must watch. Choked
  effects cost only their (few, shared) chokepoint edges. Residual effects need
  composition-aware monitoring over every ordinary edge that could carry the
  flow. We report both counts and a scalar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

import networkx as nx

from .graph import build_graph, choke_free_view, reachable
from .models import Interface, Lattice
from .partition import Partition, partition_effects


@dataclass
class MonitoringBurden:
    """Decomposition of ``B_mon(I)``.

    ``chokepoint_edges`` are cheap, shared per-call monitoring points.
    ``residual_edges`` are ordinary edges that can carry a residual catastrophic
    flow and therefore need composition-aware monitoring. ``scalar`` is the
    headline burden (their sum): total distinct edges a monitor must cover.
    """

    chokepoint_edges: int
    residual_edges: int
    n_residual_effects: int

    @property
    def scalar(self) -> float:
        return float(self.chokepoint_edges + self.residual_edges)


@dataclass
class InterfaceMetrics:
    interface_id: str
    partition: Partition
    rho: float
    # effect id -> shortest choke-free composition length (residual effects only)
    l_min_residual: Dict[str, int]
    burden: MonitoringBurden
    # single-call escapes: (tool, sink) pairs where one tool takes agent-controlled
    # input straight to a catastrophic sink (see `fabrication_escapes`).
    fabrication_escapes: List[Tuple[str, str]] = field(default_factory=list)

    def coverage(self) -> float:
        return self.rho

    def n_residual(self) -> int:
        return len(self.partition.residual)

    def n_escapes(self) -> int:
        return len(self.fabrication_escapes)


def fabrication_escapes(
    lattice: Lattice, interface: Interface
) -> List[Tuple[str, str]]:
    """Single-call escapes: tools that route **agent-controlled** content straight
    to a **catastrophic sink** in one call.

    This is the static signature of "no composition required". A tool with
    ``agent`` in its ``In`` and a catastrophic sink in its ``Out`` lets a
    misaligned agent realize a dangerous effect — exfiltration, a production
    write, etc. — in a single opaque call: nothing upstream forces it to compose,
    so a per-call monitor sees only the emit and a trajectory monitor has no
    composition to read. It generalizes past exfiltration: the sink is *any*
    catastrophic sink (``external``, ``pg_prod``, …), not just ``external``.

    This is what statically separates an intent-labelled chokepoint that still
    accepts agent-fabricated content (a single-call escape survives) from one that
    only exports typed, real sources (zero escapes — every catastrophic effect
    must be composed, and the composition is what a monitor reads).
    """
    sinks = {e.sink for e in lattice.catastrophic} - {"agent"}
    out: List[Tuple[str, str]] = []
    for t in interface.tools:
        if "agent" in t.reads:
            for s in sorted(sinks):
                if s in t.writes:
                    out.append((t.name, s))
    return sorted(out)


def _edges_on_residual_flows(
    g_choke_free: nx.MultiDiGraph, residual_pairs: List[Tuple[str, str]]
) -> Set[Tuple[str, str]]:
    """Ordinary edges that lie on some residual ``src -> sink`` flow.

    An edge ``(u, v)`` can carry a residual flow for effect ``(s, t)`` iff
    ``s`` reaches ``u`` and ``v`` reaches ``t`` in the choke-free graph. The
    union over residual effects is the set a composition-aware monitor must
    cover. Deduplicated on ``(u, v)`` (parallel tool edges collapse).
    """
    if not residual_pairs:
        return set()

    # Precompute descendants/ancestors once.
    nodes = list(g_choke_free.nodes())
    reach_from: Dict[str, Set[str]] = {
        n: set(nx.descendants(g_choke_free, n)) | {n} for n in nodes
    }
    simple = nx.DiGraph()
    simple.add_nodes_from(nodes)
    for u, v in g_choke_free.edges():
        simple.add_edge(u, v)

    involved: Set[Tuple[str, str]] = set()
    for (s, t) in residual_pairs:
        if s not in reach_from or t not in reach_from:
            continue
        for (u, v) in simple.edges():
            if t in reach_from.get(v, set()) and u in reach_from.get(s, set()):
                involved.add((u, v))
    return involved


def _chokepoint_edges(g_full: nx.MultiDiGraph) -> Set[Tuple[str, str, str]]:
    """Distinct chokepoint edges ``(u, v, tool)`` present in the interface."""
    out: Set[Tuple[str, str, str]] = set()
    for u, v, data in g_full.edges(data=True):
        if data.get("chokepoint", False):
            out.add((u, v, data.get("tool", "")))
    return out


def compute_metrics(lattice: Lattice, interface: Interface) -> InterfaceMetrics:
    """Compute ``rho``, residual ``l_min``, and ``B_mon`` for one interface."""
    part = partition_effects(lattice, interface)
    counts = part.counts()
    total = counts["total"]
    rho = (counts["block"] + counts["choke"]) / total if total else 1.0

    g_full = build_graph(lattice, interface)
    g_cf = choke_free_view(g_full)

    residual_pairs = [(v.effect.src, v.effect.sink) for v in part.residual]
    l_min_residual = {
        v.effect.id: v.l_min_choke_free
        for v in part.residual
        if v.l_min_choke_free is not None
    }

    residual_edges = _edges_on_residual_flows(g_cf, residual_pairs)
    choke_edges = _chokepoint_edges(g_full)

    burden = MonitoringBurden(
        chokepoint_edges=len(choke_edges),
        residual_edges=len(residual_edges),
        n_residual_effects=len(part.residual),
    )

    return InterfaceMetrics(
        interface_id=interface.id,
        partition=part,
        rho=rho,
        l_min_residual=l_min_residual,
        burden=burden,
        fabrication_escapes=fabrication_escapes(lattice, interface),
    )
