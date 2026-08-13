"""E1-T3 -- build the reachability graph ``G_I`` for an interface.

``G_I`` is a directed multigraph over capability nodes. Each tool contributes a
parallel edge ``u -> v`` for every ``u in In`` and ``v in Out`` it declares,
tagged with the originating tool and whether that tool is a chokepoint.

Two subgraphs matter for the bucket partition (E1-T4):

* the **full** graph ``G_I`` -- all induced edges;
* the **choke-free** graph -- ``G_I`` with every chokepoint edge removed.

An effect ``src -> sink`` is *choked* exactly when it is reachable in the full
graph but not in the choke-free graph, i.e. the chokepoint edges form a cut for
that ``src -> sink`` pair (every path traverses at least one chokepoint).
"""

from __future__ import annotations

from typing import Optional

import networkx as nx

from .models import Interface, Lattice


def build_graph(lattice: Lattice, interface: Interface) -> nx.MultiDiGraph:
    """Construct ``G_I`` for ``interface`` over the lattice's capability nodes."""
    g = nx.MultiDiGraph()
    for node in lattice.nodes:
        g.add_node(node.id, kind=node.kind, sensitivity=node.sensitivity)
    for tool in interface.tools:
        for (u, v) in tool.edges():
            # Tolerate tools referencing only lattice nodes; unknown nodes are
            # created implicitly by networkx, which would hide a schema typo, so
            # guard explicitly.
            for endpoint in (u, v):
                if endpoint not in g:
                    raise ValueError(
                        f"tool {tool.name!r} references unknown node {endpoint!r}"
                    )
            g.add_edge(u, v, tool=tool.name, chokepoint=tool.chokepoint)
    return g


def choke_free_view(g: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """Return a copy of ``g`` with all chokepoint edges removed."""
    h = nx.MultiDiGraph()
    h.add_nodes_from(g.nodes(data=True))
    for u, v, key, data in g.edges(keys=True, data=True):
        if not data.get("chokepoint", False):
            h.add_edge(u, v, key=key, **data)
    return h


def reachable(g: nx.MultiDiGraph, src: str, sink: str) -> bool:
    """True iff there is a directed path ``src -> sink`` (src != sink assumed)."""
    if src not in g or sink not in g:
        return False
    if src == sink:
        return True
    return nx.has_path(g, src, sink)


def shortest_len(g: nx.MultiDiGraph, src: str, sink: str) -> Optional[int]:
    """Shortest directed path length (in edges), or ``None`` if unreachable."""
    if not reachable(g, src, sink):
        return None
    if src == sink:
        return 0
    return nx.shortest_path_length(g, src, sink)
