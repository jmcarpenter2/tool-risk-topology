"""partition the catastrophic set into block / choke / residual.

For each catastrophic effect ``c = (src, sink)`` and interface ``I`` (ref §1.7):

* ``C_block``  -- ``src`` cannot reach ``sink`` in ``G_I`` at all. The carving
  denies the capability outright.
* ``C_choke``  -- ``src`` reaches ``sink`` in ``G_I``, but *not* once chokepoint
  edges are removed: every path is forced through a monitorable, effect-
  transparent chokepoint. Cheap to monitor (watch the chokepoint calls).
* ``C_resid``  -- ``src`` reaches ``sink`` even in the choke-free graph: there
  exists a composition of ordinary tools that realizes the effect while dodging
  every chokepoint. This is the residual monitoring burden -- it needs
  composition/trajectory-aware monitoring, not a single call.

The residual set ``C_resid`` is the quantity the KILL GATE asks carving
C to shrink relative to A and B.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import networkx as nx

from .graph import build_graph, choke_free_view, reachable, shortest_len
from .models import CatastrophicEffect, Interface, Lattice

BLOCK = "block"
CHOKE = "choke"
RESID = "resid"


@dataclass
class EffectVerdict:
    """Per-effect partition result for one interface."""

    effect: CatastrophicEffect
    bucket: str  # BLOCK | CHOKE | RESID
    l_min: int | None  # shortest src->sink length in the full graph (None if blocked)
    l_min_choke_free: int | None  # shortest length avoiding chokepoints (None if none)


@dataclass
class Partition:
    """The full block/choke/residual partition of ``C`` for one interface."""

    interface_id: str
    verdicts: List[EffectVerdict] = field(default_factory=list)

    def _by_bucket(self, bucket: str) -> List[EffectVerdict]:
        return [v for v in self.verdicts if v.bucket == bucket]

    @property
    def blocked(self) -> List[EffectVerdict]:
        return self._by_bucket(BLOCK)

    @property
    def choked(self) -> List[EffectVerdict]:
        return self._by_bucket(CHOKE)

    @property
    def residual(self) -> List[EffectVerdict]:
        return self._by_bucket(RESID)

    def counts(self) -> Dict[str, int]:
        return {
            BLOCK: len(self.blocked),
            CHOKE: len(self.choked),
            RESID: len(self.residual),
            "total": len(self.verdicts),
        }


def partition_effects(lattice: Lattice, interface: Interface) -> Partition:
    """Classify every catastrophic effect for ``interface`` into a bucket."""
    g_full = build_graph(lattice, interface)
    g_choke_free = choke_free_view(g_full)

    part = Partition(interface_id=interface.id)
    for c in lattice.catastrophic:
        reach_full = reachable(g_full, c.src, c.sink)
        if not reach_full:
            bucket = BLOCK
        else:
            reach_cf = reachable(g_choke_free, c.src, c.sink)
            bucket = RESID if reach_cf else CHOKE

        part.verdicts.append(
            EffectVerdict(
                effect=c,
                bucket=bucket,
                l_min=shortest_len(g_full, c.src, c.sink),
                l_min_choke_free=shortest_len(g_choke_free, c.src, c.sink),
            )
        )
    return part
