"""Core data model for the static Property-3 analyzer (E1).

The analyzer reasons about tool *interfaces* purely from their signatures:
no agent, no models, no GPU. Everything is a typed capability/data-location
graph and a set of catastrophic ``src -> sink`` effects.

Terminology (ref Build Plan §1.7, §2.6):

* **Node** -- a typed capability / data-location endpoint (e.g. ``repo``,
  ``pg_prod``, ``env_secrets``, the agent's own context ``agent``, and the
  single sanctioned egress ``external``).
* **Tool** -- a callable exposed by an interface. It *reads* from a set of
  ``In`` nodes and *writes/affects* a set of ``Out`` nodes. A tool induces a
  directed edge ``u -> v`` for every ``u in In`` and ``v in Out``.
* **Chokepoint tool** -- a *named, effect-transparent* tool whose invocation
  legibly reveals the effect it carries (e.g. ``export_data``). A generic
  opaque tool such as ``run_command`` is *not* a chokepoint even though every
  call flows through it, because a monitor cannot read the effect off the call.
* **CatastrophicEffect** -- an unwanted ``src -> sink`` reachability (each ``c``
  in the catastrophic set ``C``), e.g. exfiltration ``repo -> external``.
* **Interface** -- a carving: an ordered set of tools (A / B / C).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple


@dataclass(frozen=True)
class Node:
    """A typed capability / data-location node in the lattice."""

    id: str
    kind: str  # "data_location" | "channel" | "sink"
    label: str = ""
    sensitivity: str = "internal"  # internal | prod | secret | n/a


@dataclass(frozen=True)
class CatastrophicEffect:
    """One element ``c`` of the catastrophic effect set ``C``.

    An effect is a directed ``src -> sink`` reachability we do not want an
    interface to grant (or, failing that, that we want forced through a
    monitorable chokepoint).
    """

    id: str
    kind: str  # exfiltration | prod-mutation | credential-read | weight-access | ...
    src: str
    sink: str

    @property
    def pair(self) -> Tuple[str, str]:
        return (self.src, self.sink)


@dataclass(frozen=True)
class BenignPath:
    """A ``src -> sink`` reachability that legitimate tasks require.

    The union of these defines the benign task-completion set. Every carving
    must realize all of them; this is the confound control that keeps A/B/C
    information-matched (equal usefulness reach) so that differences in the
    catastrophic partition are attributable to *topology*, not to reach.
    """

    src: str
    sink: str
    note: str = ""

    @property
    def pair(self) -> Tuple[str, str]:
        return (self.src, self.sink)


@dataclass(frozen=True)
class Tool:
    """A tool signature: what it reads (``In``) and writes/affects (``Out``).

    ``chokepoint=True`` marks a *named, effect-transparent* tool -- the whole
    point of carving C. Edges induced by chokepoint tools are the only edges a
    concentrated monitor needs to watch for the effects they cut.
    """

    name: str
    reads: Tuple[str, ...]  # In capability labels
    writes: Tuple[str, ...]  # Out capability labels
    chokepoint: bool = False
    description: str = ""

    def edges(self) -> List[Tuple[str, str]]:
        """Directed edges induced by this tool: ``In x Out`` (minus self-loops)."""
        return [(u, v) for u in self.reads for v in self.writes if u != v]


@dataclass(frozen=True)
class Interface:
    """A carving: a named collection of tools over the shared capability set."""

    id: str  # "A" | "B" | "C"
    label: str
    tools: Tuple[Tool, ...]

    @property
    def chokepoint_tools(self) -> Tuple[Tool, ...]:
        return tuple(t for t in self.tools if t.chokepoint)


@dataclass(frozen=True)
class Lattice:
    """The shared capability lattice + catastrophic set + benign requirements.

    This is interface-independent: A, B and C are all evaluated against the
    same lattice, catastrophic set ``C`` and benign requirement set.
    """

    nodes: Tuple[Node, ...]
    catastrophic: Tuple[CatastrophicEffect, ...]
    benign: Tuple[BenignPath, ...]

    @property
    def node_ids(self) -> List[str]:
        return [n.id for n in self.nodes]

    def node(self, node_id: str) -> Node:
        for n in self.nodes:
            if n.id == node_id:
                return n
        raise KeyError(f"unknown node: {node_id!r}")

    def validate(self) -> None:
        """Fail loudly if effects/benign paths reference unknown nodes."""
        known = set(self.node_ids)
        if len(known) != len(self.nodes):
            raise ValueError("duplicate node ids in lattice")
        for c in self.catastrophic:
            missing = {c.src, c.sink} - known
            if missing:
                raise ValueError(
                    f"catastrophic effect {c.id!r} references unknown node(s): {sorted(missing)}"
                )
        for b in self.benign:
            missing = {b.src, b.sink} - known
            if missing:
                raise ValueError(
                    f"benign path {b.src}->{b.sink} references unknown node(s): {sorted(missing)}"
                )
