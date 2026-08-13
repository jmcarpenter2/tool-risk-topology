"""Shared toy fixtures with hand-checkable partitions.

Toy lattice: s -> m -> t, plus an isolated node x. One catastrophic effect
c = (s, t). Three toy carvings exercise each bucket:

* ``toy_block``  -- only ``read`` (s->m). t unreachable  => BLOCK.
* ``toy_choke``  -- ``read`` (s->m) + chokepoint ``gate`` (m->t). The only s->t
                    path uses the chokepoint => CHOKE.
* ``toy_resid``  -- ``toy_choke`` plus a non-chokepoint ``bypass`` (m->t), so a
                    choke-free path exists => RESID.
"""

from __future__ import annotations

import pytest

from tool_risk_topology.models import (
    BenignPath,
    CatastrophicEffect,
    Interface,
    Lattice,
    Node,
    Tool,
)


@pytest.fixture
def toy_lattice() -> Lattice:
    nodes = (
        Node("s", "data_location", "source"),
        Node("m", "channel", "middle"),
        Node("t", "sink", "target"),
        Node("x", "data_location", "isolated"),
    )
    catastrophic = (CatastrophicEffect("c_st", "exfiltration", "s", "t"),)
    benign = (BenignPath("s", "m", "benign read"),)
    lat = Lattice(nodes=nodes, catastrophic=catastrophic, benign=benign)
    lat.validate()
    return lat


@pytest.fixture
def toy_block() -> Interface:
    return Interface(
        id="toy_block",
        label="block",
        tools=(Tool("read", reads=("s",), writes=("m",)),),
    )


@pytest.fixture
def toy_choke() -> Interface:
    return Interface(
        id="toy_choke",
        label="choke",
        tools=(
            Tool("read", reads=("s",), writes=("m",)),
            Tool("gate", reads=("m",), writes=("t",), chokepoint=True),
        ),
    )


@pytest.fixture
def toy_resid() -> Interface:
    return Interface(
        id="toy_resid",
        label="resid",
        tools=(
            Tool("read", reads=("s",), writes=("m",)),
            Tool("gate", reads=("m",), writes=("t",), chokepoint=True),
            Tool("bypass", reads=("m",), writes=("t",)),
        ),
    )
