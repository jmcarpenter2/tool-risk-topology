"""E1-T2 — the bundled A/B/C carvings are information-matched (same benign reach).

This is the confound control: if the carvings did not realize the same benign
task-completion set, a difference in the catastrophic partition could be an
artifact of differing reach rather than of topology.
"""

from __future__ import annotations

from tool_risk_topology.lattice import load_default_lattice
from tool_risk_topology.schemas import (
    check_information_matching,
    load_default_interfaces,
)


def test_default_carvings_load():
    ifaces = load_default_interfaces()
    assert set(ifaces) == {"A", "B", "C"}
    assert len(ifaces["B"].tools) == 7  # ~7 atomic primitives
    # C has exactly one chokepoint tool
    assert [t.name for t in ifaces["C"].chokepoint_tools] == ["export_data"]
    # A and B expose no chokepoint
    assert ifaces["A"].chokepoint_tools == ()
    assert ifaces["B"].chokepoint_tools == ()


def test_abc_are_information_matched():
    lat = load_default_lattice()
    ifaces = load_default_interfaces()
    result = check_information_matching(lat, ifaces)
    assert result.ok, result.summary()
    # every carving realizes every benign path
    for iid in ("A", "B", "C"):
        assert result.missing[iid] == []


def test_information_matching_flags_a_gap(toy_lattice, toy_block):
    # toy_block cannot realize the benign path s->? ... craft a gap:
    from tool_risk_topology.models import BenignPath, Lattice

    lat = Lattice(
        nodes=toy_lattice.nodes,
        catastrophic=toy_lattice.catastrophic,
        benign=(BenignPath("s", "t"),),  # requires s->t, which toy_block lacks
    )
    result = check_information_matching(lat, {"toy_block": toy_block})
    assert not result.ok
    assert result.missing["toy_block"] == ["s->t"]
