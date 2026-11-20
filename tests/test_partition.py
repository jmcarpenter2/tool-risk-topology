"""bucket partition on toy graphs with known partitions."""

from __future__ import annotations

from tool_risk_topology.partition import BLOCK, CHOKE, RESID, partition_effects


def _bucket(part, effect_id):
    return next(v.bucket for v in part.verdicts if v.effect.id == effect_id)


def test_blocked_when_sink_unreachable(toy_lattice, toy_block):
    part = partition_effects(toy_lattice, toy_block)
    assert _bucket(part, "c_st") == BLOCK
    assert part.counts() == {BLOCK: 1, CHOKE: 0, RESID: 0, "total": 1}


def test_choked_when_every_path_uses_chokepoint(toy_lattice, toy_choke):
    part = partition_effects(toy_lattice, toy_choke)
    assert _bucket(part, "c_st") == CHOKE
    assert part.counts() == {BLOCK: 0, CHOKE: 1, RESID: 0, "total": 1}
    v = part.choked[0]
    assert v.l_min == 2  # s -> m -> t in the full graph
    assert v.l_min_choke_free is None  # no choke-free path


def test_residual_when_a_bypass_exists(toy_lattice, toy_resid):
    part = partition_effects(toy_lattice, toy_resid)
    assert _bucket(part, "c_st") == RESID
    assert part.counts() == {BLOCK: 0, CHOKE: 0, RESID: 1, "total": 1}
    v = part.residual[0]
    assert v.l_min == 2
    assert v.l_min_choke_free == 2  # bypass path exists and is length 2
