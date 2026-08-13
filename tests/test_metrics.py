"""E1-T5 — metrics match hand-calculation on the toy example."""

from __future__ import annotations

import pytest

from tool_risk_topology.metrics import compute_metrics


def test_choke_metrics_hand_calc(toy_lattice, toy_choke):
    m = compute_metrics(toy_lattice, toy_choke)
    # 1 choked, 0 residual, 0 blocked  => rho = 1.0
    assert m.rho == pytest.approx(1.0)
    assert m.n_residual() == 0
    # only the single chokepoint edge (m->t) needs watching
    assert m.burden.chokepoint_edges == 1
    assert m.burden.residual_edges == 0
    assert m.burden.scalar == pytest.approx(1.0)
    assert m.l_min_residual == {}


def test_residual_metrics_hand_calc(toy_lattice, toy_resid):
    m = compute_metrics(toy_lattice, toy_resid)
    # 1 residual => rho = 0.0
    assert m.rho == pytest.approx(0.0)
    assert m.n_residual() == 1
    # residual flow s->m->t touches both ordinary edges (s,m) and (m,t)
    assert m.burden.residual_edges == 2
    # the chokepoint gate edge (m->t) still exists in the interface
    assert m.burden.chokepoint_edges == 1
    assert m.burden.scalar == pytest.approx(3.0)
    # shortest choke-free composition length
    assert m.l_min_residual == {"c_st": 2}


def test_block_metrics_hand_calc(toy_lattice, toy_block):
    m = compute_metrics(toy_lattice, toy_block)
    assert m.rho == pytest.approx(1.0)  # blocked counts as covered
    assert m.n_residual() == 0
    assert m.burden.residual_edges == 0
    assert m.burden.chokepoint_edges == 0
    assert m.burden.scalar == pytest.approx(0.0)
