"""metrics match hand-calculation on the toy example."""

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


def test_fabrication_escapes_distinguish_C_from_D():
    """Single-call escapes statically separate the two chokepoint carvings that
    look identical on ρ and residual: C still accepts agent-fabricated egress, D
    does not. Generalizes past exfiltration (covers pg_prod writes too)."""
    from tool_risk_topology.lattice import load_default_lattice
    from tool_risk_topology.schemas import load_default_interfaces
    from tool_risk_topology.metrics import fabrication_escapes

    lat = load_default_lattice()
    ifaces = load_default_interfaces()
    esc = {i: fabrication_escapes(lat, ifaces[i]) for i in ifaces}

    # D is the only carving with no single-call escape to any catastrophic sink.
    assert esc["D"] == []
    # C looks like D on ρ/residual but retains exactly one: agent -> external.
    assert esc["C"] == [("export_data", "external")]
    # A and B leave several (and they include a non-exfil sink: pg_prod).
    assert len(esc["A"]) >= 2 and len(esc["B"]) >= 2
    all_sinks = {s for i in ("A", "B") for _, s in esc[i]}
    assert "pg_prod" in all_sinks and "external" in all_sinks
