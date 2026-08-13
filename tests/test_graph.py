"""E1-T3 — reachability graph builds and answers source->sink correctly."""

from __future__ import annotations

import pytest

from tool_risk_topology.graph import (
    build_graph,
    choke_free_view,
    reachable,
    shortest_len,
)
from tool_risk_topology.models import Interface, Tool


def test_edges_are_induced_by_in_cross_out(toy_lattice, toy_choke):
    g = build_graph(toy_lattice, toy_choke)
    edge_pairs = {(u, v) for u, v in g.edges()}
    assert ("s", "m") in edge_pairs
    assert ("m", "t") in edge_pairs
    # no spurious edges
    assert edge_pairs == {("s", "m"), ("m", "t")}


def test_self_loops_are_dropped(toy_lattice):
    iface = Interface(
        id="loopy",
        label="loopy",
        tools=(Tool("io", reads=("s", "m"), writes=("s", "m")),),
    )
    g = build_graph(toy_lattice, iface)
    assert all(u != v for u, v in g.edges())
    assert set(g.edges()) == {("s", "m"), ("m", "s")}


def test_reachability_hand_checked(toy_lattice, toy_choke):
    g = build_graph(toy_lattice, toy_choke)
    assert reachable(g, "s", "t") is True
    assert reachable(g, "s", "m") is True
    assert reachable(g, "t", "s") is False  # directed
    assert reachable(g, "s", "x") is False  # isolated node


def test_shortest_len(toy_lattice, toy_resid):
    g = build_graph(toy_lattice, toy_resid)
    assert shortest_len(g, "s", "t") == 2
    assert shortest_len(g, "s", "x") is None
    assert shortest_len(g, "s", "s") == 0


def test_choke_free_view_removes_only_chokepoint_edges(toy_lattice, toy_choke):
    g = build_graph(toy_lattice, toy_choke)
    cf = choke_free_view(g)
    assert reachable(cf, "s", "m") is True  # ordinary edge kept
    assert reachable(cf, "s", "t") is False  # chokepoint edge removed
    # original graph is untouched
    assert reachable(g, "s", "t") is True


def test_unknown_node_in_tool_raises(toy_lattice):
    bad = Interface(
        id="bad",
        label="bad",
        tools=(Tool("oops", reads=("s",), writes=("nope",)),),
    )
    with pytest.raises(ValueError, match="unknown node"):
        build_graph(toy_lattice, bad)
