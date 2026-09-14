"""E3-T5 (static half) — runnable carvings match their E1 schemas and are
information-matched. Host-runnable: only schemas/graphs are touched, no services.
"""

from __future__ import annotations

from tool_risk_topology.carvings import build_all, run_info_match
from tool_risk_topology.carvings.info_match import compare_to_e1, runnable_to_interface
from tool_risk_topology.schemas import load_default_interfaces


def test_carvings_build_with_expected_shape():
    servers = build_all()
    assert set(servers) == {"A", "B", "C", "D"}
    assert [t.name for t in servers["A"].tools] == ["run_command"]
    assert len(servers["B"].tools) == 7
    # C has exactly one chokepoint tool, named export_data
    assert [t.name for t in servers["C"].chokepoint_tools] == ["export_data"]
    assert servers["A"].chokepoint_tools == []
    assert servers["B"].chokepoint_tools == []


def test_runnable_schema_matches_e1_yaml():
    servers = build_all()
    e1 = load_default_interfaces()
    for cid in ("A", "B", "C", "D"):
        diffs = compare_to_e1(servers[cid], e1[cid])
        assert diffs == [], f"{cid} schema drift: {diffs}"


def test_info_match_passes():
    report = run_info_match()
    assert report.schema_ok, report.schema_diffs
    assert report.graph_ok, report.graph_summary
    assert report.passed
    # every carving realizes every benign path
    for cid in ("A", "B", "C", "D"):
        assert report.missing[cid] == []


def test_runnable_interface_reaches_benign_via_e1_graph():
    # sanity: the runnable-derived C interface still reaches a benign export
    from tool_risk_topology.graph import build_graph, reachable
    from tool_risk_topology.lattice import load_default_lattice

    lattice = load_default_lattice()
    c_iface = runnable_to_interface(build_all()["C"])
    g = build_graph(lattice, c_iface)
    assert reachable(g, "repo", "external")  # via export_data chokepoint
    assert not reachable(g, "env_secrets", "agent")  # credential-read blocked
