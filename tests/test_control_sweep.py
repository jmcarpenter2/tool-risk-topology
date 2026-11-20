"""hypothesis-test analysis over synthetic per-config metrics (host-runnable)."""

from __future__ import annotations

from tool_risk_topology.control.audit import diff_in_diff
from tool_risk_topology.control.safety_sweep import (
    PER_CALL,
    TRAJECTORY,
    ConfigMetrics,
    h_horizon,
    h_nonmono,
)

S = 3  # a strength level used as the key in these synthetic tests


def _m(carving, horizon, safety, n_attack=300):
    n_success = round((1 - safety) * n_attack)
    return ConfigMetrics(carving, horizon, S, safety, safety - 0.03, safety + 0.03,
                         usefulness=1.0, theta=0.5, monitor_cost=100.0,
                         n_attack=n_attack, n_success=n_success)


def test_h_nonmono_pass_when_C_dominates():
    metrics = {
        ("A", PER_CALL, S): _m("A", PER_CALL, 0.40),
        ("B", PER_CALL, S): _m("B", PER_CALL, 0.45),  # B breaks under a strong attack
        ("C", PER_CALL, S): _m("C", PER_CALL, 0.95),  # C holds
    }
    r = h_nonmono(metrics, PER_CALL, S)
    assert r["pass"] is True
    assert r["contrasts"]["C>A"]["significant"] and r["contrasts"]["C>B"]["significant"]


def test_h_nonmono_fails_when_B_also_safe():
    metrics = {
        ("A", PER_CALL, S): _m("A", PER_CALL, 0.50),
        ("B", PER_CALL, S): _m("B", PER_CALL, 1.00),  # weak attack -> B looks safe
        ("C", PER_CALL, S): _m("C", PER_CALL, 1.00),
    }
    r = h_nonmono(metrics, PER_CALL, S)
    assert r["pass"] is False


def test_h_horizon_requires_B_to_steepen():
    # C flat (0.90->0.91), B steep up (0.55->0.90): PASS
    good = {
        ("C", PER_CALL, S): _m("C", PER_CALL, 0.90),
        ("C", TRAJECTORY, S): _m("C", TRAJECTORY, 0.91),
        ("B", PER_CALL, S): _m("B", PER_CALL, 0.55),
        ("B", TRAJECTORY, S): _m("B", TRAJECTORY, 0.90),
    }
    assert h_horizon(good, S)["pass"] is True

    # DiD negative but because C *degrades*, B flat -> must NOT pass
    bad = {
        ("C", PER_CALL, S): _m("C", PER_CALL, 1.00),
        ("C", TRAJECTORY, S): _m("C", TRAJECTORY, 0.50),
        ("B", PER_CALL, S): _m("B", PER_CALL, 1.00),
        ("B", TRAJECTORY, S): _m("B", TRAJECTORY, 1.00),
    }
    assert h_horizon(bad, S)["pass"] is False


def test_diff_in_diff_zero_when_parallel():
    r = diff_in_diff(0.8, 300, 0.7, 300, 0.6, 300, 0.5, 300)
    assert abs(r["did"]) < 1e-9
