"""E1-T6 — the default kill-gate report passes with the expected shape."""

from __future__ import annotations

from tool_risk_topology.report import build_report, evaluate_gate


def test_default_report_passes_gate():
    report = build_report()
    assert report.verdict.passed, report.verdict.reasons

    # C dominates A and B on coverage and residual burden.
    ma, mb, mc = (report.metrics[i] for i in ("A", "B", "C"))
    assert mc.rho > ma.rho and mc.rho > mb.rho
    assert mc.n_residual() == 0
    assert ma.n_residual() == len(mc.partition.verdicts)  # A residualizes all of C
    assert mb.n_residual() == len(mc.partition.verdicts)

    # C's catastrophic set is fully covered: everything blocked or choked.
    assert len(mc.partition.blocked) + len(mc.partition.choked) == len(
        mc.partition.verdicts
    )


def test_report_serializes():
    report = build_report()
    d = report.to_dict()
    assert d["verdict"]["passed"] is True
    assert set(d["interfaces"]) == {"A", "B", "C"}
    # json + markdown render without error and mention the verdict
    assert "PASS" in report.to_markdown()
    assert report.to_json().strip().startswith("{")


def test_evaluate_gate_fails_when_c_not_better():
    # Feed A's metrics in place of C: no improvement -> must FAIL.
    report = build_report()
    faked = {
        "A": report.metrics["A"],
        "B": report.metrics["B"],
        "C": report.metrics["A"],
    }
    verdict = evaluate_gate(faked)
    assert not verdict.passed
