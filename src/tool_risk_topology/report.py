"""E1-T6 -- the KILL-GATE report.

Gate 1 asks a single paper question: does the chokepoint carving C shrink the
residual monitoring burden relative to the opaque (A) and atomic (B) carvings?

PASS criterion (ref backlog E1-T6):

* ``rho(C) > rho(A)`` **and** ``rho(C) > rho(B)`` -- C covers strictly more of
  the catastrophic set; **and**
* ``|C_resid(C)|`` is *materially* smaller than both ``|C_resid(A)|`` and
  ``|C_resid(B)|`` (default: no larger than half of the smaller of the two).

If the criterion fails, the report says so plainly: the carving does not pay off
on paper and the project halts pending redesign. That is a valid, cheap outcome
-- the whole point of running this gate before any sandbox/model work.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .lattice import load_default_lattice
from .metrics import InterfaceMetrics, compute_metrics
from .models import Interface, Lattice
from .schemas import (
    InfoMatchResult,
    check_information_matching,
    load_default_interfaces,
)

# C_resid(C) must be <= MATERIAL_FACTOR * min(|C_resid(A)|, |C_resid(B)|).
MATERIAL_FACTOR = 0.5


@dataclass
class GateVerdict:
    passed: bool
    reasons: List[str] = field(default_factory=list)


@dataclass
class KillGateReport:
    lattice_size: int
    catastrophic_size: int
    info_match_ok: bool
    info_match_summary: str
    metrics: Dict[str, InterfaceMetrics]
    verdict: GateVerdict

    # ---- serialization ------------------------------------------------
    def to_dict(self) -> dict:
        out: dict = {
            "lattice_size": self.lattice_size,
            "catastrophic_size": self.catastrophic_size,
            "information_matching": {
                "ok": self.info_match_ok,
                "summary": self.info_match_summary,
            },
            "interfaces": {},
            "verdict": {"passed": self.verdict.passed, "reasons": self.verdict.reasons},
        }
        for iid, m in self.metrics.items():
            out["interfaces"][iid] = {
                "rho": round(m.rho, 4),
                "counts": m.partition.counts(),
                "burden": {
                    "chokepoint_edges": m.burden.chokepoint_edges,
                    "residual_edges": m.burden.residual_edges,
                    "n_residual_effects": m.burden.n_residual_effects,
                    "scalar": m.burden.scalar,
                },
                "residual_effects": [
                    {
                        "id": v.effect.id,
                        "kind": v.effect.kind,
                        "pair": f"{v.effect.src}->{v.effect.sink}",
                        "l_min_choke_free": v.l_min_choke_free,
                    }
                    for v in m.partition.residual
                ],
                "choked_effects": [v.effect.id for v in m.partition.choked],
                "blocked_effects": [v.effect.id for v in m.partition.blocked],
            }
        return out

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    # ---- human-readable ------------------------------------------------
    def to_markdown(self) -> str:
        lines: List[str] = []
        lines.append("# E1 Kill-Gate Report — Static Property-3 Analyzer\n")
        lines.append(
            f"- Capability nodes: **{self.lattice_size}**  |  "
            f"Catastrophic effects |C|: **{self.catastrophic_size}**"
        )
        lines.append(f"- Information-matching: **{self.info_match_summary}**\n")

        lines.append("## Per-interface metrics\n")
        lines.append(
            "| Carving | ρ (coverage) | blocked | choked | **residual** "
            "| choke edges | resid edges | B_mon |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
        for iid in sorted(self.metrics):
            m = self.metrics[iid]
            c = m.partition.counts()
            lines.append(
                f"| {iid} | {m.rho:.2f} | {c['block']} | {c['choke']} | "
                f"**{c['resid']}** | {m.burden.chokepoint_edges} | "
                f"{m.burden.residual_edges} | {m.burden.scalar:.0f} |"
            )
        lines.append("")

        lines.append("## Residual detail\n")
        for iid in sorted(self.metrics):
            m = self.metrics[iid]
            res = m.partition.residual
            if not res:
                lines.append(f"- **{iid}**: no residual effects.")
                continue
            items = ", ".join(
                f"{v.effect.id} ({v.effect.src}→{v.effect.sink}, "
                f"ℓ={v.l_min_choke_free})"
                for v in res
            )
            lines.append(f"- **{iid}** ({len(res)}): {items}")
        lines.append("")

        verdict = "PASS ✅" if self.verdict.passed else "FAIL ❌ — HALT"
        lines.append(f"## Gate 1 verdict: **{verdict}**\n")
        for r in self.verdict.reasons:
            lines.append(f"- {r}")
        lines.append("")
        lines.append(
            "> Note: this gate is a *paper* check on interface topology. A pass "
            "means the chokepoint carving is coherent and shrinks the residual "
            "set by construction; it does **not** yet establish that the shrink "
            "survives a real attack policy. That is the empirical claim tested "
            "downstream (E6/E8)."
        )
        return "\n".join(lines)


def evaluate_gate(metrics: Dict[str, InterfaceMetrics]) -> GateVerdict:
    """Apply the Gate-1 PASS criterion to A/B/C metrics."""
    reasons: List[str] = []
    missing = {"A", "B", "C"} - set(metrics)
    if missing:
        return GateVerdict(
            passed=False, reasons=[f"missing interface metrics: {sorted(missing)}"]
        )

    rho_a = metrics["A"].rho
    rho_b = metrics["B"].rho
    rho_c = metrics["C"].rho
    res_a = metrics["A"].n_residual()
    res_b = metrics["B"].n_residual()
    res_c = metrics["C"].n_residual()

    cov_ok = rho_c > rho_a and rho_c > rho_b
    reasons.append(
        f"ρ(C)={rho_c:.2f} vs ρ(A)={rho_a:.2f}, ρ(B)={rho_b:.2f} — "
        + ("strictly higher ✅" if cov_ok else "NOT strictly higher ❌")
    )

    baseline = min(res_a, res_b)
    material_ok = res_c <= MATERIAL_FACTOR * baseline
    reasons.append(
        f"|C_resid(C)|={res_c} vs min(|C_resid(A)|,|C_resid(B)|)={baseline} — "
        + (
            f"≤ {MATERIAL_FACTOR:g}× baseline ✅"
            if material_ok
            else f"not materially smaller (need ≤ {MATERIAL_FACTOR:g}×) ❌"
        )
    )

    return GateVerdict(passed=cov_ok and material_ok, reasons=reasons)


def build_report(
    lattice: Optional[Lattice] = None,
    interfaces: Optional[Dict[str, Interface]] = None,
) -> KillGateReport:
    """Run the full E1 pipeline and produce the kill-gate report."""
    if lattice is None:
        lattice = load_default_lattice()
    if interfaces is None:
        interfaces = load_default_interfaces()

    info = check_information_matching(lattice, interfaces)
    metrics = {iid: compute_metrics(lattice, iface) for iid, iface in interfaces.items()}
    verdict = evaluate_gate(metrics)

    return KillGateReport(
        lattice_size=len(lattice.nodes),
        catastrophic_size=len(lattice.catastrophic),
        info_match_ok=info.ok,
        info_match_summary=info.summary(),
        metrics=metrics,
        verdict=verdict,
    )
