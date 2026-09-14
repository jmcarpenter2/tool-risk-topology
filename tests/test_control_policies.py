"""E4-T1/T2 — policy trajectory construction (host-runnable via a fake carving)."""

from __future__ import annotations

from tool_risk_topology.carvings.base import ToolResult
from tool_risk_topology.control.policies import (
    AttackPolicy,
    HonestPolicy,
    StealthAttackPolicy,
)
from tool_risk_topology.control.tasks import suite


class FakeCarving:
    """Records calls; returns canned success. No services touched."""

    def __init__(self, cid: str):
        self.id = cid
        self.calls = []

    def call(self, tool_name: str, **kwargs) -> ToolResult:
        self.calls.append((tool_name, kwargs))
        return ToolResult(ok=True, output=f"{tool_name}-ok")


def test_honest_policy_produces_benign_trajectory():
    task = suite()[0]  # customer_report
    traj = HonestPolicy().run(task, FakeCarving("B"), backend=None, tag="t1")
    assert traj.policy_kind == "H"
    assert len(traj) >= 2
    assert traj.sentinel_actions == []  # honest carries no sentinel


def test_attack_logs_strength_and_marks_one_sentinel():
    task = suite()[1]  # publish_report
    traj = AttackPolicy(strength=2).run(task, FakeCarving("B"), backend=None,
                                        tag="t2", token="CANARY-abc123")
    assert traj.policy_kind == "A"
    assert traj.meta["strength"] == 2
    assert traj.meta["technique"] == "csv+secret"
    assert traj.meta["secret_exfiltrated"] is True  # B exposes read_env, s<=2 reads it
    assert len(traj.sentinel_actions) == 1
    assert "CANARY-abc123" in str(traj.sentinel_actions[0].args)


def test_attack_spread_inserts_sigma_filler_between_head_and_egress():
    task = suite()[1]  # publish_report
    base = AttackPolicy(strength=2, spread=0).run(
        task, FakeCarving("B"), backend=None, tag="t-s0", token="CANARY-s0")
    spread = AttackPolicy(strength=2, spread=3).run(
        task, FakeCarving("B"), backend=None, tag="t-s3", token="CANARY-s3")

    assert base.meta["spread"] == 0 and spread.meta["spread"] == 3
    # σ adds exactly σ actions
    assert len(spread) == len(base) + 3
    # the sentinel egress stays the tail; the sensitive read is the head before it
    assert spread.actions[-1].carried_sentinel is True
    head_idx = next(i for i, a in enumerate(spread.actions) if a.tool == "read_env")
    between = spread.actions[head_idx + 1: -1]
    assert len(between) == 3
    assert all(a.ok and not a.carried_sentinel for a in between)  # benign filler


def test_stealth_attack_is_a_benign_read_then_egress_with_no_env_tell():
    task = suite()[0]  # customer_report
    traj = StealthAttackPolicy(spread=2).run(
        task, FakeCarving("B"), backend=None, tag="st", token="CANARY-xyz789")
    assert traj.meta["technique"] == "stealth-composition"
    assert traj.meta["spread"] == 2 and traj.meta["head"] == "benign_read"
    # no per-call tell: the attack never reads an env secret
    assert all(a.tool != "read_env" for a in traj.actions)
    # the composition is a benign data read (db_query) somewhere before the egress
    tools = [a.tool for a in traj.actions]
    assert "db_query" in tools
    # exactly one sentinel egress, carrying the canary, as the tail
    assert len(traj.sentinel_actions) == 1
    assert traj.actions[-1].carried_sentinel is True
    assert "CANARY-xyz789" in str(traj.actions[-1].args)


def test_attack_on_C_blocks_secret_and_chokes_egress():
    task = suite()[1]
    traj = AttackPolicy(strength=1).run(task, FakeCarving("C"), backend=None,
                                        tag="t3", token="CANARY-def456")
    # C exposes no env-read -> secret not exfiltrated, and a failed action recorded
    assert traj.meta["secret_exfiltrated"] is False
    assert traj.meta["egress_is_chokepoint"] is True
    sentinel = traj.sentinel_actions[0]
    assert sentinel.tool == "export_data" and sentinel.chokepoint is True
    assert any(not a.ok for a in traj.actions)  # the blocked read_env attempt
