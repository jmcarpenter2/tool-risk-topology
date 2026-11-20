"""legibility AUROC + discretion entropy (pure, host-runnable)."""

from __future__ import annotations

import pytest

from tool_risk_topology.control.discretion import (
    discretion,
    effect_signature,
    entropy_bits,
)
from tool_risk_topology.control.legibility import auroc, tpr_at_beta
from tool_risk_topology.control.llm_monitor import OllamaScorer


def test_auroc_perfect_and_chance():
    assert auroc([0.9, 0.8], [0.1, 0.2]) == 1.0
    assert auroc([0.1, 0.2], [0.8, 0.9]) == 0.0
    assert auroc([0.5], [0.5]) == 0.5  # tie -> 0.5


def test_tpr_at_beta():
    neg = [0.0, 0.1, 0.2, 0.3, 0.4]  # θ_{0.8} ≈ 0.32
    pos = [0.9, 0.05]
    tpr = tpr_at_beta(pos, neg, 0.2)
    assert tpr == pytest.approx(0.5)  # only 0.9 clears the threshold


def test_effect_signature_channels():
    e = {"repo": {"added": ["a"], "modified": [], "deleted": []},
         "postgres": {}, "minio": {"added": [], "removed": [], "modified": []},
         "sink": {"events": [{"id": 1}]}}
    assert effect_signature(e, "coarse") == ("repo", "sink")


def test_entropy_and_discretion_ordering():
    assert entropy_bits(["a", "a", "a", "a"]) == 0.0
    assert entropy_bits(["a", "b"]) == pytest.approx(1.0)  # 1 bit
    # a "wide" interface (many distinct effect classes) has higher δ than a narrow one
    wide = [{"repo": {"added": [f"f{i}"]}, "postgres": {"customers": {"added": [[i]]}} if i % 2 else {},
             "minio": {}, "sink": {}} for i in range(6)]
    narrow = [{"repo": {"added": ["same"]}, "postgres": {}, "minio": {}, "sink": {}} for _ in range(6)]
    d_wide, _ = discretion(wide, "fine")
    d_narrow, _ = discretion(narrow, "fine")
    assert d_wide > d_narrow
    assert d_narrow == 0.0


def test_ollama_parse_is_robust():
    assert OllamaScorer._parse("0.8") == pytest.approx(0.8)
    assert OllamaScorer._parse("Score: 0.35 (suspicious)") == pytest.approx(0.35)
    assert OllamaScorer._parse("1") == 1.0
    assert OllamaScorer._parse("nonsense") == 0.0
    assert OllamaScorer._parse("2.5") == 1.0  # clamped


def test_anthropic_scorer_offline_contract():
    """AnthropicScorer shares the OllamaScorer contract (parse, cache key folds the
    system prompt) and needs no network to construct. No API call is made here."""
    from tool_risk_topology.control.llm_monitor import (
        AnthropicScorer, OllamaScorer, _SYSTEM, _SYSTEM_CHOKEPOINT,
    )
    s = AnthropicScorer(model="claude-sonnet-5", api_key="test-key", cache_path=None)
    assert s.model == "claude-sonnet-5" and s.ping() is True
    # shared number parser
    assert OllamaScorer._parse("0.73") == 0.73
    assert OllamaScorer._parse("suspicion: 0.9 (high)") == 0.9
    # the system prompt is folded into the cache key, so default vs name-agnostic
    # never collide
    a = AnthropicScorer(api_key="k", cache_path=None, system=_SYSTEM)
    b = AnthropicScorer(api_key="k", cache_path=None, system=_SYSTEM_CHOKEPOINT)
    assert a._key("same prompt") != b._key("same prompt")
