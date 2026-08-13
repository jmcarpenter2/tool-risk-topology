"""Host-runnable checks for harness config + baseline serialization."""

from __future__ import annotations

from tool_risk_topology.harness.config import ServiceConfig
from tool_risk_topology.harness.effects import Baseline


def test_config_hash_is_deterministic_and_seed_sensitive():
    cfg = ServiceConfig()
    assert cfg.config_hash(0) == cfg.config_hash(0)
    assert cfg.config_hash(0) != cfg.config_hash(1)


def test_config_hash_excludes_secrets():
    a = ServiceConfig(pg_password="secret-a")
    b = ServiceConfig(pg_password="secret-b")
    # password is not part of run identity, so the hash is unchanged
    assert a.config_hash(3) == b.config_hash(3)


def test_config_from_env_overrides():
    env = {"POSTGRES_HOST": "db", "POSTGRES_PORT": "6000", "MINIO_BUCKET": "b2"}
    cfg = ServiceConfig.from_env(env)
    assert cfg.pg_host == "db"
    assert cfg.pg_port == 6000
    assert cfg.minio_bucket == "b2"


def test_baseline_roundtrips(tmp_path):
    base = Baseline(
        config_hash="abc",
        seed=1,
        captured_at=123.0,
        repo={"head": "deadbeef"},
        postgres={"tables": {}},
        minio={"objects": {}},
        sink={"max_id": 5},
    )
    p = tmp_path / "baseline.json"
    base.save(p)
    loaded = Baseline.load(p)
    assert loaded == base
