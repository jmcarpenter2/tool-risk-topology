"""Harness CLI — run inside the trusted `harness` container.

    python -m tool_risk_topology.harness.cli seed
    python -m tool_risk_topology.harness.cli baseline --out /workspace/.baseline.json
    python -m tool_risk_topology.harness.cli extract --baseline /workspace/.baseline.json \
        --token CANARY-xyz
    python -m tool_risk_topology.harness.cli selftest
    python -m tool_risk_topology.harness.cli reset-sink

`selftest` returns exit code 0 on success (1 on failure) so CI can gate on it.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import actions
from .config import ServiceConfig
from .effects import Baseline, capture_baseline, extract_effects
from .episode import run_selftest
from .sentinel import SentinelSpec, evaluate
from .workspace import reset_workspace, seed_workspace


def _cfg() -> ServiceConfig:
    return ServiceConfig.from_env()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="trt-harness")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("seed", help="seed the workspace repo")

    sp = sub.add_parser("baseline", help="capture a pre-episode baseline")
    sp.add_argument("--out", default="/workspace/.baseline.json")
    sp.add_argument("--seed", type=int, default=0)

    ep = sub.add_parser("extract", help="extract E(tau) and evaluate Z")
    ep.add_argument("--baseline", default="/workspace/.baseline.json")
    ep.add_argument("--token", default=None, help="canary token for the sentinel")
    ep.add_argument("--out", default=None)

    sub.add_parser("reset-sink", help="clear the canary-sink event log")
    sub.add_parser("reset-state", help="per-episode teardown: reset sink + workspace")

    stp = sub.add_parser("selftest", help="run benign+attack episodes end-to-end")
    stp.add_argument("--seed", type=int, default=0)
    stp.add_argument("--json", action="store_true")

    args = p.parse_args(argv)
    cfg = _cfg()

    if args.cmd == "seed":
        print(json.dumps(seed_workspace(cfg), indent=2))
        return 0

    if args.cmd == "baseline":
        base = capture_baseline(cfg, seed=args.seed)
        base.save(args.out)
        print(f"baseline (config_hash={base.config_hash}, seed={base.seed}) -> {args.out}")
        return 0

    if args.cmd == "extract":
        base = Baseline.load(args.baseline)
        effects = extract_effects(base, cfg)
        result = {"effects": effects.to_dict()}
        if args.token:
            res = evaluate(effects, SentinelSpec(canary_token=args.token))
            result["sentinel"] = {"z": res.z, "triggers": res.triggers}
        text = json.dumps(result, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        print(text)
        return 0

    if args.cmd == "reset-sink":
        actions.sink_reset(cfg)
        print("sink reset")
        return 0

    if args.cmd == "reset-state":
        actions.sink_reset(cfg)
        info = reset_workspace(cfg)
        print(json.dumps({"reset": True, "workspace": info}, indent=2))
        return 0

    if args.cmd == "selftest":
        report = run_selftest(cfg, seed=args.seed)
        if args.json:
            print(
                json.dumps(
                    {
                        "passed": report.passed,
                        "benign_z": report.benign_z,
                        "attack_z": report.attack_z,
                        "attack_triggers": report.attack_triggers,
                        "checks": report.checks,
                    },
                    indent=2,
                )
            )
        else:
            for c in report.checks:
                print(c)
            print(f"\nselftest: {'PASS' if report.passed else 'FAIL'}")
        return 0 if report.passed else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
