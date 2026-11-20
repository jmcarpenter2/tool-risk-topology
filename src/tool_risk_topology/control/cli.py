"""Control CLI — run inside the harness container.

    python -m tool_risk_topology.control.cli selftest   # live policies + monitor + audit

Exit 0 on success, 1 on failure (CI-gateable).
"""

from __future__ import annotations

import argparse
import json
import sys

from .selftest import run as run_selftest


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="trt-control")
    sub = p.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("selftest", help="live policies + monitor + audit check")
    st.add_argument("--seed", type=int, default=0)
    dp = sub.add_parser("dump", help="dump labeled actions + K-sample effects to logs/")
    dp.add_argument("--out", default="/repo/logs")
    dp.add_argument("--K", type=int, default=6)
    dp.add_argument("--seed", type=int, default=0)
    sw = sub.add_parser("sweep", help="sweep phase-1: generate trajectories (resumable)")
    sw.add_argument("--out", default="/repo/logs/sweep_trajectories.jsonl")
    sw.add_argument("--n-attack", type=int, default=300)
    sw.add_argument("--n-honest", type=int, default=100)
    sw.add_argument("--strengths", default="0,1,2,3,4",
                    help="comma-separated attacker strength levels")
    args = p.parse_args(argv)

    if args.cmd == "selftest":
        report = run_selftest(seed=args.seed)
        for c in report.checks:
            print(c)
        print()
        for row in report.table:
            print(row)
        print(f"\ncontrol selftest: {'PASS' if report.passed else 'FAIL'}")
        return 0 if report.passed else 1

    if args.cmd == "dump":
        from .instrument import dump
        info = dump(out_dir=args.out, K=args.K, seed=args.seed)
        print(json.dumps(info, indent=2))
        return 0

    if args.cmd == "sweep":
        from .sweep import run_phase1
        strengths = tuple(int(x) for x in args.strengths.split(",") if x.strip() != "")
        info = run_phase1(out_path=args.out, n_attack=args.n_attack,
                          n_honest=args.n_honest, strengths=strengths)
        print(json.dumps(info, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
