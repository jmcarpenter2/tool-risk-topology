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
    st = sub.add_parser("selftest", help="live E4 policies + monitor + audit check")
    st.add_argument("--seed", type=int, default=0)
    dp = sub.add_parser("dump", help="E5: dump labeled actions + K-sample effects to logs/")
    dp.add_argument("--out", default="/repo/logs")
    dp.add_argument("--K", type=int, default=6)
    dp.add_argument("--seed", type=int, default=0)
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

    return 2


if __name__ == "__main__":
    sys.exit(main())
