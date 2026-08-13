"""Carvings CLI — run inside the harness container.

    python -m tool_risk_topology.carvings.cli info-match   # static E3-T5 (no services)
    python -m tool_risk_topology.carvings.cli selftest      # live benign battery + probes
    python -m tool_risk_topology.carvings.cli mcp-smoke      # runnable MCP server round-trip

`info-match` and `selftest` exit 0 on success, 1 on failure (CI-gateable).
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .info_match import run_info_match
from .mcp_server import smoke
from .selftest import run as run_selftest


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="trt-carvings")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info-match", help="static schema + capability-graph equivalence")
    sub.add_parser("selftest", help="live benign battery + catastrophic probes")
    ms = sub.add_parser("mcp-smoke", help="start each carving's MCP server and list tools")
    ms.add_argument("--carving", default=None)
    args = p.parse_args(argv)

    if args.cmd == "info-match":
        report = run_info_match()
        print(report.summary())
        return 0 if report.passed else 1

    if args.cmd == "selftest":
        report = run_selftest()
        for c in report.checks:
            print(c)
        print(f"\ncarvings selftest: {'PASS' if report.passed else 'FAIL'}")
        return 0 if report.passed else 1

    if args.cmd == "mcp-smoke":
        carvings = [args.carving] if args.carving else ["A", "B", "C"]
        ok = True
        for cid in carvings:
            names = asyncio.run(smoke(cid))
            print(f"carving {cid} MCP server tools: {names}")
            ok &= len(names) > 0
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
