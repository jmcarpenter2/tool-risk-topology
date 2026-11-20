"""Command-line entry point for the static analyzer.

    trt-analyze                 # print the kill-gate report (markdown)
    trt-analyze --json          # emit machine-readable JSON
    trt-analyze --out DIR       # also write report.md + report.json to DIR

Exit code is 0 when Gate 1 passes, 1 when it fails (so CI can gate on it).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import build_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="trt-analyze",
        description="static Property-3 analyzer / Gate-1 kill report.",
    )
    parser.add_argument(
        "--json", action="store_true", help="print machine-readable JSON instead of markdown"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="directory to write report.md and report.json into",
    )
    args = parser.parse_args(argv)

    report = build_report()

    if args.out is not None:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.md").write_text(report.to_markdown(), encoding="utf-8")
        (args.out / "report.json").write_text(report.to_json(), encoding="utf-8")

    if args.json:
        print(report.to_json())
    else:
        print(report.to_markdown())

    return 0 if report.verdict.passed else 1


if __name__ == "__main__":
    sys.exit(main())
