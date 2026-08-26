from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from data_enricher import VLSBuilder

from .pipeline_runner import PipelineError, SecurityPipeline, SemgrepScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orchestrator",
        description="Run Semgrep and assemble VLS records.",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        required=True,
        help="Source directory scanned by Semgrep (supplied by CLI/GUI).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("pipeline-result.json"),
        help="Path for the resulting JSON report.",
    )
    parser.add_argument(
        "--semgrep-config",
        default="p/sql-injection",
        help="Semgrep registry ruleset or local config path.",
    )
    parser.add_argument("--semgrep-timeout", type=float, default=300)

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        scanner = SemgrepScanner(
            config=args.semgrep_config,
            timeout_seconds=args.semgrep_timeout,
        )
        pipeline = SecurityPipeline(scanner, VLSBuilder())
        report = pipeline.run(args.target_dir)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, PipelineError) as exc:
        print(f"pipeline failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"VLS report written to {args.output}")
