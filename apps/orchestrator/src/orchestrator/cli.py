from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from data_enricher import VLSBuilder

from .pipeline_runner import PipelineError, SecurityPipeline, SemgrepScanner
from .dast_scanner import ZapDastScanner


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
    parser.add_argument(
        "--dast-base-url",
        help="Base URL of the running target, for example http://target:3000.",
    )
    parser.add_argument(
        "--zap-network",
        help="Internal Docker network shared by ZAP and the target.",
    )
    parser.add_argument(
        "--zap-image",
        default="ghcr.io/zaproxy/zaproxy:stable",
    )
    parser.add_argument("--zap-timeout", type=float, default=900)
    parser.add_argument(
        "--disable-correlation",
        action="store_true",
        help="Skip endpoint lookup and targeted DAST correlation.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        scanner = SemgrepScanner(
            config=args.semgrep_config,
            timeout_seconds=args.semgrep_timeout,
        )
        dast_scanner = None
        # отключенная корреляция не создает сканер dast
        if args.dast_base_url and not args.disable_correlation:
            if not args.zap_network:
                raise PipelineError("--zap-network is required with --dast-base-url")
            dast_scanner = ZapDastScanner(
                docker_network=args.zap_network,
                image=args.zap_image,
                timeout_seconds=args.zap_timeout,
            )
        pipeline = SecurityPipeline(
            scanner,
            VLSBuilder(),
            dast_scanner=dast_scanner,
        )
        report = pipeline.run(
            args.target_dir,
            args.dast_base_url,
            correlation_enabled=not args.disable_correlation,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, PipelineError) as exc:
        print(f"pipeline failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    locator = report["locator"]
    dast = report["dast"]
    if locator["enabled"]:
        print(
            "Endpoint locator: "
            f"{locator['matched_findings']}/{locator['total_findings']}, "
            f"confidence={locator['average_confidence']:.2f}"
        )
    else:
        print("Endpoint correlation: disabled")
    if dast["requested"] and dast["correlation_enabled"]:
        print(
            f"DAST: executed={dast['executed']}, "
            f"skipped={len(dast['skipped'])}"
        )
    print(f"VLS report written to {args.output}")
