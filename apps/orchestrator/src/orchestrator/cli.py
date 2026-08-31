from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .pipeline_runner import PipelineError, run_pipeline


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
        help="Run SAST and DAST separately without merging their results.",
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=Path("logs"),
        help="Directory for the standalone DAST report.",
    )
    parser.add_argument(
        "--scoring-topology",
        type=Path,
        help="Topology JSON used by the scoring agent.",
    )
    parser.add_argument(
        "--scoring-service",
        help="Service node from topology that owns the target repository.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        scorer = None
        if args.scoring_topology is not None:
            if not args.scoring_service:
                raise PipelineError(
                    "--scoring-service is required with --scoring-topology"
                )
            # cli создает конкретный скоринг
            from scoring_agent import RegistryScoringAgent

            scorer = RegistryScoringAgent.from_topology_file(
                args.scoring_topology,
                args.scoring_service,
            )
        registry = run_pipeline(
            args.target_dir,
            dast_base_url=args.dast_base_url,
            correlation_enabled=not args.disable_correlation,
            logs_dir=args.logs_dir,
            semgrep_config=args.semgrep_config,
            semgrep_timeout=args.semgrep_timeout,
            zap_network=args.zap_network,
            zap_image=args.zap_image,
            zap_timeout=args.zap_timeout,
            scorer=scorer,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(registry.to_records(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, PipelineError) as exc:
        print(f"pipeline failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    records = registry.all()
    if args.scoring_topology is not None:
        scored = sum(
            bool(item.sast and item.sast.score is not None)
            for item in records
        )
        print(f"Scoring: {scored}/{len(records)}")
    if args.disable_correlation:
        print("Endpoint correlation: disabled")
    else:
        matched = sum(bool(item.sast and item.sast.endpoint) for item in records)
        print(f"Endpoint locator: {matched}/{len(records)}")
    if args.dast_base_url and args.disable_correlation:
        print(f"Standalone DAST report written to {args.logs_dir / 'dast-report.json'}")
    elif args.dast_base_url:
        executed = sum(
            item.verification_history.dast.run_executed for item in records
        )
        print(
            f"DAST: executed={executed}, "
            f"skipped={len(records) - executed}"
        )
    print(f"VLS registry written to {args.output}")
