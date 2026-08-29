from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from data_enricher import VLSBuilder
from vls import VLS

from .dast_scanner import ZapDastScanner
from .endpoint_locator import EndpointLocator
from .errors import PipelineError


class SemgrepScanner:
    """запускает sast-анализ."""

    def __init__(
        self,
        config: str = "p/sql-injection",
        timeout_seconds: float = 300,
    ) -> None:
        self.config = config
        self.timeout_seconds = timeout_seconds

    def scan(self, target_dir: str | Path) -> dict[str, Any]:
        target = Path(target_dir).expanduser().resolve()
        if not target.is_dir():
            raise PipelineError(f"Semgrep target directory does not exist: {target}")

        command = [
            "semgrep",
            "scan",
            "--config",
            self.config,
            "--json",
            "--quiet",
            "--project-root",
            ".",
            ".",
        ]
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                cwd=target,
            )
        except FileNotFoundError as exc:
            raise PipelineError("Semgrep executable was not found in PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise PipelineError("Semgrep scan timed out") from exc

        if process.returncode != 0:
            details = process.stderr.strip() or "no diagnostic output"
            raise PipelineError(f"Semgrep failed: {details}")

        try:
            output = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise PipelineError("Semgrep returned invalid JSON") from exc
        if not isinstance(output, dict) or not isinstance(output.get("results"), list):
            raise PipelineError("Semgrep output does not contain a results list")
        return output


class SecurityPipeline:
    """управляет sast-пайплайном."""

    def __init__(
        self,
        scanner: SemgrepScanner,
        builder: VLSBuilder,
        endpoint_locator: EndpointLocator | None = None,
        dast_scanner: ZapDastScanner | None = None,
    ) -> None:
        self.scanner = scanner
        self.builder = builder
        self.endpoint_locator = endpoint_locator or EndpointLocator()
        self.dast_scanner = dast_scanner

    def run(
        self,
        target_dir: str | Path,
        dast_base_url: str | None = None,
        correlation_enabled: bool = True,
    ) -> dict[str, Any]:
        target = Path(target_dir).expanduser().resolve()
        semgrep_output = self.scanner.scan(target)
        # без корреляции исходный sast сразу идет в vls
        enriched_output = (
            self.endpoint_locator.enrich(target, semgrep_output)
            if correlation_enabled
            else semgrep_output
        )
        vulnerabilities = self.builder.build(enriched_output)
        locator_summary = self._locator_summary(vulnerabilities, correlation_enabled)
        # точечный dast зависит от найденного endpoint
        dast_summary = (
            self._run_dast(vulnerabilities, dast_base_url)
            if correlation_enabled
            else {
                "requested": dast_base_url is not None,
                "correlation_enabled": False,
                "executed": 0,
                "skipped": [],
            }
        )
        return {
            "target_dir": str(target),
            "locator": locator_summary,
            "dast": dast_summary,
            "vulnerabilities": vulnerabilities,
        }

    @staticmethod
    def _locator_summary(
        vulnerabilities: list[dict[str, Any]],
        enabled: bool = True,
    ) -> dict[str, Any]:
        matches = []
        for vulnerability in vulnerabilities:
            endpoint = (vulnerability.get("sast") or {}).get("endpoint")
            if not endpoint:
                continue
            matches.append(
                {
                    "vulnerability_id": vulnerability["id"],
                    "path": endpoint["path"],
                    "http_methods": endpoint["http_methods"],
                    "confidence": endpoint["locator_confidence"],
                    "evidence": endpoint["locator_evidence"],
                }
            )
        total = len(vulnerabilities)
        average = (
            sum(match["confidence"] for match in matches) / len(matches)
            if matches
            else 0.0
        )
        return {
            "enabled": enabled,
            "total_findings": total,
            "matched_findings": len(matches),
            "coverage": len(matches) / total if total else 0.0,
            "average_confidence": average,
            "matches": matches,
        }

    def _run_dast(
        self,
        vulnerabilities: list[dict[str, Any]],
        base_url: str | None,
    ) -> dict[str, Any]:
        requested = base_url is not None
        if not requested:
            return {
                "requested": False,
                "correlation_enabled": True,
                "executed": 0,
                "skipped": [],
            }
        if self.dast_scanner is None:
            raise PipelineError("dast base URL задан, но ZAP scanner не настроен")

        executed = 0
        skipped = []
        for index, vulnerability in enumerate(vulnerabilities):
            result = self.dast_scanner.scan(vulnerability, base_url)
            if result.step is None:
                skipped.append(
                    {
                        "vulnerability_id": vulnerability["id"],
                        "target_url": result.target_url,
                        "reason": result.skip_reason,
                    }
                )
                continue

            executed += 1
            # vls сам применяет результат выполненного dast-этапа
            record = VLS.model_validate(vulnerability).with_dast_verification(
                result.step
            )
            vulnerabilities[index] = record.model_dump(mode="json")
        return {
            "requested": True,
            "correlation_enabled": True,
            "executed": executed,
            "skipped": skipped,
        }
