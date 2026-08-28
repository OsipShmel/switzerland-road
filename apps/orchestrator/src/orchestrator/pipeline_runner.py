from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from data_enricher import VLSBuilder

from .endpoint_locator import EndpointLocator


class PipelineError(RuntimeError):
    """ошибка этапа пайплайна."""


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
    ) -> None:
        self.scanner = scanner
        self.builder = builder
        self.endpoint_locator = endpoint_locator or EndpointLocator()

    def run(self, target_dir: str | Path) -> dict[str, Any]:
        target = Path(target_dir).expanduser().resolve()
        semgrep_output = self.scanner.scan(target)
        enriched_output = self.endpoint_locator.enrich(target, semgrep_output)
        vulnerabilities = self.builder.build(enriched_output)
        return {
            "target_dir": str(target),
            "vulnerabilities": vulnerabilities,
        }
