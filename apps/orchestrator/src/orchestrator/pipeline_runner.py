from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from data_enricher import VLSBuilder
from vls import VlsRegistry

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
    """собирает результаты проверок в vls registry."""

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
        logs_dir: str | Path = "logs",
    ) -> VlsRegistry:
        target = Path(target_dir).expanduser().resolve()
        semgrep_output = self.scanner.scan(target)
        # локатор нужен только для связи sast и dast
        enriched_output = (
            self.endpoint_locator.enrich(target, semgrep_output)
            if correlation_enabled
            else semgrep_output
        )
        registry = VlsRegistry.from_records(self.builder.build(enriched_output))

        if dast_base_url is None:
            return registry
        if self.dast_scanner is None:
            raise PipelineError("dast base URL задан, но ZAP scanner не настроен")

        if not correlation_enabled:
            # несвязанный dast сохраняется отдельно и не меняет vls
            report = self.dast_scanner.scan_standalone(dast_base_url)
            self._write_dast_log(report, logs_dir)
            return registry

        self._merge_dast(registry, dast_base_url)
        return registry

    def _merge_dast(
        self,
        registry: VlsRegistry,
        base_url: str,
    ) -> None:
        for vulnerability in registry.all():
            result = self.dast_scanner.scan(
                vulnerability.model_dump(mode="json"),
                base_url,
            )
            if result.step is None:
                continue
            # upsert сохраняет sast и добавляет связанную dast-проверку
            registry.upsert(vulnerability.with_dast_verification(result.step))

    @staticmethod
    def _write_dast_log(report: dict[str, Any], logs_dir: str | Path) -> Path:
        directory = Path(logs_dir).expanduser().resolve()
        directory.mkdir(parents=True, exist_ok=True)
        output = directory / "dast-report.json"
        output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return output


def run_pipeline(
    target_dir: str | Path,
    *,
    dast_base_url: str | None = None,
    correlation_enabled: bool = True,
    logs_dir: str | Path = "logs",
    semgrep_config: str = "p/sql-injection",
    semgrep_timeout: float = 300,
    zap_network: str | None = None,
    zap_image: str = "ghcr.io/zaproxy/zaproxy:stable",
    zap_timeout: float = 900,
) -> VlsRegistry:
    """запускает весь пайплайн и возвращает готовый registry."""
    dast_scanner = None
    if dast_base_url is not None:
        if not zap_network:
            raise PipelineError("zap network требуется при запуске dast")
        dast_scanner = ZapDastScanner(
            docker_network=zap_network,
            image=zap_image,
            timeout_seconds=zap_timeout,
        )

    pipeline = SecurityPipeline(
        scanner=SemgrepScanner(semgrep_config, semgrep_timeout),
        builder=VLSBuilder(),
        dast_scanner=dast_scanner,
    )
    return pipeline.run(
        target_dir,
        dast_base_url=dast_base_url,
        correlation_enabled=correlation_enabled,
        logs_dir=logs_dir,
    )
