from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from vls import DastReport, DastVerificationStep

from .errors import PipelineError


@dataclass(frozen=True)
class DastScanResult:
    step: DastVerificationStep | None
    target_url: str | None
    confirmed: bool = False
    skip_reason: str | None = None


class ZapDastScanner:
    """запускает zap для найденного endpoint."""

    def __init__(
        self,
        docker_network: str,
        image: str = "ghcr.io/zaproxy/zaproxy:stable",
        timeout_seconds: float = 900,
    ) -> None:
        if not docker_network:
            raise ValueError("для zap требуется docker network")
        self.docker_network = docker_network
        self.image = image
        self.timeout_seconds = timeout_seconds

    def scan(
        self,
        vulnerability: dict[str, Any],
        base_url: str,
    ) -> DastScanResult:
        sast = vulnerability.get("sast") or {}
        endpoint = sast.get("endpoint") or {}
        target_url, skip_reason = self._target_url(base_url, endpoint)
        if skip_reason is not None:
            return DastScanResult(None, target_url, skip_reason=skip_reason)

        methods = endpoint.get("http_methods") or []
        method = methods[0] if methods else "GET"
        if method != "GET":
            return DastScanResult(
                None,
                target_url,
                skip_reason=f"метод {method} пока не поддержан точечным zap-сканером",
            )

        report = self._run_zap(target_url)
        relevant_alerts = self._relevant_alerts(report, sast, target_url)
        confirmed = bool(relevant_alerts)
        first = relevant_alerts[0] if relevant_alerts else {}
        instance = first.get("instance") or {}
        details = (
            f"ZAP нашел {len(relevant_alerts)} совпадающих предупреждений"
            if confirmed
            else "ZAP не нашел предупреждений с совпадающим CWE на endpoint"
        )
        step = DastVerificationStep(
            run_executed=True,
            verdict_output="confirmed" if confirmed else "unconfirmed",
            human_report=DastReport(
                executor_name="OWASP ZAP",
                action_taken="точечный active scan найденного endpoint",
                result_details=details,
                target_url=target_url,
                http_method=method,
                parameter=instance.get("param"),
                payload=instance.get("attack"),
                evidence=instance.get("evidence") or first.get("name"),
            ),
        )
        return DastScanResult(step, target_url, confirmed=confirmed)

    def _run_zap(self, target_url: str) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="orchestrator-zap-") as directory:
            workdir = Path(directory)
            # zap пишет отчет от непривилегированного пользователя контейнера
            workdir.chmod(0o777)
            report = workdir / "report.json"
            command = [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--network",
                self.docker_network,
                "--volume",
                f"{workdir}:/zap/wrk:rw",
                self.image,
                "zap.sh",
                "-cmd",
                "-quickurl",
                target_url,
                "-quickout",
                "/zap/wrk/report.json",
                "-quickprogress",
            ]
            try:
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )
            except FileNotFoundError as exc:
                raise PipelineError("docker executable was not found in PATH") from exc
            except subprocess.TimeoutExpired as exc:
                raise PipelineError("ZAP scan timed out") from exc

            if not report.is_file():
                details = process.stderr.strip() or process.stdout.strip() or "нет отчета"
                raise PipelineError(f"ZAP failed: {details}")
            try:
                return json.loads(report.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise PipelineError("ZAP returned invalid JSON report") from exc

    @staticmethod
    def _target_url(
        base_url: str,
        endpoint: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        base = urlsplit(base_url)
        if base.scheme not in {"http", "https"} or not base.netloc:
            raise PipelineError("dast base URL must use http or https")
        path = endpoint.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            return None, "локатор не нашел абсолютный путь endpoint"
        if re.search(r"[()\[\]*+?]", path):
            return None, "динамический regex-маршрут нельзя безопасно преобразовать в URL"

        concrete_path = re.sub(r":[A-Za-z_]\w*", "1", path)
        query = list(parse_qsl(base.query, keep_blank_values=True))
        query.extend((name, "1") for name in endpoint.get("query_parameters", []))
        target_url = urlunsplit(
            (base.scheme, base.netloc, concrete_path, urlencode(query), "")
        )
        return target_url, None

    @staticmethod
    def _relevant_alerts(
        report: dict[str, Any],
        sast: dict[str, Any],
        target_url: str,
    ) -> list[dict[str, Any]]:
        sast_cwes = {
            int(number)
            for value in sast.get("cwe", [])
            for number in re.findall(r"\d+", str(value))
        }
        target_path = urlsplit(target_url).path.rstrip("/") or "/"
        matches: list[dict[str, Any]] = []
        for site in report.get("site", []):
            for alert in site.get("alerts", []):
                try:
                    alert_cwe = int(alert.get("cweid"))
                except (TypeError, ValueError):
                    continue
                if not sast_cwes or alert_cwe not in sast_cwes:
                    continue
                for instance in alert.get("instances", []):
                    uri_path = urlsplit(str(instance.get("uri") or "")).path.rstrip("/") or "/"
                    if uri_path == target_path:
                        matches.append(
                            {
                                "name": alert.get("name") or alert.get("alert"),
                                "cwe": alert_cwe,
                                "risk": alert.get("riskdesc"),
                                "instance": instance,
                            }
                        )
        return matches
