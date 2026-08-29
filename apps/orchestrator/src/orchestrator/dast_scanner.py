from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import uuid
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

    _all_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]

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

        # один идентификатор связывает zap с исполняемой трассой
        trace_id = uuid.uuid4().hex
        # схема ограничивает zap найденным маршрутом
        specification = self._openapi_spec(base_url, endpoint)
        report = self._run_zap(specification, trace_id)
        runtime_trace = self._fetch_runtime_trace(base_url, trace_id)
        relevant_alerts = self._relevant_alerts(
            report,
            sast,
            target_url,
            runtime_trace,
        )
        confirmed = bool(relevant_alerts)
        first = relevant_alerts[0] if relevant_alerts else {}
        instance = first.get("instance") or {}
        runtime_events = first.get("runtime_events") or []
        methods = self._http_methods(endpoint)
        details = (
            f"ZAP и runtime-трасса подтвердили {len(relevant_alerts)} совпадений"
            if confirmed
            else "совпадение ZAP не подтверждено runtime-трассой до строки SAST"
        )
        step = DastVerificationStep(
            run_executed=True,
            verdict_output="confirmed" if confirmed else "unconfirmed",
            human_report=DastReport(
                executor_name="OWASP ZAP",
                action_taken="точечный active scan найденного endpoint",
                result_details=details,
                target_url=target_url,
                http_method=instance.get("method") or ",".join(methods),
                parameter=instance.get("param"),
                payload=instance.get("attack"),
                evidence=instance.get("evidence") or first.get("name"),
                runtime_trace_id=trace_id,
                runtime_evidence=self._runtime_evidence(runtime_events, sast),
            ),
        )
        return DastScanResult(step, target_url, confirmed=confirmed)

    def scan_standalone(self, base_url: str) -> dict[str, Any]:
        """запускает полный zap без связи с sast."""
        self._validate_base_url(base_url)
        with tempfile.TemporaryDirectory(prefix="orchestrator-zap-") as directory:
            workdir = Path(directory)
            # zap пишет отчет от пользователя контейнера
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
                "zap-full-scan.py",
                "-t",
                base_url,
                "-J",
                "report.json",
                "-I",
            ]
            process = self._run_command(command, "ZAP scan timed out")
            if not report.is_file():
                details = (
                    process.stderr.strip()
                    or process.stdout.strip()
                    or "нет отчета"
                )
                raise PipelineError(f"ZAP failed: {details}")
            try:
                parsed = json.loads(report.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise PipelineError("ZAP returned invalid JSON report") from exc
            if not isinstance(parsed, dict):
                raise PipelineError("ZAP report must be a JSON object")
            return parsed

    def _run_zap(
        self,
        specification: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="orchestrator-zap-") as directory:
            workdir = Path(directory)
            # zap пишет отчет от пользователя контейнера
            workdir.chmod(0o777)
            report = workdir / "report.json"
            specification_path = workdir / "openapi.json"
            specification_path.write_text(
                json.dumps(specification, ensure_ascii=False),
                encoding="utf-8",
            )
            # replacer добавляет идентификатор трассы в запросы zap
            replacer = " ".join(
                [
                    "-config replacer.full_list(0).description=vls-trace",
                    "-config replacer.full_list(0).enabled=true",
                    "-config replacer.full_list(0).matchtype=REQ_HEADER",
                    "-config replacer.full_list(0).matchstr=X-VLS-Trace-Id",
                    f"-config replacer.full_list(0).replacement={trace_id}",
                ]
            )
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
                "zap-api-scan.py",
                "-t",
                "/zap/wrk/openapi.json",
                "-f",
                "openapi",
                "-J",
                "report.json",
                "-I",
                "-z",
                replacer,
            ]
            process = self._run_command(command, "ZAP scan timed out")
            if not report.is_file():
                details = process.stderr.strip() or process.stdout.strip() or "нет отчета"
                raise PipelineError(f"ZAP failed: {details}")
            try:
                return json.loads(report.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise PipelineError("ZAP returned invalid JSON report") from exc

    def _fetch_runtime_trace(
        self,
        base_url: str,
        trace_id: str,
    ) -> dict[str, Any]:
        # трасса читается из той же внутренней сети
        base = urlsplit(base_url)
        trace_url = urlunsplit(
            (base.scheme, base.netloc, f"/_vls/trace/{trace_id}", "", "")
        )
        script = (
            "import sys,urllib.request;"
            "print(urllib.request.urlopen(sys.argv[1],timeout=10).read().decode())"
        )
        command = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network",
            self.docker_network,
            "--entrypoint",
            "python3",
            self.image,
            "-c",
            script,
            trace_url,
        ]
        try:
            process = self._run_command(command, "runtime trace timed out", timeout=30)
        except PipelineError as exc:
            return {"available": False, "events": [], "error": str(exc)}
        if process.returncode != 0:
            details = process.stderr.strip() or process.stdout.strip()
            return {"available": False, "events": [], "error": details}
        try:
            trace = json.loads(process.stdout)
        except json.JSONDecodeError:
            return {"available": False, "events": [], "error": "invalid trace JSON"}
        if not isinstance(trace, dict) or not isinstance(trace.get("events"), list):
            return {"available": False, "events": [], "error": "invalid trace shape"}
        trace["available"] = True
        return trace

    def _run_command(
        self,
        command: list[str],
        timeout_message: str,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise PipelineError("docker executable was not found in PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise PipelineError(timeout_message) from exc

    @classmethod
    def _openapi_spec(
        cls,
        base_url: str,
        endpoint: dict[str, Any],
    ) -> dict[str, Any]:
        # параметры раскладываются по местам из маршрута
        base = urlsplit(base_url)
        server_url = urlunsplit((base.scheme, base.netloc, base.path.rstrip("/"), "", ""))
        path = cls._openapi_path(str(endpoint["path"]))
        parameters = cls._parameters(endpoint)
        operations: dict[str, Any] = {}
        for method in cls._http_methods(endpoint):
            operation: dict[str, Any] = {
                "operationId": f"vls_{method.lower()}",
                "responses": {"200": {"description": "scan response"}},
            }
            regular_parameters = []
            body_parameters = []
            for parameter in parameters:
                if parameter["location"] == "body":
                    body_parameters.append(parameter)
                    continue
                regular_parameters.append(
                    {
                        "name": parameter["name"],
                        "in": parameter["location"],
                        "required": parameter["location"] == "path" or parameter["required"],
                        "schema": {"type": "string", "example": "1"},
                    }
                )
            if regular_parameters:
                operation["parameters"] = regular_parameters
            if body_parameters and method not in {"GET", "HEAD", "TRACE"}:
                operation["requestBody"] = {
                    "required": any(item["required"] for item in body_parameters),
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    item["name"]: {"type": "string", "example": "1"}
                                    for item in body_parameters
                                },
                            }
                        }
                    },
                }
            operations[method.lower()] = operation
        return {
            "openapi": "3.0.0",
            "info": {"title": "VLS targeted scan", "version": "1.0.0"},
            "servers": [{"url": server_url}],
            "paths": {path: operations},
        }

    @classmethod
    def _target_url(
        cls,
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
        concrete_path = re.sub(r"\{[A-Za-z_]\w*\}", "1", concrete_path)
        concrete_path = re.sub(r"<(?:(?:[^:>]+):)?[A-Za-z_]\w*>", "1", concrete_path)
        query = list(parse_qsl(base.query, keep_blank_values=True))
        query.extend(
            (item["name"], "1")
            for item in cls._parameters(endpoint)
            if item["location"] == "query"
        )
        target_url = urlunsplit(
            (base.scheme, base.netloc, concrete_path, urlencode(query), "")
        )
        return target_url, None

    @staticmethod
    def _validate_base_url(base_url: str) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise PipelineError("dast base URL must use http or https")

    @classmethod
    def _relevant_alerts(
        cls,
        report: dict[str, Any],
        sast: dict[str, Any],
        target_url: str,
        runtime_trace: dict[str, Any],
    ) -> list[dict[str, Any]]:
        # сначала сверяются cwe, путь, метод и параметр
        sast_cwes = {
            int(number)
            for value in sast.get("cwe", [])
            for number in re.findall(r"\d+", str(value))
        }
        endpoint = sast.get("endpoint") or {}
        methods = set(cls._http_methods(endpoint))
        parameters = cls._parameters(endpoint)
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
                    method = str(instance.get("method") or "GET").upper()
                    if uri_path != target_path or method not in methods:
                        continue
                    if not cls._parameter_matches(instance.get("param"), parameters):
                        continue
                    runtime_events = cls._matching_runtime_events(
                        runtime_trace,
                        sast,
                        method,
                        uri_path,
                        alert_cwe,
                        instance,
                        parameters,
                    )
                    if not runtime_events:
                        continue
                    matches.append(
                        {
                            "name": alert.get("name") or alert.get("alert"),
                            "cwe": alert_cwe,
                            "risk": alert.get("riskdesc"),
                            "instance": instance,
                            "runtime_events": runtime_events,
                        }
                    )
        return matches

    @staticmethod
    def _matching_runtime_events(
        runtime_trace: dict[str, Any],
        sast: dict[str, Any],
        method: str,
        path: str,
        cwe: int,
        instance: dict[str, Any],
        parameters: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        # стек должен содержать точную строку sast
        if not runtime_trace.get("available"):
            return []
        file_path = str(sast.get("file_path") or "").replace("\\", "/").lstrip("./")
        try:
            line = int(sast.get("line"))
        except (TypeError, ValueError):
            return []
        if not file_path or line < 1:
            return []
        source_pattern = re.compile(
            rf"(?:^|[/\\]){re.escape(file_path)}:{line}(?::\d+)?(?:\)|\s|$)"
        )
        matches = []
        for event in runtime_trace.get("events", []):
            event_path = urlsplit(str(event.get("url") or "")).path.rstrip("/") or "/"
            if str(event.get("method") or "").upper() != method:
                continue
            if event_path != path or int(event.get("cwe") or 0) != cwe:
                continue
            if (
                source_pattern.search(str(event.get("stack") or ""))
                and ZapDastScanner._runtime_input_matches(
                    event,
                    instance,
                    parameters,
                )
            ):
                matches.append(event)
        return matches

    @staticmethod
    def _runtime_input_matches(
        event: dict[str, Any],
        instance: dict[str, Any],
        parameters: list[dict[str, Any]],
    ) -> bool:
        # хеш подтверждает конкретный параметр и нагрузку
        value = str(instance.get("param") or "").strip()
        attack = instance.get("attack")
        if not value or attack is None:
            return False
        tokens = re.findall(r"[A-Za-z_]\w*", value)
        name = tokens[-1] if tokens else value
        parameter = next(
            (item for item in parameters if item["name"] == name),
            None,
        )
        if parameter is None:
            return False
        expected = hashlib.sha256(str(attack).encode()).hexdigest()
        inputs = event.get("inputs") or {}
        actual = (inputs.get(parameter["location"]) or {}).get(name)
        return actual == expected

    @staticmethod
    def _parameter_matches(
        alert_parameter: Any,
        parameters: list[dict[str, Any]],
    ) -> bool:
        if not parameters:
            return not alert_parameter
        value = str(alert_parameter or "").strip()
        if not value:
            return False
        names = {str(item["name"]) for item in parameters}
        if value in names:
            return True
        tokens = re.findall(r"[A-Za-z_]\w*", value)
        return bool(tokens and tokens[-1] in names)

    @staticmethod
    def _runtime_evidence(
        events: list[dict[str, Any]],
        sast: dict[str, Any],
    ) -> list[str]:
        file_path = str(sast.get("file_path") or "").replace("\\", "/").lstrip("./")
        evidence = []
        for event in events:
            frame = next(
                (
                    line.strip()
                    for line in str(event.get("stack") or "").splitlines()
                    if file_path and file_path in line.replace("\\", "/")
                ),
                "stack frame unavailable",
            )
            value = f"{event.get('sink')}: {frame}"
            if value not in evidence:
                evidence.append(value)
        return evidence[:3]

    @classmethod
    def _parameters(cls, endpoint: dict[str, Any]) -> list[dict[str, Any]]:
        raw = endpoint.get("parameters") or []
        parameters = [
            {
                "name": str(item["name"]),
                "location": str(item["location"]),
                "required": bool(item.get("required", False)),
            }
            for item in raw
            if isinstance(item, dict) and item.get("name") and item.get("location")
        ]
        for name in endpoint.get("query_parameters", []):
            value = {"name": str(name), "location": "query", "required": False}
            if value not in parameters:
                parameters.append(value)
        return parameters

    @classmethod
    def _http_methods(cls, endpoint: dict[str, Any]) -> list[str]:
        methods = [
            str(method).upper()
            for method in endpoint.get("http_methods", [])
            if str(method).upper() in cls._all_methods
        ]
        return list(dict.fromkeys(methods)) or list(cls._all_methods)

    @staticmethod
    def _openapi_path(path: str) -> str:
        path = re.sub(r":([A-Za-z_]\w*)", r"{\1}", path)
        return re.sub(
            r"<(?:(?:[^:>]+):)?([A-Za-z_]\w*)>",
            r"{\1}",
            path,
        )
