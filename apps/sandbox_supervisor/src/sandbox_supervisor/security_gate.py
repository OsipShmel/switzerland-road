from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Request,
    status,
)
from fastapi.responses import StreamingResponse
from orchestrator import run_pipeline
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator
from vls import VLS, VlsRegistry

from .VLSManager import vls_manager_instance
from .scan_events import ScanEventBroker, scan_event_broker
from .supervisor import Supervisor


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/security-gate", tags=["security-gate"])

ScanStatus = Literal[
    "accepted",
    "running",
    "sandbox_starting",
    "agent_running",
    "completed",
    "failed",
]
SemgrepConfig = Literal["p/sql-injection", "p/default", "auto"]
PipelineRunner = Callable[..., VlsRegistry]
RegistryPublisher = Callable[[list[dict[str, Any]]], Awaitable[None]]
SandboxDispatcher = Callable[[Path, VlsRegistry], Awaitable[None]]


def _allowed_repository_hosts() -> set[str]:
    configured = os.getenv(
        "SECURITY_GATE_ALLOWED_REPOSITORY_HOSTS",
        "github.com,gitlab.com,bitbucket.org",
    )
    return {host.strip().lower() for host in configured.split(",") if host.strip()}


class ScanSubmission(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    repository_url: AnyHttpUrl = Field(alias="repositoryUrl")
    correlation_enabled: bool = Field(alias="correlationEnabled")
    semgrep_config: SemgrepConfig | None = Field(default=None, alias="semgrepConfig")

    @field_validator("repository_url")
    @classmethod
    def validate_repository_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        parsed = urlsplit(str(value))
        if parsed.username or parsed.password:
            raise ValueError("repository URL must not contain credentials")

        allowed_hosts = _allowed_repository_hosts()
        if (
            "*" not in allowed_hosts
            and (parsed.hostname or "").lower() not in allowed_hosts
        ):
            raise ValueError("repository host is not allowed")
        return value


class ScanReceipt(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    scan_id: str = Field(alias="scanId")
    status: ScanStatus = "accepted"
    repository_url: str = Field(alias="repositoryUrl")
    correlation_enabled: bool = Field(alias="correlationEnabled")
    semgrep_config: str = Field(alias="semgrepConfig")
    finding_count: int | None = Field(default=None, alias="findingCount")
    error: str | None = None


class SecurityGateInbox:
    """хранит состояние заявок и их результаты."""

    def __init__(self) -> None:
        self._submissions: dict[str, ScanReceipt] = {}
        self._registries: dict[str, list[dict[str, Any]]] = {}

    def accept(
        self,
        submission: ScanSubmission,
        default_semgrep_config: str = "p/sql-injection",
    ) -> ScanReceipt:
        scan_id = str(uuid4())
        receipt = ScanReceipt(
            scan_id=scan_id,
            repository_url=str(submission.repository_url),
            correlation_enabled=submission.correlation_enabled,
            semgrep_config=submission.semgrep_config or default_semgrep_config,
        )
        self._submissions[scan_id] = receipt
        return receipt

    def get(self, scan_id: str) -> ScanReceipt | None:
        return self._submissions.get(scan_id)

    def mark_running(self, scan_id: str) -> ScanReceipt:
        receipt = self._required(scan_id)
        receipt.status = "running"
        receipt.error = None
        return receipt

    def store_registry(
        self,
        scan_id: str,
        records: list[dict[str, Any]],
    ) -> None:
        receipt = self._required(scan_id)
        self._registries[scan_id] = records
        receipt.finding_count = len(records)

    def mark_completed(self, scan_id: str) -> ScanReceipt:
        receipt = self._required(scan_id)
        receipt.status = "completed"
        receipt.error = None
        return receipt

    def mark_sandbox_starting(self, scan_id: str) -> ScanReceipt:
        receipt = self._required(scan_id)
        receipt.status = "sandbox_starting"
        return receipt

    def mark_agent_running(self, scan_id: str) -> ScanReceipt:
        receipt = self._required(scan_id)
        receipt.status = "agent_running"
        return receipt

    def mark_failed(self, scan_id: str, error: str) -> ScanReceipt:
        receipt = self._required(scan_id)
        receipt.status = "failed"
        receipt.error = error
        return receipt

    def get_registry(self, scan_id: str) -> list[dict[str, Any]] | None:
        self._required(scan_id)
        return self._registries.get(scan_id)

    def upsert_vls(self, scan_id: str, record: dict[str, Any]) -> None:
        receipt = self._required(scan_id)
        records = self._registries.setdefault(scan_id, [])
        for index, current in enumerate(records):
            if current.get("id") == record.get("id"):
                records[index] = record
                break
        else:
            records.append(record)
        receipt.finding_count = len(records)

    def _required(self, scan_id: str) -> ScanReceipt:
        receipt = self.get(scan_id)
        if receipt is None:
            raise KeyError(scan_id)
        return receipt


class RepositoryCloner(Protocol):
    async def clone(self, repository_url: str, destination: Path) -> None: ...


class GitRepositoryCloner:
    """клонирует публичный git-репозиторий без истории."""

    def __init__(self, timeout_seconds: float = 180) -> None:
        self.timeout_seconds = timeout_seconds

    async def clone(self, repository_url: str, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        command = [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.file.allow=never",
            "clone",
            "--depth",
            "1",
            "--no-tags",
            "--single-branch",
            "--",
            repository_url,
            str(destination),
        ]
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "/bin/false",
                "GCM_INTERACTIVE": "never",
            }
        )
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("git executable was not found") from exc

        try:
            _stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout_seconds,
            )
        except TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise RuntimeError("repository clone timed out") from exc

        if process.returncode != 0:
            details = stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"repository clone failed: {details[:1000]}")


async def dispatch_to_sandbox(
    target_dir: Path,
    registry: VlsRegistry,
) -> None:
    import httpx

    async with httpx.AsyncClient(timeout=60.0) as client:
        await Supervisor(client).start_from_directory(target_dir, registry)


def _severity(value: Any) -> str:
    normalized = str(value or "").lower()
    if normalized in {"critical", "high", "medium", "low"}:
        return normalized
    return {
        "error": "high",
        "warning": "medium",
        "info": "low",
    }.get(normalized, "medium")


def _finding_event(record: dict[str, Any]) -> dict[str, Any]:
    sast = record.get("sast") or {}
    endpoint = sast.get("endpoint") or {}
    path = endpoint.get("path")
    methods = endpoint.get("http_methods") or []
    if path:
        method_prefix = f"{', '.join(methods)} " if methods else ""
        location = f"{method_prefix}{path}"
    else:
        file_path = sast.get("file_path") or "неизвестный источник"
        line = sast.get("line")
        location = f"{file_path}:{line}" if line else file_path

    dast = ((record.get("verification_history") or {}).get("dast") or {})
    if sast and dast.get("run_executed"):
        source = "SAST + DAST"
    elif dast.get("run_executed"):
        source = "DAST"
    else:
        source = "SAST"

    return {
        "type": "finding",
        "finding": {
            "id": str(record.get("id") or "unknown"),
            "title": str(record.get("title") or "Уязвимость без названия"),
            "severity": _severity(sast.get("severity")),
            "source": source,
            "location": location,
            "status": (
                "confirmed"
                if record.get("verdict") == "confirmed"
                else "unconfirmed"
            ),
        },
    }


_SANDBOX_PROGRESS: dict[str, tuple[str, str, int]] = {
    "sandbox.startup_started": (
        "Песочница",
        "Начинается развертывание изолированного окружения",
        80,
    ),
    "sandbox.started": (
        "Песочница",
        "Окружение запущено, ожидается старт агента",
        88,
    ),
    "sandbox.node_build_started": (
        "Песочница",
        "Собирается контейнер target или агента",
        82,
    ),
    "sandbox.node_build_finished": (
        "Песочница",
        "Сборка контейнера завершена",
        84,
    ),
    "sandbox.node_started": (
        "Песочница",
        "Контейнер запущен",
        85,
    ),
    "sandbox.node_healthcheck_started": (
        "Песочница",
        "Проверяется готовность контейнера",
        86,
    ),
    "sandbox.node_healthy": (
        "Песочница",
        "Контейнер готов к работе",
        87,
    ),
    "agent_started": (
        "Pentest agent",
        "Агент начал проверять записи VLS Registry",
        90,
    ),
    "check_session_started": (
        "Pentest agent",
        "Начата проверка следующей уязвимости",
        93,
    ),
    "tool_start": (
        "Pentest tools",
        "Агент запустил инструмент проверки",
        95,
    ),
    "tool_result": (
        "Pentest tools",
        "Инструмент вернул результат агенту",
        96,
    ),
    "tool_error": (
        "Pentest tools",
        "Инструмент завершился с ошибкой, агент получил результат",
        96,
    ),
    "check_result_submitted": (
        "VLS Registry",
        "Результат проверки записан в VLS",
        97,
    ),
    "check_session_finished": (
        "Pentest agent",
        "Проверка уязвимости завершена",
        98,
    ),
}


class SecurityGateService:
    """запускает pipeline для принятой заявки."""

    def __init__(
        self,
        inbox: SecurityGateInbox,
        cloner: RepositoryCloner,
        pipeline_runner: PipelineRunner = run_pipeline,
        registry_publisher: RegistryPublisher = vls_manager_instance.set_registry,
        sandbox_dispatcher: SandboxDispatcher = dispatch_to_sandbox,
        event_broker: ScanEventBroker = scan_event_broker,
        work_dir: str | Path | None = None,
        semgrep_config: str | None = None,
        semgrep_timeout: float | None = None,
    ) -> None:
        self.inbox = inbox
        self.cloner = cloner
        self.pipeline_runner = pipeline_runner
        self.registry_publisher = registry_publisher
        self.sandbox_dispatcher = sandbox_dispatcher
        self.event_broker = event_broker
        self.work_dir = Path(
            work_dir or os.getenv("SECURITY_GATE_WORK_DIR", "/tmp/security-gate")
        )
        self.semgrep_config = semgrep_config or os.getenv(
            "SECURITY_GATE_SEMGREP_CONFIG",
            "p/sql-injection",
        )
        self.semgrep_timeout = semgrep_timeout or float(
            os.getenv("SECURITY_GATE_SEMGREP_TIMEOUT", "300")
        )

    async def execute(self, scan_id: str) -> None:
        receipt = self.inbox.mark_running(scan_id)
        scan_dir = self.work_dir / scan_id
        repository_dir = scan_dir / "repository"
        logs_dir = scan_dir / "logs"

        try:
            await self.event_broker.publish(
                scan_id,
                {
                    "type": "progress",
                    "stage": "Подготовка",
                    "details": "Скачивается репозиторий",
                    "progress": 10,
                },
            )
            # pipeline получает локальный путь, поэтому сначала клонируем target
            await self.cloner.clone(receipt.repository_url, repository_dir)
            await self.event_broker.publish(
                scan_id,
                {
                    "type": "progress",
                    "stage": "SAST",
                    "details": f"Semgrep запущен с конфигом {receipt.semgrep_config}",
                    "progress": 25,
                },
            )
            registry = await asyncio.to_thread(
                self.pipeline_runner,
                repository_dir,
                correlation_enabled=receipt.correlation_enabled,
                logs_dir=logs_dir,
                semgrep_config=receipt.semgrep_config,
                semgrep_timeout=self.semgrep_timeout,
            )
            records = registry.to_records()
            await self.registry_publisher(records)
            self.inbox.store_registry(scan_id, records)
            await self.event_broker.publish(
                scan_id,
                {
                    "type": "progress",
                    "stage": "VLS Registry",
                    "details": f"Pipeline собрал записей: {len(records)}",
                    "progress": 65,
                },
            )
            for record in records:
                await self.event_broker.publish(scan_id, _finding_event(record))

            self.inbox.mark_sandbox_starting(scan_id)
            await self.event_broker.publish(
                scan_id,
                {
                    "type": "progress",
                    "stage": "Песочница",
                    "details": "Target и VLS Registry передаются в sandboxd",
                    "progress": 72,
                },
            )
            await self.sandbox_dispatcher(repository_dir, registry)
        except Exception as exc:
            logger.exception("security gate scan %s failed", scan_id)
            self.inbox.mark_failed(scan_id, str(exc))
            await self.event_broker.publish(
                scan_id,
                {"type": "error", "message": str(exc)},
            )
        finally:
            if os.getenv("SECURITY_GATE_KEEP_WORK_DIR", "0") != "1":
                # удаляем только каталог конкретной заявки
                await asyncio.to_thread(shutil.rmtree, scan_dir, True)

    async def handle_sandbox_vls(self, vls: VLS) -> None:
        scan_id = self.event_broker.active_scan_id
        if scan_id is None or self.inbox.get(scan_id) is None:
            return
        record = vls.model_dump(mode="json")
        self.inbox.upsert_vls(scan_id, record)
        await self.event_broker.publish(scan_id, _finding_event(record))

    async def handle_sandbox_log(self, payload: dict[str, Any]) -> None:
        scan_id = self.event_broker.active_scan_id
        if scan_id is None or self.inbox.get(scan_id) is None:
            return

        event_name = str(payload.get("event") or "")
        if event_name == "agent_started":
            self.inbox.mark_agent_running(scan_id)

        progress = _SANDBOX_PROGRESS.get(event_name)
        if progress is not None:
            stage, default_details, percent = progress
            metadata = payload.get("metadata") or {}
            action = metadata.get("action")
            vulnerability_id = metadata.get("vulnerability_id")
            node = metadata.get("node_image") or metadata.get("image") or metadata.get(
                "node"
            )
            suffix = action or vulnerability_id or node
            details = f"{default_details}: {suffix}" if suffix else default_details
            await self.event_broker.publish(
                scan_id,
                {
                    "type": "progress",
                    "stage": stage,
                    "details": details,
                    "progress": percent,
                },
            )

        if event_name in {
            "sandbox.startup_failed",
            "sandbox.node_build_failed",
            "sandbox.node_healthcheck_failed",
            "agent_max_errors",
        }:
            message = str(payload.get("message") or "Выполнение завершилось с ошибкой")
            self.inbox.mark_failed(scan_id, message)
            await self.event_broker.publish(
                scan_id,
                {"type": "error", "message": message},
            )
            return

        if event_name == "agent_stopped":
            receipt = self.inbox.mark_completed(scan_id)
            await self.event_broker.publish(
                scan_id,
                {
                    "type": "complete",
                    "summary": (
                        "Проверка завершена. "
                        f"Записей в VLS Registry: {receipt.finding_count or 0}"
                    ),
                },
            )


security_gate_inbox = SecurityGateInbox()
security_gate_service = SecurityGateService(
    inbox=security_gate_inbox,
    cloner=GitRepositoryCloner(
        timeout_seconds=float(os.getenv("SECURITY_GATE_CLONE_TIMEOUT", "180"))
    ),
)


def get_security_gate_service() -> SecurityGateService:
    return security_gate_service


@router.post(
    "/scans",
    response_model=ScanReceipt,
    response_model_by_alias=True,
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_scan(
    submission: ScanSubmission,
    background_tasks: BackgroundTasks,
    service: SecurityGateService = Depends(get_security_gate_service),
) -> ScanReceipt:
    active_scan_id = service.event_broker.active_scan_id
    if active_scan_id is not None:
        active = service.inbox.get(active_scan_id)
        if active is not None and active.status not in {"completed", "failed"}:
            raise HTTPException(
                status_code=409,
                detail="another scan is already running",
            )

    receipt = service.inbox.accept(submission, service.semgrep_config)
    service.event_broker.activate(receipt.scan_id)
    await service.event_broker.publish(
        receipt.scan_id,
        {
            "type": "progress",
            "stage": "Security Gate",
            "details": "Заявка принята supervisor",
            "progress": 5,
        },
    )
    background_tasks.add_task(service.execute, receipt.scan_id)
    return receipt


@router.get(
    "/scans/{scan_id}",
    response_model=ScanReceipt,
    response_model_by_alias=True,
)
async def get_scan(
    scan_id: str,
    service: SecurityGateService = Depends(get_security_gate_service),
) -> ScanReceipt:
    receipt = service.inbox.get(scan_id)
    if receipt is None:
        raise HTTPException(status_code=404, detail="scan request not found")
    return receipt


@router.get("/scans/{scan_id}/registry")
async def get_scan_registry(
    scan_id: str,
    service: SecurityGateService = Depends(get_security_gate_service),
) -> list[dict[str, Any]]:
    try:
        records = service.inbox.get_registry(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="scan request not found") from exc
    if records is None:
        raise HTTPException(status_code=409, detail="scan is not completed")
    return records


@router.get("/scans/{scan_id}/events")
async def stream_scan_events(
    scan_id: str,
    request: Request,
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    service: SecurityGateService = Depends(get_security_gate_service),
) -> StreamingResponse:
    if service.inbox.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="scan request not found")
    try:
        after_event_id = int(last_event_id or 0)
    except ValueError:
        after_event_id = 0

    async def event_stream():
        async for event in service.event_broker.subscribe(scan_id, after_event_id):
            if await request.is_disconnected():
                break
            if event is None:
                yield ": keep-alive\n\n"
                continue
            payload = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
            yield f"id: {event['id']}\ndata: {payload}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
