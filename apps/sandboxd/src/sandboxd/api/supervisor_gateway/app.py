from __future__ import annotations

import asyncio
import io
import os
import shutil
from pathlib import Path, PurePosixPath
from uuid import uuid4
import zipfile

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Request
from sandboxdapi.AgentInteraction import AgentLog
from vls import VLS, VlsRegistry

from sandboxd.config.settings import SandboxSettings
from sandboxd.control_plane.sandbox_runtime import SandboxRuntime, SandboxStateStore
from sandboxd.control_plane.supervisor_client import SupervisorClient, SupervisorUnavailable

router = APIRouter(tags=["sandbox-control"])


class SandboxControlService:
    def __init__(
        self,
        settings: SandboxSettings,
        runtime: SandboxRuntime | None = None,
        supervisor: SupervisorClient | None = None,
        state_store: SandboxStateStore | None = None,
    ) -> None:
        self.settings = settings
        self.runtime = runtime or SandboxRuntime(settings)
        self.supervisor = supervisor or SupervisorClient(settings.supervisor_url, settings.supervisor_timeout)
        self.state_store = state_store or SandboxStateStore(settings.state_dir)

    async def receive_target(self, archive: bytes) -> None:
        if not archive:
            raise HTTPException(status_code=400, detail="target archive is empty")
        if self.runtime.started:
            await self.runtime.stop()
        try:
            await asyncio.to_thread(self._replace_target, archive)
        except (ValueError, zipfile.BadZipFile) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        self.runtime.mark_target_ready()
        self._schedule_start()

    async def receive_vls_registry(self, records: list[VLS]) -> None:
        registry = VlsRegistry(records)
        await self.state_store.write_registry(registry.to_records())
        self.runtime.mark_vls_ready()
        self._schedule_start()

    async def get_registry_records(self) -> list[dict]:
        return await self.state_store.read_registry()

    async def sync_vls(self, vls: VLS) -> None:
        records = await self.state_store.read_registry()
        registry = VlsRegistry.from_records(records)
        registry.upsert(vls)
        await self.state_store.write_registry(registry.to_records())
        try:
            await self.supervisor.send_vls_update(vls)
        except SupervisorUnavailable as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    async def publish_log(self, log: AgentLog, *, context: str) -> None:
        try:
            await self.supervisor.send_log(log, context=context)
        except SupervisorUnavailable as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    def _schedule_start(self) -> None:
        asyncio.create_task(self._ensure_started())

    async def _ensure_started(self) -> None:
        try:
            await self.runtime.ensure_started()
        except Exception as exc:
            print(f"[sandboxd] automatic sandbox startup failed: {exc}")

    def _replace_target(self, archive: bytes) -> None:
        target_dir = self.settings.target_dir
        target_dir.parent.mkdir(parents=True, exist_ok=True)
        temp_dir = target_dir.parent / f".{target_dir.name}.incoming-{uuid4().hex}"
        temp_dir.mkdir(parents=True, exist_ok=False)

        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                for member in zf.infolist():
                    self._validate_zip_member(member.filename)
                    destination = temp_dir / PurePosixPath(member.filename)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if member.is_dir():
                        destination.mkdir(parents=True, exist_ok=True)
                        continue
                    with zf.open(member, "r") as src, destination.open("wb") as dst:
                        shutil.copyfileobj(src, dst)

            if target_dir.exists():
                shutil.rmtree(target_dir)
            os.replace(temp_dir, target_dir)
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    @staticmethod
    def _validate_zip_member(name: str) -> None:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsafe archive member: {name!r}")
        if not name.strip():
            raise ValueError("archive contains an empty member name")



def create_sandbox_control_app(service: SandboxControlService) -> FastAPI:
    app = FastAPI(title="sandboxd control plane", version="0.1.0")
    app.state.sandbox_control = service
    app.include_router(router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def _service(request: Request) -> SandboxControlService:
    return request.app.state.sandbox_control


@router.post("/target_zip")
async def receive_target_zip(request: Request) -> dict[str, bool]:
    await _service(request).receive_target(await request.body())
    return {"is_success": True}


@router.post("/init_vls_registry")
async def initialize_vls_registry(records: list[VLS], request: Request) -> dict[str, bool]:
    try:
        await _service(request).receive_vls_registry(records)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"is_success": True}


@router.get("/get_instruction")
async def get_instruction(request: Request) -> dict[str, object]:
    service = _service(request)
    return {
        "is_success": True,
        "target_ready": service.runtime.target_ready,
        "vls_ready": service.runtime.vls_ready,
        "started": service.runtime.started,
    }


@router.get("/internal/vls-registry")
async def get_internal_vls_registry(request: Request) -> list[dict]:
    return await _service(request).get_registry_records()


@router.post("/internal/vls-updated")
async def receive_internal_vls_update(vls: VLS, request: Request) -> dict[str, bool]:
    await _service(request).sync_vls(vls)
    return {"accepted": True}


@router.post("/internal/log")
async def receive_internal_log(
    payload: dict,
    request: Request,
) -> dict[str, bool]:
    context = str(payload.pop("context", "global"))
    log = AgentLog.model_validate(payload)

    await _service(request).publish_log(
        log,
        context=context,
    )
    return {"accepted": True}
