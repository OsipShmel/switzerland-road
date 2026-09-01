from __future__ import annotations

import asyncio
import io
import os
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

from vls import VlsRegistry, VLS

from .VLSManager import vls_manager_instance
from .sandbox_io_manager import SandboxIOManager

router = APIRouter(prefix="/api/supervisor", tags=["supervisor"])


class StartRequest(BaseModel):
    target_link: str | None = None
    vlsreg: list[VLS] | None = None


def _sandbox_url() -> str:
    return os.getenv("SANDBOXD_URL", "http://sandboxd:8001")


class Supervisor:
    MAX_RETRIES = 5

    def __init__(
        self,
        client: httpx.AsyncClient,
        sandbox_url: str | None = None,
        io_manager: SandboxIOManager | None = None,
    ) -> None:
        self._client = client
        self._iomanager = io_manager or SandboxIOManager(
            sandbox_url or _sandbox_url(),
            client,
        )

    async def start(self, target_link: str | None, vlsreg: VlsRegistry | None = None) -> None:
        await self._setup_target(target_link)

        if vlsreg is None:
            return

        await self._send_registry(vlsreg)

    async def start_from_directory(
        self,
        target_dir: str | Path,
        vlsreg: VlsRegistry,
    ) -> None:
        # sandboxd сам запускает окружение после получения target и registry
        target_zip_bytes = await asyncio.to_thread(
            self._pack_directory,
            Path(target_dir),
        )
        await self._send_target(target_zip_bytes)
        await self._send_registry(vlsreg)

    async def _send_registry(self, vlsreg: VlsRegistry) -> None:
        retries = 0
        while not await self._iomanager.send_vls_registry(vlsreg):
            retries += 1
            if retries >= self.MAX_RETRIES:
                raise RuntimeError("failed to transfer VLS registry")
            await asyncio.sleep(5)

    async def _get_target_zip(self, target_link: str) -> bytes:
        response = await self._client.get(target_link, timeout=60.0)
        response.raise_for_status()
        return response.content

    async def _setup_target(self, target_link: str | None = None) -> None:
        if target_link:
            target_zip_bytes = await self._get_target_zip(target_link)
        else:
            target_zip_bytes = await asyncio.to_thread(
                self._pack_directory,
                Path("/tmp/target_app"),
            )

        await self._send_target(target_zip_bytes)

    async def _send_target(self, target_zip_bytes: bytes) -> None:
        retries = 0
        while not await self._iomanager.send_zip(target_zip_bytes):
            retries += 1
            if retries >= self.MAX_RETRIES:
                raise RuntimeError("failed to transfer target")
            await asyncio.sleep(5)

    @staticmethod
    def _pack_directory(source_root: Path) -> bytes:
        source_root = source_root.expanduser().resolve()
        if not source_root.is_dir():
            raise RuntimeError(f"target directory does not exist: {source_root}")

        output = io.BytesIO()
        with ZipFile(output, "w", ZIP_DEFLATED) as fzip:
            for file_path in source_root.rglob("*"):
                relative = file_path.relative_to(source_root)
                if ".git" in relative.parts or file_path.is_symlink():
                    continue
                if file_path.is_file():
                    fzip.write(file_path, relative.as_posix())
        return output.getvalue()


@router.post("/start")
async def start_supervisor(body: StartRequest):
    vlsreg = VlsRegistry(body.vlsreg) if body.vlsreg is not None else None
    async with httpx.AsyncClient(timeout=60.0) as client:
        if vlsreg is not None:
            await vls_manager_instance.set_registry(vlsreg.to_records())
        supervisor = Supervisor(client)
        await supervisor.start(body.target_link, vlsreg)
    return {"accepted": True}
