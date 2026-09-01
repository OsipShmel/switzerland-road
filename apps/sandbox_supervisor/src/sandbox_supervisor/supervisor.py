from __future__ import annotations

import asyncio
import io
import os
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

    def __init__(self, client: httpx.AsyncClient, sandbox_url: str | None = None) -> None:
        self._client = client
        self._iomanager = SandboxIOManager(sandbox_url or _sandbox_url(), client)

    async def start(self, target_link: str | None, vlsreg: VlsRegistry | None = None) -> None:
        await self._setup_target(target_link)

        if vlsreg is None:
            return

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
        output_zip_path = "/tmp/target_packed.zip"

        if target_link:
            target_zip_bytes = await self._get_target_zip(target_link)
        else:
            target_zip_bytes = await asyncio.to_thread(self._pack_local_target, output_zip_path)

        retries = 0
        while not await self._iomanager.send_zip(target_zip_bytes):
            retries += 1
            if retries >= self.MAX_RETRIES:
                raise RuntimeError("failed to transfer target")
            await asyncio.sleep(5)

    @staticmethod
    def _pack_local_target(output_zip_path: str) -> bytes:
        source_root = "/tmp/target_app"
        entries = os.listdir(source_root)
        if len(entries) == 1 and os.path.isdir(os.path.join(source_root, entries[0])):
            source_root = os.path.join(source_root, entries[0])

        with ZipFile(output_zip_path, "w", ZIP_DEFLATED) as fzip:
            for root, _dirs, files in os.walk(source_root):
                for file in files:
                    file_path = os.path.join(root, file)
                    archname = os.path.relpath(file_path, source_root)
                    fzip.write(file_path, archname)
        with open(output_zip_path, "rb") as f:
            return f.read()


@router.post("/start")
async def start_supervisor(body: StartRequest):
    vlsreg = VlsRegistry(body.vlsreg) if body.vlsreg is not None else None
    async with httpx.AsyncClient(timeout=60.0) as client:
        if vlsreg is not None:
            await vls_manager_instance.set_registry(vlsreg.to_records())
        supervisor = Supervisor(client)
        await supervisor.start(body.target_link, vlsreg)
    return {"accepted": True}
