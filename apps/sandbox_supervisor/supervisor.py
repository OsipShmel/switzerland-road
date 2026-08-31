from __future__ import annotations

import io
import os
import asyncio
import httpx
from zipfile import ZipFile, ZIP_DEFLATED
from fastapi import APIRouter
#import docker
#from docker.errors import NotFound

from vls import VlsRegistry
from VLSManager import vls_manager_instance
from sandbox_io_manager import SandboxIOManager

router = APIRouter(prefix="/api/supervisor", tags=["supervisor"])

class Supervisor:

    MAX_RETRIES = 5
    
    def __init__(self, client: httpx.AsyncClient, port: int) -> None:
        self.PORT = port
        self._vlsmanager = vls_manager_instance
        self._client = client
        self._iomanager = SandboxIOManager(self.PORT, self._client)
        
    async def start(self, target_link: str, vlsreg: VlsRegistry | None = None) -> None:
        await self._setup_target(target_link)
        
        if vlsreg is not None:
            print("starting vls transmission")
            retries = 0
            while not await self._iomanager.send_vls_registry(vlsreg):
                retries += 1
                print("retrying vls transmission..")
                if retries >= self.MAX_RETRIES:
                    print("failed to transfer vls")
                    return
                await asyncio.sleep(5)
            print("vls successfully sent")

    async def _setup_target(self, target_link: str | None = None) -> None:
        output_zip_path = "/tmp/target_packed.zip"
        target_zip_bytes = b""

        if target_link:
            target_zip_bytes = await self._get_target_zip(target_link)

            def extract():
                with ZipFile(io.BytesIO(target_zip_bytes)) as zip_ref:
                    zip_ref.extractall("/tmp/target_app")

            await asyncio.to_thread(extract)
            print("Target successfully extracted")
            
        else:
            print("starting target packing")

            def pack():
                with ZipFile(output_zip_path, 'w', ZIP_DEFLATED) as fzip:
                    for root, dirs, files in os.walk("/tmp/target_app"):
                        for file in files:
                            file_path = os.path.join(root, file)
                            archname = os.path.relpath(file_path, "/tmp")
                            fzip.write(file_path, archname)

            await asyncio.to_thread(pack)
            if os.path.exists(output_zip_path):
                with open(output_zip_path, "rb") as f:
                    target_zip_bytes = f.read()
            
        print("starting target transmission")
        retries = 0
        while not await self._iomanager.send_zip(target_zip_bytes):
            retries += 1
            print("retrying target transmission..")
            if retries >= self.MAX_RETRIES:
                print("failed to transfer target")
                return
            await asyncio.sleep(5)

        print("Target successfully sent")

@router.post("/start")
async def start_supervisor(
    target_link: str,
    vlsreg: VlsRegistry | None = None
):
    """Эндпоинт для запуска Supervisor с целевым приложением"""
    supervisor = Supervisor()
    result = await supervisor.start(target_link, vlsreg)
    return result


supervisor_instance = Supervisor()

