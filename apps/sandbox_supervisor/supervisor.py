from __future__ import annotations

import io
import asyncio
import zipfile
import docker
from docker errors import NotFound

from VLSManager import VLSManager
from sandbox_io_manager import SandboxIOManager

class Supervisor:

    PORT = "1337"
    
    def __init__(self) -> None:

        self._vlsmanager = VLSManager()
        self._iomanager = SandboxIOManager(self.PORT)

    async def start(self, target_link: str, vlsreg: VlsRegistry) -> None:

        await self._setup_target(target_link)
        print("starting vls transmission")

        while not await self._iomanager.send_vls_regisry(vlsreg):
            print("retrying vls transmission..")
            await httpx.aio.sleep(5)

        print("vls successfully sent")
        self._insruct_sandbox("start")
        
    async def _setup_target(self, target_link: str) -> None:

        target_zip_bytes = await self._get_target_zip(target_link)
        print("starting target transmission")

        while not await self._iomanager.send_zip(target_zip_bytes):
            print("retrying target transmission..")
            await httpx.aio.sleep(5)

        print("Target successfully sent")

        with zipfile.ZipFile(io.BytesIO(target_zip_bytes)) as zip_ref:
            zip_ref.estractall("/tmp/target_app")

        print("Target successfully extracted")
    
            
    async def _get_target_zip(self, target_link: str) -> bytes:
        
        async with httpx.AsyncClient() as cli:
            resp = await cli.get(target_link)
            resp.raise_for_status()
            return resp.content

    async def _port_checking(self, port: int) -> None:
        self._current_task = await self._iomanager.receive_instruction()

        
    def _send_to_sandbnox(self, args: str) -> None:
        ...

    
    
