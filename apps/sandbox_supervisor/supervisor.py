from __future__ import annotations

import io
import os
import asyncio
import httpx
import aiofiles.os
from zipfile import ZipFile, ZIP_DEFLATED
from fastapi import FastAPI
#import docker
#from docker.errors import NotFound
from pydantic import TypeAdapter

#from vls import VlsRegistry
#from VLSManager import VLSManager
from sandbox_io_manager import SandboxIOManager

app = FastAPI()

class Supervisor:

    PORT = "1337"
    MAX_RETRIES = 5
    
    def __init__(self, client = httpx.AsyncClient) -> None:
        self._vlsmanager = VLSManager()
        self._client = client
        self._iomanager = SandboxIOManager(self.PORT, self._client)
        self._current_task = ""
        
    async def start(self, target_link: str, vlsreg: VlsRegistry) -> None:
        await self._setup_target(target_link)
        print("starting vls transmission")
        retries = 0
        while not await self._iomanager.send_vls_registry(vlsreg):
            retries += 1
            print("retrying vls transmission..")
            if retries >= self.MAX_RETRIES:
                print("failed to transfer")
                return
            await asyncio.sleep(5)
        print("vls successfully sent")
        self._insruct_sandbox("start")

    async def _setup_target(self, target_link: str = "") -> None:
        if target_link is not None:
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
                            archname = os.path.relpath(file_path, os.path.dirname("/tmp"))
                            fzip.write(file_path, archname)

            await asyncio.to_thread(pack)
            
        print("starting target transmission")
        retries = 0
        while not await self._iomanager.send_zip(target_zip_bytes):
            retries += 1

            print("retrying target transmission..")
            if retries >= self.MAX_RETIES:
                print("failed to transfer")
                return
            await asyncio.sleep(5)

        print("Target successfully sent")
        return None

    async def _get_target_zip(self, target_link: str) -> bytes:
        resp = await self._client.get(target_link)
        resp.raise_for_status()
        return resp.content

    async def _task_check(self, port: int) -> None:
        self._current_task = await self._iomanager.receive_instruction()
        return None

@app.post("/log-vls")    
async def receive_vls_registry(vlsreg: VlsRegistry) -> VlsRegistry | None:
    vls_adapter = TypeAdapter(VlsRegistry)
    try:
        return vls_adapter.validate_python(vlsreg.json())
    except httpx.HTTPStatusError as e:
        print(f"HTTP error: {e.response.text}")
        return None
    except httpx.RequestError as e:
        print(f"transport reqest error:  {e}")
        return None
    
    
        
