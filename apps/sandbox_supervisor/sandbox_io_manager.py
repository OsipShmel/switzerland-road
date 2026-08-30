from __future__ import annotations

import io
import zipfile
import httpx
from pydantic import TypeAdapter

#from vls import VlsRegistry

class SandboxIOManager:

    def __init__(self, port: str, client: httpx.AsyncClient) -> None:
        self._client = client
        base_url = f"http://sandboxd:{port}"
        self._sandbox_target_url = f"{base_url}/target_zip"
        self._sandbox_vls_registry_up = f"{base_url}/init_vls_regisry"
        self._sandbox_instruction_url = f"{base_url}/get_instruction"
                
    async def send_zip(self, zip_bytes: bytes, filename: str = "target.zip") -> bool:
        files = {"file": (filename, zip_bytes, "application/zip")}
        try:
            response = await self._client.post(self._sandbox_target_url, files=files, timeout=60.0)
            return response.is_success  
        except httpx.HTTPStatusError as e:
            print(f"HTTP error: {e.response.text}")
            return False
        except httpx.RequestError as e:
            print(f"transport reqest error:  {e}")
            return False

    async def receive_instruction(self) -> str:
        try:    
            response = await self._client.get(self._sandbox_instruction_url, timeout = 30.0)
            response.raise_for_status()
            return response.text
        except httpx.HTTPStatusError as e:
            print(f"HTTP error: {e.response.text}")
            return ""
        except httpx.RequestError as e:
            print(f"transport reqest error:  {e}")
            return ""
        
    async def send_vls_registry(self, vlsreg: VlsRegistry) -> bool:
        vls_adapter = TypeAdapter(VlsRegistry)
        vls_json = vls_adapter.dump_python(vlsreg, mode="json")
        try:
            response = await self._client.post(self._sandbox_vls_registry_up, json=vls_json, timeout=60.0)
            return response.is_success
        except httpx.HTTPStatusError as e:
            print(f"HTTP error: {e.response.text}")
            return False
        except httpx.RequestError as e:
            print(f"transport reqest error:  {e}")
            return False
