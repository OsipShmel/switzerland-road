from __future__ import annotations

import io
import zipfile
import httpx
from vls import VlsRegistry
from VLSManager import vls_manager_instance

class SandboxIOManager:

    def __init__(self, port: str, client: httpx.AsyncClient) -> None:
        self._client = client
        self._vlsmanager = vls_manager_instance
        base_url = f"http://sandboxd:{port}"
        self._sandbox_target_url = f"{base_url}/target_zip"
        self._sandbox_vls_registry_up = f"{base_url}/init_vls_registry"
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
            print(f"transport request error: {e}")
            return False
        
    async def send_vls_registry(self, vlsreg: VlsRegistry) -> bool:
        vls_json = self._vlsmanager._vlsreg_adapter.dump_python(vlsreg, mode="json")
        try:
            response = await self._client.post(self._sandbox_vls_registry_up, json=vls_json, timeout=60.0)
            return response.is_success
        except httpx.HTTPStatusError as e:
            print(f"HTTP error: {e.response.text}")
            return False
        except httpx.RequestError as e:
            print(f"transport request error: {e}")
            return False
