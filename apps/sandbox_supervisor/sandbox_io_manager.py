from __future__ import annotations

import io
import zipfile
import httpx
from dataclasses import dataclass
from pydantic import TypeAdapter

from vls import VlsRegistry

class SandboxIOManager:

    def __init__(self, port: str) -> None:
        
        self._sandbox_target_url = f"http://sandboxd:{port}/target_zip"
        self._sandbox_vls_reristry_up = f"http://sandboxd:{port}/init_vls_regisry"
        self._sandbox_instruction_url = f"http://sandboxd:{port}/get_instruction"
                
    async def send_zip(self, zip_bytes: bytes, filename: str = "target.zip") -> bool:

        async with httpx.AsyncClient() as cli:
            files = {"file": (filename, zip_byte, "application/zip")}

            try:
                response = await cli.post(self._sandbox_url, files=files, timeout=60.0)
                return response.is_success
            
            except httpx.HTTPStatusError as e:
                print(f"HTTP error: {e.response.text}"}
                return False

            except httpx.RequestError as e:
                print(f"transport reqest error:  {e}"}
                return False

    async def receive_instruction(self) -> str:
        
        async with httpx.AsyncClient() as cli:
            
            try:    
                response = await cli.get(self._instruction_url, timeout = 30.0)
                response.raise_for_status()
                return response.text
            
            except httpx.HTTPStatusError as e:
                print(f"HTTP error: {e.response.text}"}
                return ""
            
            except httpx.RequestError as e:
                print(f"transport reqest error:  {e}"}
                return ""
    
    async def send_vls_regisrtry(self, vlsreg: VlsRegistry) -> bool:
        
        vls_adapter = TypeAdapter(vlsreg)
        vls_json = vls_adapter.dump_python(vlsreg, mode="json")
            
        async with httpx.AsyncClient() as cli:
            try:
                response = await cli.post(self._sandbox_vls_reristry_up, json=vls_json, timeout=60.0)
                return response.is_success
            
            except httpx.HTTPStatusError as e:
                print(f"HTTP error: {e.response.text}"}
                return False

            except httpx.RequestError as e:
                print(f"transport reqest error:  {e}"}
                return False
    
