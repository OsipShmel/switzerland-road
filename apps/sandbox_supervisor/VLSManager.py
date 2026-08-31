from __future__ import annotations

import asyncio
import json
from pathlib import Path
from datetime import datetime
import aiofiles
from pydantic import TypeAdapter
from fastapi import APIRouter, Request, BackgroundTasks

from vls import VlsRegistry, VLS 

router = APIRouter(prefix="/api/vls", tags=["vls"])

class VLSManager:
    
    def __init__(self) -> None:
        self._current_vlsreg: VlsRegistry | None = None
        self._vlsreg_adapter = TypeAdapter(VlsRegistry)
        self._vls_adapter = TypeAdapter(VLS)
        
        self._session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_dir = Path("/var/logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self.log_dir / f"session_{self._session_timestamp}_log.txt"
        
    async def print_by_id(self, vls_id: str) -> None:
        if not self._current_vlsreg:
            print("No VLS Registry loaded yet.")
            return
            
        vls_item = self._current_vlsreg.get(vls_id)
        if vls_item:
            vls_dict = self._vls_adapter.dump_python(vls_item, mode="json")
            normalised_vls = json.dumps(vls_dict, indent=4, ensure_ascii=False)
            print(normalised_vls)
        else:
            print(f"vls by id {vls_id} not found. check logs")

    async def get_by_id(self, vls_id: str) -> dict | None:
        if not self._current_vlsreg:
            return None
        
        vls_item = self._current_vlsreg.get(vls_id)
        if vls_item:
            vls_dict = self._vls_adapter.dump_python(vls_item, mode="json")
            return vls_dict
        return None
        
    async def _process_json(self, raw_resp: bytes) -> None:
        self._current_vlsreg = self._vlsreg_adapter.validate_json(raw_resp)
        cleaned_json = self._vlsreg_adapter.dump_python(self._current_vlsreg, mode="json")
        normalised_json = json.dumps(cleaned_json, indent=4, ensure_ascii=False)
        
        async with aiofiles.open(self._log_file, mode="a", encoding="utf-8") as f:
            await f.write(normalised_json + "\n")

@router.get("/vls/{vls_id}")
async def get_vls_by_id(vls_id: str):
    """Эндпоинт для получения VLS по ID"""
    result = await vls_manager_instance.get_by_id(vls_id)
    if result is None:
        return {"error": f"VLS with id {vls_id} not found"}, 404
    return result

vls_manager_instance = VLSManager()
