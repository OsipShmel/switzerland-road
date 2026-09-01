from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import aiofiles
from fastapi import APIRouter, HTTPException
from vls import VLS, VlsRegistry

router = APIRouter(prefix="/api/vls", tags=["vls"])


class VLSManager:
    def __init__(self) -> None:
        self._current_vlsreg = VlsRegistry()
        self._session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_dir = Path("/var/logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self.log_dir / f"session_{self._session_timestamp}_log.txt"

    async def print_by_id(self, vls_id: str) -> None:
        vls_item = self._current_vlsreg.get(vls_id)
        if vls_item is None:
            print(f"vls by id {vls_id} not found. check logs")
            return
        print(json.dumps(vls_item.model_dump(mode="json"), indent=4, ensure_ascii=False))

    async def get_by_id(self, vls_id: str) -> dict | None:
        vls_item = self._current_vlsreg.get(vls_id)
        return vls_item.model_dump(mode="json") if vls_item else None

    async def set_registry(self, records: list[dict]) -> None:
        self._current_vlsreg = VlsRegistry.from_records(records)
        await self._write_json({"type": "vls_registry", "records": self._current_vlsreg.to_records()})

    async def upsert(self, vls: VLS) -> bool:
        updated = self._current_vlsreg.upsert(vls)
        await self._write_json({"type": "vls_upsert", "vls": vls.model_dump(mode="json")})
        return updated

    async def append_log(self, payload: dict) -> None:
        context = str(payload.get("context") or "global")
        safe_context = Path(context).name.replace("..", "_") or "global"
        path = self.log_dir / f"{safe_context}.jsonl"
        async with aiofiles.open(path, mode="a", encoding="utf-8") as f:
            await f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    async def _write_json(self, payload: dict) -> None:
        async with aiofiles.open(self._log_file, mode="a", encoding="utf-8") as f:
            await f.write(json.dumps(payload, ensure_ascii=False) + "\n")


@router.get("/vls/{vls_id}")
async def get_vls_by_id(vls_id: str):
    result = await vls_manager_instance.get_by_id(vls_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"VLS with id {vls_id} not found")
    return result


vls_manager_instance = VLSManager()
