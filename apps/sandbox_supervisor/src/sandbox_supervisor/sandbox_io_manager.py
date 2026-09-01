from __future__ import annotations

import httpx
from fastapi import APIRouter, Request
from vls import VlsRegistry, VLS

from .VLSManager import vls_manager_instance

router = APIRouter(prefix="/sandbox", tags=["sandbox-io"])


class SandboxIOManager:
    def __init__(self, base_url: str, client: httpx.AsyncClient) -> None:
        self._client = client
        self._vlsmanager = vls_manager_instance
        base_url = base_url.rstrip("/")
        self._sandbox_target_url = f"{base_url}/target_zip"
        self._sandbox_vls_registry_url = f"{base_url}/init_vls_registry"

    async def send_zip(self, zip_bytes: bytes, filename: str = "target.zip") -> bool:
        try:
            response = await self._client.post(
                self._sandbox_target_url,
                content=zip_bytes,
                headers={
                    "Content-Type": "application/zip",
                    "X-Filename": filename,
                },
                timeout=60.0,
            )
            return response.is_success
        except httpx.HTTPError as exc:
            print(f"sandboxd target transmission failed: {exc}")
            return False

    async def send_vls_registry(self, vlsreg: VlsRegistry) -> bool:
        try:
            response = await self._client.post(
                self._sandbox_vls_registry_url,
                json=vlsreg.to_records(),
                timeout=60.0,
            )
            return response.is_success
        except httpx.HTTPError as exc:
            print(f"sandboxd VLS transmission failed: {exc}")
            return False


@router.post("/receive-vls")
async def receive_vls_from_sandbox(request: Request) -> dict[str, bool]:
    payload = await request.json()
    try:
        vls = VLS.model_validate(payload)
        updated = await vls_manager_instance.upsert(vls)
        # обновление относится к единственной активной проверке mvp
        from .security_gate import security_gate_service

        await security_gate_service.handle_sandbox_vls(vls)
    except Exception as exc:
        return {"accepted": False, "error": str(exc)}
    return {"accepted": updated}


@router.post("/receive-log")
async def receive_log_from_sandbox(request: Request) -> dict[str, bool]:
    payload = await request.json()
    await vls_manager_instance.append_log(payload)
    # supervisor переводит служебный лог в событие для фронта
    from .security_gate import security_gate_service

    await security_gate_service.handle_sandbox_log(payload)
    return {"accepted": True}
