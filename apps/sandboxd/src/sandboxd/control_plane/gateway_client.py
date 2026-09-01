from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from sandboxdapi.AgentInteraction import AgentLog
from vls import VLS


@dataclass(frozen=True)
class SandboxdControlClient:
    socket_path: str
    timeout: float = 10.0

    async def get_vls_registry(self) -> list[dict[str, Any]]:
        return await self._request_json("GET", "/internal/vls-registry")

    async def sync_vls(self, vls: VLS) -> None:
        await self._request_json("POST", "/internal/vls-updated", json=vls.model_dump(mode="json"))

    async def publish_log(self, log: AgentLog, *, context: str) -> None:
        payload = log.model_dump(mode="json")
        payload["context"] = context
        await self._request_json("POST", "/internal/log", json=payload)

    async def _request_json(self, method: str, path: str, **kwargs: Any) -> Any:
        transport = httpx.AsyncHTTPTransport(uds=self.socket_path)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://sandboxd", timeout=self.timeout) as client:
                response = await client.request(method, path, **kwargs)
                response.raise_for_status()
                return response.json()
        finally:
            await transport.aclose()
