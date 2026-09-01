from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from sandboxdapi.AgentInteraction import AgentLog
from vls import VLS


class SupervisorUnavailable(RuntimeError):
    """Supervisor could not be reached or rejected a control-plane event."""


@dataclass(frozen=True)
class SupervisorClient:
    base_url: str
    timeout: float = 10.0

    async def send_vls_update(self, vls: VLS) -> None:
        await self._post_json("/sandbox/receive-vls", vls.model_dump(mode="json"))

    async def send_log(self, log: AgentLog, *, context: str = "global") -> None:
        payload = log.model_dump(mode="json")
        payload["context"] = context
        await self._post_json("/sandbox/receive-log", payload)

    async def _post_json(self, path: str, payload: dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout) as client:
                response = await client.post(path, json=payload)
                if not response.is_success:
                    raise SupervisorUnavailable(
                        f"supervisor returned HTTP {response.status_code}: {response.text[:500]}"
                    )
                try:
                    body = response.json()
                except ValueError:
                    return
                if body.get("accepted") is False or body.get("is_success") is False:
                    raise SupervisorUnavailable(
                        f"supervisor rejected {path}: {body}"
                    )
        except SupervisorUnavailable:
            raise
        except httpx.HTTPError as exc:
            raise SupervisorUnavailable(f"supervisor request failed: {exc}") from exc
