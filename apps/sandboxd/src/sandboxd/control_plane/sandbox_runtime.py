from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from sandboxd.config.settings import COMMON_HASH_EXCLUDES, SandboxSettings
from sandboxd.control_plane.log_forwarder import SupervisorLogForwarder
from sandboxd.control_plane.supervisor_client import SupervisorClient
from sandboxd.dataclasses.NodeManifest import NodeManifest

if TYPE_CHECKING:
    from sandboxd.sandbox_orchestrator.SandboxOrchestrator import SandboxOrchestrator


class SandboxRuntime:
    """Automatic replacement for the old interactive SandboxShell lifecycle."""

    def __init__(
        self,
        settings: SandboxSettings,
        orchestrator: SandboxOrchestrator | None = None,
        supervisor: SupervisorClient | None = None,
    ) -> None:
        self._settings = settings
        self._supervisor = supervisor or SupervisorClient(
            settings.supervisor_url,
            settings.supervisor_timeout,
        )
        self._log_forwarder = SupervisorLogForwarder(self._supervisor)
        if orchestrator is None:
            from sandboxd.sandbox_orchestrator.SandboxOrchestrator import SandboxOrchestrator
            orchestrator = SandboxOrchestrator(on_log=self._log_forwarder.emit)
        self._orchestrator = orchestrator
        self._lock = asyncio.Lock()
        self._target_ready = self._target_exists()
        self._vls_ready = False

    def _target_exists(self) -> bool:
        target_dir = self._settings.target_dir
        target_dockerfile = target_dir / self._settings.target_dockerfile
        return target_dir.is_dir() and target_dockerfile.is_file()

    @property
    def started(self) -> bool:
        return self._orchestrator.started

    @property
    def target_ready(self) -> bool:
        return self._target_ready

    @property
    def vls_ready(self) -> bool:
        return self._vls_ready

    def mark_target_ready(self) -> None:
        self._target_ready = True

    def reset_readiness(self) -> None:
        self._target_ready = False
        self._vls_ready = False

    async def stop(self) -> None:
        if self.started:
            await asyncio.to_thread(self._orchestrator.stop)
        await self._log_forwarder.stop()


    def mark_vls_ready(self) -> None:
        self._vls_ready = True

    async def ensure_started(self) -> None:
        if self.started or not (self._target_ready and self._vls_ready):
            return

        async with self._lock:
            if self.started or not (self._target_ready and self._vls_ready):
                return
            await self._log_forwarder.start()
            await asyncio.to_thread(
                self._orchestrator.start,
                target=self._target_manifest(),
                gateway=self._gateway_manifest(),
                llm_egress=self._llm_egress_manifest(),
                agent=self._agent_manifest(),
            )
            await self._start_agent()

    async def _start_agent(self) -> None:
        instance = self._orchestrator.get("agent")
        url = f"http://{instance.ip(self._settings.control_network)}:{self._settings.agent_target_port}/start"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            # The containers are up; keep them available for inspection and let
            # the supervisor retry the command path later if needed.
            print(f"[sandboxd] agent start failed: {exc}")

    def _target_manifest(self) -> NodeManifest:
        return NodeManifest.create_disposable(
            source_path=self._settings.target_dir,
            target_port=3000,
            health_path="/rest/admin/application-version",
            internal_networks=(self._settings.target_network,),
        )

    def _gateway_manifest(self) -> NodeManifest:
        self._settings.gateway_logs_dir.mkdir(parents=True, exist_ok=True)
        return NodeManifest.create_stable(
            source_path=self._settings.project_root,
            target_port=self._settings.gateway_port,
            health_path="/health",
            dockerfile=self._settings.gateway_dockerfile,
            internal_networks=(self._settings.control_network,),
            hash_excludes=COMMON_HASH_EXCLUDES,
            extra_options={
                "volumes": {
                    str(self._settings.gateway_logs_dir): {
                        "bind": "/logs",
                        "mode": "rw",
                    },
                    str(self._settings.control_socket.parent): {
                        "bind": str(self._settings.control_socket.parent),
                        "mode": "rw",
                    },
                }
            },
            env={
                "SANDBOXD_CONTROL_SOCKET": str(self._settings.control_socket),
            },
        )

    def _agent_manifest(self) -> NodeManifest:
        return NodeManifest.create_disposable(
            source_path=self._settings.project_root,
            dockerfile=self._settings.agent_dockerfile,
            target_port=self._settings.agent_target_port,
            health_path="/health",
            internal_networks=(
                self._settings.control_network,
                self._settings.target_network,
                self._settings.egress_network,
            ),
            hash_excludes=COMMON_HASH_EXCLUDES,
            env={
                "SANDBOXD_GATEWAY_URL": f"http://gateway:{self._settings.gateway_port}",
                "TARGET_URL": "http://target:3000",
                "OPENAI_BASE_URL": self._settings.openai_base_url,
                "OPENAI_MODEL": self._settings.openai_model,
                "OPENAI_API_KEY": "egress-managed",
            },
        )

    def _llm_egress_manifest(self) -> NodeManifest:
        return NodeManifest.create_stable(
            source_path=self._settings.project_root,
            dockerfile=self._settings.llm_egress_dockerfile,
            target_port=self._settings.llm_egress_port,
            health_check_type="tcp",
            internal_networks=(self._settings.egress_network, self._settings.uplink_network),
            external_networks=(self._settings.uplink_network,),
            hash_excludes=COMMON_HASH_EXCLUDES,
            env={
                "OPENAI_UPSTREAM_HOST": self._settings.openai_upstream_host,
                "OPENAI_UPSTREAM_PORT": self._settings.openai_upstream_port,
                "OPENAI_UPSTREAM_PATH": self._settings.openai_upstream_path,
                "OPENAI_API_KEY": self._settings.openai_api_key,
            },
        )


class SandboxStateStore:
    def __init__(self, state_dir: Path) -> None:
        self._state_dir = state_dir
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self.registry_path = self._state_dir / "vls_registry.json"

    async def write_registry(self, records: list[dict]) -> None:
        tmp = self.registry_path.with_suffix(".tmp")
        payload = json.dumps(records, ensure_ascii=False, indent=2)
        await asyncio.to_thread(tmp.write_text, payload, encoding="utf-8")
        await asyncio.to_thread(tmp.replace, self.registry_path)

    async def read_registry(self) -> list[dict]:
        if not self.registry_path.exists():
            return []
        return await asyncio.to_thread(
            lambda: json.loads(self.registry_path.read_text(encoding="utf-8"))
        )
