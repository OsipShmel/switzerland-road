from __future__ import annotations

import cmd
import json
import time
import traceback
from pathlib import Path

import httpx

from sandboxd.config.settings import COMMON_HASH_EXCLUDES, settings
from sandboxd.dataclasses.NodeManifest import NodeManifest
from sandboxd.sandbox_orchestrator.SandboxOrchestrator import SandboxOrchestrator


class SandboxShell(cmd.Cmd):
    """Temporary human-facing control surface for sandboxd."""

    intro = (
        "sandboxd manual control shell.\n"
        "Commands:\n"
        "  up\n"
        "  start\n"
        "  status\n"
        "  watch\n"
        "  logs <alias> [tail]\n"
        "  exec <alias> <command>\n"
        "  restart <alias>\n"
        "  down\n"
    )
    prompt = "sandboxd> "

    def __init__(self, orchestrator: SandboxOrchestrator | None = None) -> None:
        super().__init__()
        self._orchestrator = orchestrator or SandboxOrchestrator()

    @property
    def _started(self) -> bool:
        return self._orchestrator.started

    def _agent_base_url(self) -> str:
        instance = self._orchestrator.get("agent")
        return f"http://{instance.ip(settings.control_network)}:{settings.agent_target_port}"

    # ------------------------------------------------------------------
    # Manifests
    # ------------------------------------------------------------------

    def _target_manifest(self) -> NodeManifest:
        return NodeManifest.create_disposable(
            source_path=settings.target_dir,
            target_port=3000,
            health_path="/rest/admin/application-version",
            internal_networks=(settings.target_network,),
        )

    def _agent_manifest(self) -> NodeManifest:
        return NodeManifest.create_disposable(
            source_path=settings.project_root,
            dockerfile=settings.agent_dockerfile,
            target_port=settings.agent_target_port,
            health_path="/health",
            internal_networks=(
                settings.control_network,
                settings.target_network,
                settings.egress_network,
            ),
            external_networks=(settings.egress_network,),
            hash_excludes=COMMON_HASH_EXCLUDES,
            env={
                "SANDBOXD_GATEWAY_URL": f"http://gateway:{settings.gateway_port}",
                "TARGET_URL": "http://target:3000",
                "OLLAMA_BASE_URL": settings.ollama_base_url,
                "OLLAMA_MODEL": settings.ollama_model,
            },
        )


    def _gateway_manifest(self) -> NodeManifest:
        settings.gateway_logs_dir.mkdir(parents=True, exist_ok=True)
        return NodeManifest.create_stable(
            source_path=settings.project_root,
            target_port=settings.gateway_port,
            health_path="/health",
            dockerfile=settings.gateway_dockerfile,
            internal_networks=(settings.control_network,),
            hash_excludes=COMMON_HASH_EXCLUDES,
            extra_options={
                "volumes": {
                    str(settings.gateway_logs_dir): {
                        "bind": "/logs",
                        "mode": "rw",
                    }
                }
            },
        )

    def _llm_egress_manifest(self) -> NodeManifest:
        """DEPRESSED"""
        return NodeManifest.create_stable(
            source_path=settings.project_root,
            dockerfile=settings.llm_egress_dockerfile,
            target_port=settings.llm_egress_port,
            health_check_type="tcp",
            internal_networks=(settings.egress_network, settings.control_network),
            external_networks=(settings.egress_network,),
            hash_excludes=COMMON_HASH_EXCLUDES,
            env={
                "UPSTREAM_HOST": settings.llm_upstream_host,
                "UPSTREAM_PORT": settings.llm_upstream_port,
            },
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def do_up(self, _arg: str) -> None:
        if self._started:
            print("already up — use 'down' first")
            return

        print("bringing up target + gateway + agent...")
        try:
            self._orchestrator.start(
                target=self._target_manifest(),
                gateway=self._gateway_manifest(),
                agent=self._agent_manifest(),
            )
        except Exception as error:
            print(f"up failed: {error}")
            traceback.print_exc()
            return

        print("up.\naliases: " + ", ".join(self._orchestrator.aliases()))

    def do_down(self, _arg: str) -> None:
        if not self._started:
            print("nothing is up")
            return

        print("tearing down...")
        try:
            self._orchestrator.stop()
        except Exception as error:
            print(f"down failed: {error}")
            return
        print("down.")

    def do_restart(self, arg: str) -> None:
        if not self._require_started():
            return

        alias = arg.strip()
        if not alias:
            print("usage: restart <alias>")
            return

        try:
            self._orchestrator.restart(alias)
        except Exception as error:
            print(f"restart failed: {error}")
            return
        print(f"'{alias}' restarted.")

    # ------------------------------------------------------------------
    # Agent control
    # ------------------------------------------------------------------

    def do_start(self, _arg: str) -> None:
        if not self._require_started():
            return
        try:
            response = httpx.post(f"{self._agent_base_url()}/start", timeout=10)
            print(response.status_code, response.text)
        except (httpx.HTTPError, KeyError, RuntimeError) as error:
            print(f"failed to contact agent: {error}")

    def do_agent_status(self, _arg: str) -> None:
        if not self._require_started():
            return
        try:
            response = httpx.get(f"{self._agent_base_url()}/status", timeout=5)
            response.raise_for_status()
            print(json.dumps(response.json(), indent=2))
        except (httpx.HTTPError, KeyError, RuntimeError, ValueError) as error:
            print(f"failed to contact agent: {error}")

    # ------------------------------------------------------------------
    # Inspection / interaction
    # ------------------------------------------------------------------

    def do_exec(self, arg: str) -> None:
        if not self._require_started():
            return

        parts = arg.split(maxsplit=1)
        if len(parts) < 2:
            print("usage: exec <alias> <command...>")
            return

        alias, command = parts
        try:
            print(self._orchestrator.get(alias).exec(command))
        except KeyError as error:
            print(str(error))
        except Exception as error:
            print(f"exec failed: {error}")

    def do_logs(self, arg: str) -> None:
        if not self._require_started():
            return

        parts = arg.split()
        if not parts:
            print("usage: logs <alias> [tail]")
            return

        try:
            tail = int(parts[1]) if len(parts) > 1 else 100
            if tail < 1:
                raise ValueError
        except ValueError:
            print("tail must be a positive integer")
            return

        try:
            print(self._orchestrator.get(parts[0]).logs(tail=tail))
        except KeyError as error:
            print(str(error))

    def do_status(self, _arg: str) -> None:
        if not self._require_started():
            return

        for alias in self._orchestrator.aliases():
            instance = self._orchestrator.get(alias)
            try:
                state = "running" if instance.is_running() else "stopped"
            except Exception as error:
                state = f"error: {error}"
            print(f"{alias}: {state}")

        try:
            response = httpx.get(f"{self._agent_base_url()}/status", timeout=3)
            response.raise_for_status()
            print(f"agent activity: {response.json().get('status', '?')}")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Log watching
    # ------------------------------------------------------------------

    def do_watch(self, _arg: str) -> None:
        if not self._require_started():
            return

        print("watching gateway logs...")
        positions: dict[Path, int] = {}
        try:
            while True:
                for path in sorted(settings.gateway_logs_dir.glob("*.jsonl")):
                    position = positions.get(path, 0)
                    with path.open("r", encoding="utf-8") as file:
                        file.seek(position)
                        for line in file:
                            self._print_log(path, line.strip())
                        positions[path] = file.tell()
                time.sleep(0.25)
        except KeyboardInterrupt:
            print("\nwatch stopped.")

    @staticmethod
    def _print_log(path: Path, raw: str) -> None:
        if not raw:
            return
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            print(f"[{path.stem}] {raw}")
            return

        print(
            f"[{path.stem}] {str(record.get('level', '?')).upper()} "
            f"{record.get('event', '?')}: {record.get('message', '')}"
        )

    def _require_started(self) -> bool:
        if not self._started:
            print("nothing is up — run 'up' first")
            return False
        return True

    def do_exit(self, _arg: str) -> bool:
        if self._started:
            self.do_down(_arg)
        print("bye.")
        return True

    do_quit = do_exit
    do_EOF = do_exit
