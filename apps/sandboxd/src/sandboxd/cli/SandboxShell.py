from __future__ import annotations

import cmd
import json
import os
import time
from pathlib import Path

import httpx

from sandboxd.dataclasses.NodeManifest import NodeManifest
from sandboxd.sandbox_orchestrator.SandboxOrchestrator import (
    SandboxOrchestrator,
)

import traceback

PROJECT_ROOT = Path("/app")

TARGET_DIR = (
    PROJECT_ROOT
    / "apps"
    / "sandboxd"
    / "tests"
    / "target"
    / "juice-shop-master"
)

AGENT_DIR = (
    PROJECT_ROOT
    / "apps"
    / "sandboxd"
    / "tests"
    / "pentest_stub"
)

COMMON_HASH_EXCLUDES = (
    "apps/sandboxd/tests/target",
    ".git",
    ".venv",
    "__pycache__",
)


TARGET_NETWORK = "sandbox-target-net"
CONTROL_NETWORK = "sandbox-control-net"
EGRESS_NETWORK = "sandbox-egress-net"





GATEWAY_LOGS_DIR = Path("/var/lib/sandboxd/gateway_logs")

AGENT_TARGET_PORT = 8080


def _target_manifest() -> NodeManifest:

    return NodeManifest.create_disposable(
        source_path=TARGET_DIR,
        target_port=3000,
        health_path="/rest/admin/application-version",
        internal_networks=(TARGET_NETWORK,),
    )



AGENT_DOCKERFILE = "apps/pentest_agent_test/Dockerfile"

def _agent_manifest() -> NodeManifest:
    return NodeManifest.create_disposable(
        source_path=PROJECT_ROOT,
        dockerfile=AGENT_DOCKERFILE,
        target_port=AGENT_TARGET_PORT,
        health_path="/health",
        internal_networks=(CONTROL_NETWORK, TARGET_NETWORK, EGRESS_NETWORK),
        external_networks=(EGRESS_NETWORK,),
        hash_excludes=COMMON_HASH_EXCLUDES,
        env={
            "SANDBOXD_GATEWAY_URL": "http://gateway:9000",
            "TARGET_URL": "http://target:3000",
            "OLLAMA_BASE_URL": os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11435"),
            "OLLAMA_MODEL": "gemma4-26b-think:latest"
        },
    )


GATEWAY_DOCKERFILE = "apps/sandboxd/tests/gateway/Dockerfile"

def _gateway_manifest() -> NodeManifest:
    GATEWAY_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    return NodeManifest.create_stable(
        source_path=PROJECT_ROOT,
        target_port=9000,
        health_path="/health",
        dockerfile=GATEWAY_DOCKERFILE,
        internal_networks=(CONTROL_NETWORK,),
        hash_excludes=COMMON_HASH_EXCLUDES,
        extra_options={"volumes": {str(GATEWAY_LOGS_DIR): {"bind": "/logs", "mode": "rw"}}},
    )


EGRESS_DOCKERFILE ="apps/sandboxd/tests/llm_egress/Dockerfile"

def _llm_egress_manifest() -> NodeManifest:
    """DEPRESSED, судя по всему"""
    return NodeManifest.create_stable(
        source_path=PROJECT_ROOT,
        dockerfile=EGRESS_DOCKERFILE,
        target_port=11434,
        health_check_type="tcp",
        health_path="",                    # не используется в tcp-режиме
        internal_networks=(EGRESS_NETWORK, CONTROL_NETWORK),
        external_networks=(EGRESS_NETWORK,),
        hash_excludes=COMMON_HASH_EXCLUDES,
        env={
            "UPSTREAM_HOST": os.getenv("LLM_UPSTREAM_HOST", "host.docker.internal"),
            "UPSTREAM_PORT": os.getenv("LLM_UPSTREAM_PORT", "11435"),
        },
        #extra_options={"extra_hosts": {"host.docker.internal": "172.25.0.1"}}
    )


class SandboxShell(cmd.Cmd):

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

    def __init__(self) -> None:
        super().__init__()
        self._orchestrator = (SandboxOrchestrator())
        self._started = False

    def _agent_base_url(self) -> str:
        instance = self._orchestrator.get("agent")
        ip = instance.ip(CONTROL_NETWORK)
        return f"http://{ip}:{AGENT_TARGET_PORT}"

    # --------------------------------------------------
    # lifecycle
    # --------------------------------------------------

    def do_up(self, _arg: str,) -> None:
        if self._started:
            print( "already up — use 'down' first")
            return

        print("bringing up target + gateway + agent...")

        try:
            self._orchestrator.start(
                target=_target_manifest(),
                gateway = _gateway_manifest(),
                agent = _agent_manifest(),
            )

            self._started = True

            print(
                "up.\n"
                "aliases: target, gateway, agent"
            )


        except Exception as error:
            print(f"up failed: {error}")
            traceback.print_exc()

            try:
                self._orchestrator.stop()
            except Exception:
                pass

    def do_down(
        self,
        _arg: str,
    ) -> None:

        if not self._started:
            print("nothing is up")
            return

        print("tearing down...")

        self._orchestrator.stop()

        self._started = False

        print("down.")

    def do_restart(
        self,
        arg: str,
    ) -> None:

        if not self._require_started():
            return

        alias = arg.strip()

        if not alias:
            print(
                "usage: restart <alias>"
            )
            return

        print(
            f"restarting '{alias}'..."
        )

        try:

            self._orchestrator.restart(
                alias
            )

            print(
                f"'{alias}' restarted."
            )

        except Exception as error:

            print(
                f"restart failed: {error}"
            )

    # --------------------------------------------------
    # agent control
    # --------------------------------------------------

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
            print(json.dumps(response.json(), indent=2))
        except (httpx.HTTPError, KeyError, RuntimeError) as error:
            print(f"failed to contact agent: {error}")

    # --------------------------------------------------
    # interaction
    # --------------------------------------------------

    def do_exec(
        self,
        arg: str,
    ) -> None:

        if not self._require_started():
            return

        parts = arg.split(
            maxsplit=1
        )

        if len(parts) < 2:
            print(
                "usage: exec "
                "<alias> <command...>"
            )
            return

        alias, command = parts

        try:

            output = (
                self._orchestrator
                .get(alias)
                .exec(command)
            )

            print(output)

        except KeyError:

            print(
                f"unknown alias '{alias}'. "
                "known: "
                f"{', '.join(self._orchestrator.aliases())}"
            )

        except Exception as error:

            print(
                f"exec failed: {error}"
            )

    def do_logs(
        self,
        arg: str,
    ) -> None:

        if not self._require_started():
            return

        parts = arg.split()

        if not parts:
            print(
                "usage: logs <alias> [tail]"
            )
            return

        alias = parts[0]

        tail = (
            int(parts[1])
            if len(parts) > 1
            else 100
        )

        try:

            print(
                self._orchestrator
                .get(alias)
                .logs(tail=tail)
            )

        except KeyError:

            print(
                f"unknown alias '{alias}'"
            )

    def do_status(
        self,
        _arg: str,
    ) -> None:

        if not self._require_started():
            return

        for alias in (
            "target",
            "gateway",
            "agent",
        ):

            try:

                instance = (
                    self._orchestrator
                    .get(alias)
                )

                state = (
                    "running"
                    if instance.is_running()
                    else "stopped"
                )

                print(
                    f"{alias}: {state}"
                )

            except KeyError:

                print(
                    f"{alias}: not spawned"
                )

        try:
            response = httpx.get(f"{self._agent_base_url()}/status", timeout=3)
            agent_state = response.json()
            print(f"agent activity: {agent_state['status']}")
        except Exception:
            pass

    # --------------------------------------------------
    # log watching
    # --------------------------------------------------

    def do_watch(
        self,
        _arg: str,
    ) -> None:
        """
        watch — читать новые gateway JSONL-логи в realtime.
        Ctrl-C для остановки.
        """

        if not self._require_started():
            return

        print(
            "watching gateway logs..."
        )

        positions: dict[Path, int] = {}

        try:

            while True:

                files = sorted(
                    GATEWAY_LOGS_DIR.glob(
                        "*.jsonl"
                    )
                )

                for path in files:

                    position = positions.get(
                        path,
                        0,
                    )

                    with path.open(
                        "r",
                        encoding="utf-8",
                    ) as file:

                        file.seek(position)

                        for line in file:

                            line = line.strip()

                            if not line:
                                continue

                            self._print_log(
                                path,
                                line,
                            )

                        positions[path] = (
                            file.tell()
                        )

                time.sleep(0.25)

        except KeyboardInterrupt:

            print("\nwatch stopped.")

    @staticmethod
    def _print_log(
        path: Path,
        raw: str,
    ) -> None:

        try:

            record = json.loads(raw)

            level = record.get(
                "level",
                "?",
            )

            event = record.get(
                "event",
                "?",
            )

            message = record.get(
                "message",
                "",
            )

            print(
                f"[{path.stem}] "
                f"{level.upper()} "
                f"{event}: "
                f"{message}"
            )

        except json.JSONDecodeError:

            print(
                f"[{path.stem}] {raw}"
            )

    # --------------------------------------------------
    # housekeeping
    # --------------------------------------------------

    def _require_started(
        self,
    ) -> bool:

        if not self._started:
            print(
                "nothing is up — run 'up' first"
            )
            return False

        return True

    def do_exit(
        self,
        _arg: str,
    ) -> bool:

        if self._started:
            self.do_down(_arg)

        print("bye.")

        return True

    do_quit = do_exit
    do_EOF = do_exit