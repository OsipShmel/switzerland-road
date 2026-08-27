from __future__ import annotations

import cmd
from pathlib import Path

from sandboxd.dataclasses.NodeManifest import NodeManifest
from sandboxd.sandbox_orchestrator.SandboxOrchestrator import SandboxOrchestrator








NETWORK_NAME = "sandbox-shell-net"
TARGET_DIR = Path("/app/apps/sandboxd/tests/target/juice-shop-master")
AGENT_DIR = Path("/app/apps/sandboxd/tests/pentest_stub")


def _target_manifest() -> NodeManifest:
    return NodeManifest.create_disposable(
        source_path=TARGET_DIR,
        target_port=3000,
        health_path="/rest/admin/application-version",
        published_port=18001
    )


def _agent_manifest() -> NodeManifest:
    return NodeManifest.create_disposable(
        source_path=AGENT_DIR,
        target_port=8080,
    )


class SandboxShell(cmd.Cmd):
    intro = (
        "sandboxd manual control shell. "
        "Type 'help' or '?' for commands, 'up' to bring target+agent online.\n"
    )
    prompt = "sandboxd> "

    def __init__(self) -> None:
        super().__init__()
        self._orchestrator = SandboxOrchestrator()
        self._started = False

    # --- lifecycle -------------------------------------------------

    def do_up(self, _arg: str) -> None:
        """up — поднять target и agent в общей сети (создаёт сеть, если её ещё нет)."""
        if self._started:
            print("already up — use 'down' first if you want a clean restart")
            return
        print("bringing up target + agent...")
        self._orchestrator.start(
            NETWORK_NAME, target=_target_manifest(), agent=_agent_manifest()
        )
        self._started = True
        print("up. aliases: target, agent")

    def do_down(self, _arg: str) -> None:
        """down — погасить все ноды и удалить сеть."""
        if not self._started:
            print("nothing is up")
            return
        print("tearing down...")
        self._orchestrator.stop()
        self._started = False
        print("down.")

    def do_restart(self, arg: str) -> None:
        """restart <alias> — пересоздать один узел (target|agent), сеть и соседей не трогает."""
        alias = arg.strip()
        if not self._require_started():
            return
        if not alias:
            print("usage: restart <alias>")
            return
        print(f"restarting '{alias}'...")
        try:
            self._orchestrator.restart(alias)
            print(f"'{alias}' restarted.")
        except Exception as e:
            print(f"restart failed: {e}")

    # --- interaction -------------------------------------------------

    def do_exec(self, arg: str) -> None:
        """exec <alias> <command...> — выполнить команду внутри указанного узла."""
        if not self._require_started():
            return
        parts = arg.split(maxsplit=1)
        if len(parts) < 2:
            print("usage: exec <alias> <command...>")
            return
        alias, command = parts
        try:
            output = self._orchestrator.get(alias).exec(command)
            print(output)
        except KeyError:
            print(f"unknown alias '{alias}'. known: target, agent")
        except Exception as e:
            print(f"exec failed: {e}")

    def do_logs(self, arg: str) -> None:
        """logs <alias> [tail] — показать последние строки логов узла (по умолчанию 100)."""
        if not self._require_started():
            return
        parts = arg.split()
        if not parts:
            print("usage: logs <alias> [tail]")
            return
        alias = parts[0]
        tail = int(parts[1]) if len(parts) > 1 else 100
        try:
            print(self._orchestrator.get(alias).logs(tail=tail))
        except KeyError:
            print(f"unknown alias '{alias}'. known: target, agent")

    def do_status(self, _arg: str) -> None:
        """status — показать состояние всех поднятых узлов."""
        if not self._require_started():
            return
        for alias in ("target", "agent"):
            try:
                instance = self._orchestrator.get(alias)
                state = "running" if instance.is_running() else "stopped"
                print(f"{alias}: {state}")
            except KeyError:
                print(f"{alias}: not spawned")

    # --- housekeeping -------------------------------------------------

    def _require_started(self) -> bool:
        if not self._started:
            print("nothing is up — run 'up' first")
            return False
        return True

    def do_exit(self, _arg: str) -> bool:
        """exit — погасить всё (если поднято) и выйти из shell."""
        if self._started:
            self.do_down(_arg)
        print("bye.")
        return True

    do_quit = do_exit
    do_EOF = do_exit  # Ctrl-D