from __future__ import annotations
from docker.models.containers import Container

from sandboxd.sandbox_orchestrator.node_runtime.helpers import get_ip


class NodeInstance:
    """A stable sandboxd handle over one Docker container."""

    def __init__(self, alias: str, container: Container) -> None:
        self.alias = alias
        self._container = container

    @property
    def id(self) -> str:
        return self._container.id

    def exec(self, command: str) -> str:
        _, output = self._container.exec_run(command)
        return output.decode(errors="replace").strip()

    def logs(self, tail: int = 100) -> str:
        return self._container.logs(tail=tail).decode(errors="replace")

    def is_running(self) -> bool:
        self._container.reload()
        return self._container.status == "running"

    def ip(self, network: str) -> str:
        return get_ip(self._container, network)

    @property
    def raw_access(self) -> Container:
        """Legacy Docker escape hatch; prefer the NodeInstance API above."""
        return self._container
