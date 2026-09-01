from __future__ import annotations

from typing import Protocol

from docker.models.containers import Container

from sandboxd.dataclasses.NodeManifest import NodeManifest


class ContainerRuntime(Protocol):
    """Operations the orchestrator needs from a container runtime."""

    def up(self, manifest: NodeManifest) -> Container: ...

    def down(self, container: Container) -> None: ...

    def remove_container(self, name: str) -> None: ...

    def create_network(self, name: str, *, internal: bool) -> None: ...

    def remove_network(self, name: str) -> None: ...

    def connect(self, container: Container, network: str) -> None: ...
