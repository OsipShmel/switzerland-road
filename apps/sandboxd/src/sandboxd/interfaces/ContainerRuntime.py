from typing import Protocol

from sandboxd.dataclasses.NodeManifest import NodeManifest


class ContainerRuntime(Protocol):
    def up(self, manifest: NodeManifest) -> list[str]: ...
    def down(self, container_ids: list[str]) -> None: ...