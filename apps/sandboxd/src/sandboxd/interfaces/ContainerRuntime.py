from typing import Protocol

from sandboxd.dataclasses.runtime_manifest import RuntimeManifest


class ContainerRuntime(Protocol):
    def up(self, manifest: RuntimeManifest) -> list[str]: ...
    def down(self, container_ids: list[str]) -> None: ...