from __future__ import annotations
from dataclasses import replace

import docker
from docker.errors import NotFound

from sandboxd.dataclasses.NodeManifest import NodeManifest
from sandboxd.sandbox_orchestrator.node_runtime.NodeRunner import NodeRunner
from sandboxd.sandbox_orchestrator.node_runtime.NodeInstance import NodeInstance


class SandboxOrchestrator:

    def __init__(self, docker_client: docker.DockerClient | None = None) -> None:
        self._client = docker_client or docker.from_env()
        self._runner = NodeRunner(self._client)
        self._network_name: str | None = None
        self._instances: dict[str, NodeInstance] = {}
        self._manifests: dict[str, NodeManifest] = {}

    def start(self, network_name: str, **manifests: NodeManifest) -> None:
        self._network_name = network_name
        self._ensure_clean_network(network_name)
        self._client.networks.create(network_name, driver="bridge")

        for alias, manifest in manifests.items():
            self._manifests[alias] = manifest
            self._instances[alias] = self._spawn_node(alias, manifest)

    def restart(self, alias: str, manifest: NodeManifest | None = None) -> NodeInstance:
        if self._network_name is None:
            raise RuntimeError("orchestrator is not started — call start() first")

        effective_manifest = manifest or self._manifests.get(alias)
        if effective_manifest is None:
            raise ValueError(f"no manifest known for alias '{alias}', pass one explicitly")

        if alias in self._instances:
            self._runner.down(self._instances[alias].raw_access)

        self._manifests[alias] = effective_manifest
        self._instances[alias] = self._spawn_node(alias, effective_manifest)
        return self._instances[alias]

    def get(self, alias: str) -> NodeInstance:
        return self._instances[alias]

    def stop(self) -> None:
        for instance in self._instances.values():
            self._runner.down(instance.raw_access)
        self._instances.clear()
        self._manifests.clear()

        if self._network_name:
            self._ensure_clean_network(self._network_name)
        self._network_name = None

    def _spawn_node(self, alias: str, manifest: NodeManifest) -> NodeInstance:
        self._ensure_clean_container(alias)
        attached = replace(
            manifest,
            extra_options={**manifest.extra_options, "name": alias, "network": self._network_name},
        )
        container = self._runner.up(attached)
        return NodeInstance(alias, container)

    def _ensure_clean_network(self, name: str) -> None:
        try:
            self._client.networks.get(name).remove()
        except NotFound:
            pass

    def _ensure_clean_container(self, name: str) -> None:
        try:
            stale = self._client.containers.get(name)
            stale.stop()
            stale.remove()
        except NotFound:
            pass