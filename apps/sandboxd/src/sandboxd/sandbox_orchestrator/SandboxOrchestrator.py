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
        self._network_names: set[str] = set()
        self._instances: dict[str, NodeInstance] = {}
        self._manifests: dict[str, NodeManifest] = {}

    def start(self, **manifests: NodeManifest) -> None:
        required_networks: set[str] = set()
        network_internal: dict[str, bool] = {}

        for alias, manifest in manifests.items():
            required_networks.update(manifest.internal_networks)
            for name in manifest.internal_networks:
                wants_internal = name not in manifest.external_networks
                if name in network_internal and network_internal[name] != wants_internal:
                    raise ValueError(
                        f"network '{name}' declared both internal and external "
                        f"across manifests (conflict introduced by node '{alias}')"
                    )
                network_internal[name] = wants_internal

        for alias in manifests:
            self._ensure_clean_container(alias)
        for name in required_networks:
            self._ensure_clean_network(name)

        for name in required_networks:
            self._client.networks.create(name, driver="bridge", internal=network_internal[name])

        self._network_names = required_networks
        self._network_name = next(iter(self._network_names), None)

        for alias, manifest in manifests.items():
            if len(manifest.internal_networks) != len(set(manifest.internal_networks)):
                raise ValueError(
                    f"Node '{alias}' contains duplicate "
                    f"networks: {manifest.internal_networks}"
                )
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
        errors: list[str] = []

        for alias, instance in self._instances.items():
            try:
                self._runner.down(instance.raw_access)
            except Exception as error:
                errors.append(f"{alias}: {error}")

        for network_name in self._network_names:
            try:
                self._ensure_clean_network(network_name)
            except Exception as error:
                errors.append(f"network cleanup ({network_name}): {error}")

        self._network_names = set()
        self._network_name = None

        if errors:
            raise RuntimeError(
                "stop() completed with errors (some resources may still be leaking): "
                + "; ".join(errors)
            )

    def _spawn_node(self, alias: str, manifest: NodeManifest) -> NodeInstance:
        self._ensure_clean_container(alias)

        networks = tuple(dict.fromkeys(manifest.internal_networks))
        print(f"starting node '{alias}' with networks={networks}")

        extra_options = {**manifest.extra_options, "name": alias}

        if networks:
            extra_options["network"] = networks[0]
        else:
            extra_options["network_mode"] = "none"

        attached = replace( manifest, extra_options=extra_options, internal_networks=networks,)
        container = self._runner.up(attached)

        for network_name in manifest.internal_networks[1:]:
            print(f"connecting node '{alias}' to network '{network_name}'")
            network = self._client.networks.get(network_name)
            network.connect(container)
        return NodeInstance(alias, container)

    def _ensure_clean_network(self, name: str) -> None:
        try:
            self._client.networks.get(name).remove()
        except NotFound:
            pass

    def _ensure_clean_container(self, name: str) -> None:
        try:
            stale = self._client.containers.get(name)
        except NotFound:
            return

        try:
            stale.remove(force=True)
        except NotFound:
            pass