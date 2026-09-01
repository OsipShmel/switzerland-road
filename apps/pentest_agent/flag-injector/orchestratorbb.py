import os

from __future__ import annotations
from dataclasses import replace

import docker
from docker.errors import NotFound, APIError

from sandboxd.dataclasses.NodeManifest import NodeManifest
from sandboxd.sandbox_orchestrator.node_runtime.NodeRunner import NodeRunner
from sandboxd.sandbox_orchestrator.node_runtime.NodeInstance import NodeInstance

#1
from injector import FlagInjector
from config.settings import DO_INJECT


class SandboxOrchestrator:

    def __init__(self, docker_client: docker.DockerClient | None = None) -> None:
        self._client = docker_client or docker.from_env()
        self._runner = NodeRunner(self._client)
        self._network_name: str | None = None
        self._network_names: set[str] = set()
        self._instances: dict[str, NodeInstance] = {}
        self._manifests: dict[str, NodeManifest] = {}
        self._injected_flags = []  # для хранения внедрённых флагов

    def _inject_flags_into_project(self, project_path: str) -> list: #dytlhtybt akfujd
        if not DO_INJECT:
            print("Инжектор флагов отключён")
            return []
        
        print(f"Внедрение флагов в {project_path}")
        injector = FlagInjector(project_path)
        flags = injector.run()
        print(f"Внедрённые флаги: {flags}")
        return flags

    def start(self, **manifests: NodeManifest) -> None:
        required_networks: set[str] = set()

        for manifest in manifests.values():
            required_networks.update(manifest.networks)

        # Определяем путь к проекту из первого манифеста или из переменной окружения. Внедрение флагов
        project_path = os.environ.get("PROJECT_PATH", "./juice-shop")
        self._injected_flags = self._inject_flags_into_project(project_path)


        for alias in manifests:
            self._ensure_clean_container(alias)
        for name in required_networks:
            self._ensure_clean_network(name)

        for name in required_networks:
            self._client.networks.create(name, driver="bridge", internal=True)

        self._network_names = required_networks
        self._network_name = next(iter(self._network_names), None)

        for alias, manifest in manifests.items():
            if len(manifest.networks) != len(set(manifest.networks)):
                raise ValueError(
                    f"Node '{alias}' contains duplicate "
                    f"networks: {manifest.networks}"
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

    def get_injected_flags(self) -> list: #возвращает список внедренных флагов
        return self._injected_flags

    def stop(self) -> None:
        errors: list[str] = []

        for alias, instance in self._instances.items():
            try:
                self._runner.down(instance.raw_access)
            except Exception as error:
                errors.append(f"{alias}: {error}")

        if self._network_name:
            try:
                self._ensure_clean_network(self._network_name)
            except Exception as error:
                errors.append(f"network cleanup: {error}")
        self._network_name = None

        if errors:
            raise RuntimeError(
                "stop() completed with errors (some resources may still be leaking): "
                + "; ".join(errors)
            )

    def _spawn_node(self, alias: str, manifest: NodeManifest) -> NodeInstance:
        self._ensure_clean_container(alias)

        networks = tuple(dict.fromkeys(manifest.networks))
        print(f"starting node '{alias}' with networks={networks}")

        extra_options = {**manifest.extra_options, "name": alias}

        if networks:
            extra_options["network"] = networks[0]
        else:
            extra_options["network_mode"] = "none"

        attached = replace( manifest, extra_options=extra_options, networks=networks,)
        container = self._runner.up(attached)

        for network_name in manifest.networks[1:]:
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