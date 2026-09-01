from __future__ import annotations

import os
from dataclasses import replace
from typing import Callable

from sandboxd.dataclasses.NodeManifest import NodeManifest
from sandboxd.interfaces.ContainerRuntime import ContainerRuntime
from sandboxd.sandbox_orchestrator.node_runtime.NodeInstance import NodeInstance
from sandboxd.sandbox_orchestrator.node_runtime.NodeRunner import NodeRunner
from sandboxdapi.AgentInteraction import LogLevel

from sandboxd.flag_injector import DO_INJECT, FlagInjector


class SandboxOrchestrator:
    """Owns the desired sandbox topology and node lifecycle.

    Docker details live in the runtime implementation. The orchestrator only
    decides which resources belong to the current sandbox and in what order
    they must be created or removed.
    """

    def __init__(
        self,
        runtime: ContainerRuntime | None = None,
        on_log: Callable[..., None] | None = None,
    ) -> None:
        self._runtime = runtime or NodeRunner(on_log=on_log)
        self._on_log = on_log
        self._instances: dict[str, NodeInstance] = {}
        self._manifests: dict[str, NodeManifest] = {}
        self._network_names: set[str] = set()
        self._injected_flags = []  # для хранения внедрённых флагов

    @property
    def started(self) -> bool:
        return bool(self._instances)

    def aliases(self) -> tuple[str, ...]:
        return tuple(self._instances)

    def start(self, **manifests: NodeManifest) -> None:
        if not manifests:
            raise ValueError("at least one node manifest is required")
        if self.started:
            raise RuntimeError("orchestrator is already started — call stop() first")

        project_path = os.environ.get("PROJECT_PATH", "./juice-shop")
        self._injected_flags = self._inject_flags_into_project(project_path)

        self._validate_manifests(manifests)
        self._emit_log(
            level=LogLevel.INFO,
            event="sandbox.startup_started",
            message="Starting sandbox topology",
            metadata={"nodes": list(manifests)},
        )
        required_networks, network_internal = self._collect_networks(manifests)

        created_networks: set[str] = set()
        started_nodes: dict[str, NodeInstance] = {}

        try:
            for alias in manifests:
                self._ensure_clean_container(alias)

            for name in required_networks:
                self._ensure_clean_network(name)

            for name in sorted(required_networks):
                self._runtime.create_network(name, internal=network_internal[name])
                created_networks.add(name)

            for alias, manifest in manifests.items():
                started_nodes[alias] = self._spawn_node(alias, manifest)

            self._instances = started_nodes
            self._manifests = dict(manifests)
            self._network_names = created_networks
            self._emit_log(
                level=LogLevel.INFO,
                event="sandbox.started",
                message="Sandbox topology started",
                metadata={"nodes": list(self._instances)},
            )
        except Exception as exc:
            self._emit_log(
                level=LogLevel.ERROR,
                event="sandbox.startup_failed",
                message=str(exc),
                metadata={"started_nodes": list(started_nodes)},
            )
            for instance in reversed(tuple(started_nodes.values())):
                self._runtime.down(instance.raw_access)
            for name in reversed(tuple(created_networks)):
                self._runtime.remove_network(name)
            raise

    def restart(
        self,
        alias: str,
        manifest: NodeManifest | None = None,
    ) -> NodeInstance:
        self._require_started()

        effective_manifest = manifest or self._manifests.get(alias)
        if effective_manifest is None:
            raise ValueError(f"no manifest known for alias '{alias}', pass one explicitly")

        old = self._instances.get(alias)
        if old is not None:
            self._runtime.down(old.raw_access)

        try:
            instance = self._spawn_node(alias, effective_manifest)
        except Exception:
            if old is not None:
                self._instances.pop(alias, None)
            raise

        self._manifests[alias] = effective_manifest
        self._instances[alias] = instance
        return instance

    def get(self, alias: str) -> NodeInstance:
        try:
            return self._instances[alias]
        except KeyError as exc:
            raise KeyError(f"unknown node alias {alias!r}; known: {', '.join(self.aliases())}") from exc

    def stop(self) -> None:
        errors: list[str] = []

        for alias, instance in list(self._instances.items()):
            try:
                self._runtime.down(instance.raw_access)
            except Exception as error:
                errors.append(f"{alias}: {error}")

        for network_name in sorted(self._network_names):
            try:
                self._runtime.remove_network(network_name)
            except Exception as error:
                errors.append(f"network cleanup ({network_name}): {error}")

        if not errors:
            self._emit_log(
                level=LogLevel.INFO,
                event="sandbox.stopped",
                message="Sandbox topology stopped",
                metadata={},
            )
            self._instances.clear()
            self._manifests.clear()
            self._network_names.clear()

        if errors:
            raise RuntimeError(
                "stop() completed with errors (some resources may still be leaking): "
                + "; ".join(errors)
            )

    # ------------------------------------------------------------------
    # Topology
    # ------------------------------------------------------------------

    def _emit_log(self, *,
                  level: LogLevel, event: str,
                  message: str,
                  metadata: dict[str, object] | None = None) -> None:
        if self._on_log is None:
            return
        try:
            self._on_log(
                level=level,
                event=event,
                message=message,
                metadata=metadata or {},
            )
        except Exception as exc:
            print(f"[sandboxd] log callback failed: {exc}")

    @staticmethod
    def _validate_manifests(manifests: dict[str, NodeManifest]) -> None:
        aliases = [alias.strip() for alias in manifests]
        if any(not alias for alias in aliases):
            raise ValueError("node aliases must not be empty")
        if len(aliases) != len(set(aliases)):
            raise ValueError("node aliases must be unique")

        for alias, manifest in manifests.items():
            if len(manifest.internal_networks) != len(set(manifest.internal_networks)):
                raise ValueError(
                    f"node {alias!r} contains duplicate networks: "
                    f"{manifest.internal_networks}"
                )
    @staticmethod
    def _inject_flags_into_project(project_path: str) -> list:  # dytlhtybt akfujd
        if not DO_INJECT:
            print("Инжектор флагов отключён")
            return []

        print(f"Внедрение флагов в {project_path}")
        injector = FlagInjector(project_path)
        flags = injector.run()
        print(f"Внедрённые флаги: {flags}")
        return flags

    def get_injected_flags(self) -> list:  # возвращает список внедренных флагов
        return self._injected_flags

    @staticmethod
    def _collect_networks(
        manifests: dict[str, NodeManifest],
    ) -> tuple[set[str], dict[str, bool]]:
        required: set[str] = set()
        internal: dict[str, bool] = {}

        for alias, manifest in manifests.items():
            required.update(manifest.internal_networks)
            for name in manifest.internal_networks:
                wants_internal = name not in manifest.external_networks
                previous = internal.get(name)
                if previous is not None and previous != wants_internal:
                    raise ValueError(
                        f"network {name!r} is declared both internal and external "
                        f"across manifests (conflict introduced by node {alias!r})"
                    )
                internal[name] = wants_internal

        return required, internal

    def _spawn_node(self, alias: str, manifest: NodeManifest) -> NodeInstance:
        self._ensure_clean_container(alias)

        networks = tuple(dict.fromkeys(manifest.internal_networks))
        extra_options = {**manifest.extra_options, "name": alias}

        if networks:
            extra_options["network"] = networks[0]
        else:
            extra_options["network_mode"] = "none"

        attached = replace(
            manifest,
            internal_networks=networks,
            extra_options=extra_options,
        )

        print(f"[sandboxd] starting node {alias!r} with networks={networks}")
        container = self._runtime.up(attached)

        try:
            for network_name in networks[1:]:
                print(
                    f"[sandboxd] connecting node {alias!r} "
                    f"to network {network_name!r}"
                )
                self._runtime.connect(container, network_name)
        except Exception:
            self._runtime.down(container)
            raise

        return NodeInstance(alias, container)

    def _ensure_clean_network(self, name: str) -> None:
        self._runtime.remove_network(name)

    def _ensure_clean_container(self, name: str) -> None:
        # Node names are sandboxd-owned, so stale containers from a previous
        # interrupted run may safely be removed before creating a new one.
        self._runtime.remove_container(name)

    def _require_started(self) -> None:
        if not self.started:
            raise RuntimeError("orchestrator is not started — call start() first")
