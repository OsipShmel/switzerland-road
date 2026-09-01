from __future__ import annotations

import shutil
import socket
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Callable

import docker
import httpx
from docker.errors import APIError, ImageNotFound, NotFound
from docker.models.containers import Container

from sandboxd.dataclasses.NodeManifest import NodeManifest
from sandboxd.interfaces.ContainerRuntime import ContainerRuntime
from sandboxdapi.AgentInteraction import LogLevel
from sandboxd.sandbox_orchestrator.node_runtime.helpers import get_ip


class NodeRunner(ContainerRuntime):
    """Docker implementation of the sandbox container runtime."""

    def __init__(
        self,
        docker_client: docker.DockerClient | None = None,
        on_log: Callable[..., None] | None = None,
    ) -> None:
        self._client = docker_client or docker.from_env()
        self._on_log = on_log



    # ------------------------------------------------------------------
    # Container lifecycle
    # ------------------------------------------------------------------

    def up(self, manifest: NodeManifest) -> Container:
        # Build only if code with that hash has not yet appeared in the system.
        if not self._image_exists(manifest.image_tag):
            build_ctx = self._prepare_build_context(
                manifest.source_path,
                manifest.hash_excludes,
            )
            try:
                self._build_image(
                    build_ctx,
                    tag=manifest.image_tag,
                    dockerfile=manifest.dockerfile,
                )
            finally:
                self._cleanup_build_context(build_ctx)

        container = self._run_container(manifest)

        try:
            self._wait_until_healthy(container, manifest)
            return container
        except Exception:
            self.down(container)
            raise

    @staticmethod
    def down(container: Container) -> None:
        try:
            container.remove(force=True)
        except NotFound:
            pass

    def remove_container(self, name: str) -> None:
        try:
            container = self._client.containers.get(name)
        except NotFound:
            return
        self.down(container)

    # ------------------------------------------------------------------
    # Network lifecycle
    # ------------------------------------------------------------------

    def create_network(self, name: str, *, internal: bool) -> None:
        self._client.networks.create(name, driver="bridge", internal=internal)

    def remove_network(self, name: str) -> None:
        try:
            self._client.networks.get(name).remove()
        except NotFound:
            pass

    def connect(self, container: Container, network: str) -> None:
        self._client.networks.get(network).connect(container)

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _image_exists(self, tag: str) -> bool:
        try:
            self._client.images.get(tag)
            return True
        except ImageNotFound:
            return False

    @staticmethod
    def _prepare_build_context(
        source_path: Path,
        excludes: tuple[str, ...] = (),
    ) -> Path:
        build_ctx = Path(f"/tmp/sandbox-build-{uuid.uuid4().hex}")

        if not excludes:
            shutil.copytree(source_path, build_ctx)
            return build_ctx

        def ignore(dir_path: str, names: list[str]) -> set[str]:
            rel_dir = Path(dir_path).relative_to(source_path).as_posix()
            skipped: set[str] = set()
            for name in names:
                rel = f"{rel_dir}/{name}" if rel_dir != "." else name
                if NodeManifest.is_excluded(PurePosixPath(rel), excludes):
                    skipped.add(name)
            return skipped

        shutil.copytree(source_path, build_ctx, ignore=ignore)
        return build_ctx

    def _emit(
        self,
        *,
        level: LogLevel,
        event: str,
        message: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
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
            # Observability must not break container lifecycle.
            print(f"[sandboxd] log callback failed: {exc}")

    def _build_image(self, build_ctx: Path, *, tag: str, dockerfile: str) -> None:
        print(f"[sandboxd] building image {tag} from {build_ctx}")
        self._emit(
            level=LogLevel.INFO,
            event="sandbox.node_build_started",
            message=f"Building image {tag}",
            metadata={"node_image": tag, "dockerfile": dockerfile},
        )

        for chunk in self._client.api.build(
            path=str(build_ctx),
            tag=tag,
            rm=True,
            decode=True,
            dockerfile=dockerfile,
        ):
            if "stream" in chunk:
                stream = str(chunk["stream"])
                print(stream, end="")
                self._emit(
                    level=LogLevel.DEBUG,
                    event="sandbox.node_build_output",
                    message=stream.rstrip("\n"),
                    metadata={"node_image": tag, "dockerfile": dockerfile},
                )
            if "error" in chunk:
                error = str(chunk["error"])
                self._emit(
                    level=LogLevel.ERROR,
                    event="sandbox.node_build_failed",
                    message=error,
                    metadata={"node_image": tag, "dockerfile": dockerfile},
                )
                raise RuntimeError(f"Docker build failed: {error}")

        print(f"[sandboxd] image {tag} ready")
        self._emit(
            level=LogLevel.INFO,
            event="sandbox.node_build_finished",
            message=f"Image {tag} ready",
            metadata={"node_image": tag, "dockerfile": dockerfile},
        )



    # ------------------------------------------------------------------
    # Container configuration
    # ------------------------------------------------------------------

    def _run_container(self, manifest: NodeManifest) -> Container:
        ports: dict[str, Any]
        if manifest.published_port is not None:
            ports = {
                f"{manifest.target_port}/tcp": (
                    "0.0.0.0",
                    str(manifest.published_port),
                )
            }
        else:
            ports = {f"{manifest.target_port}/tcp": None}

        run_kwargs: dict[str, Any] = {
            "image": manifest.image_tag,
            "detach": True,
            "environment": manifest.env,
            "ports": ports,
            "restart_policy": manifest.restart_policy,
            "mem_limit": manifest.mem_limit,
        }

        if manifest.nano_cpus is not None:
            run_kwargs["nano_cpus"] = manifest.nano_cpus

        run_kwargs.update(manifest.extra_options)
        container = self._client.containers.run(**run_kwargs)
        self._emit(
            level=LogLevel.INFO,
            event="sandbox.node_started",
            message=f"Container {manifest.image_tag} started",
            metadata={"container_id": container.id, "image": manifest.image_tag},
        )
        return container

    # ------------------------------------------------------------------
    # Health checks
    # ------------------------------------------------------------------

    def _wait_until_healthy(
        self,
        container: Container,
        manifest: NodeManifest,
    ) -> None:
        if not manifest.internal_networks:
            raise RuntimeError(
                f"node '{container.name}' has no networks attached; "
                "network healthcheck is impossible"
            )
        # еще и логику выбора сети для хэлф чека занес сюда.
        # чат гпт реально называют самой мощной моделью современности?
        # это че за конченный рефакторинг такой?
        network = manifest.internal_networks[0]
        deadline = time.monotonic() + manifest.health_timeout
        self._emit(
            level=LogLevel.INFO,
            event="sandbox.node_healthcheck_started",
            message=f"Waiting for {container.name} to become healthy",
            metadata={
                "node": container.name,
                "health_check_type": manifest.health_check_type,
                "timeout_seconds": manifest.health_timeout,
            },
        )
        last_error: Exception | None = None
        last_url: str | None = None

        with httpx.Client(timeout=2.0) as client:
            while time.monotonic() < deadline:
                try:
                    container.reload()
                    if container.status != "running":
                        raise RuntimeError(
                            f"container {container.name!r} is not running "
                            f"(status={container.status})"
                        )

                    ip_address = get_ip(container, network)

                    if manifest.health_check_type == "tcp":
                        if self._tcp_probe(ip_address, manifest.target_port):
                            self._emit(
                                level=LogLevel.INFO,
                                event="sandbox.node_healthy",
                                message=f"{container.name} passed TCP healthcheck",
                                metadata={"node": container.name, "ip": ip_address, "port": manifest.target_port},
                            )
                            return
                        raise RuntimeError(
                            f"TCP probe to {ip_address}:{manifest.target_port} failed"
                        )

                    # спасибо чату гпт за рефакторинг, ай си – отличная работа. ничего не поменялось
                    last_url = (
                        f"http://{ip_address}:{manifest.target_port}"
                        f"{manifest.health_path}"
                    )
                    response = client.get(last_url)
                    if response.status_code == 200:
                        self._emit(
                            level=LogLevel.INFO,
                            event="sandbox.node_healthy",
                            message=f"{container.name} passed HTTP healthcheck",
                            metadata={"node": container.name, "url": last_url},
                        )
                        return
                    raise RuntimeError(
                        f"healthcheck returned HTTP {response.status_code}"
                    )
                except (OSError, APIError, httpx.HTTPError, RuntimeError) as error:
                    last_error = error

                time.sleep(1.0)

        suffix = f". Last error: {last_error}" if last_error else ""
        message = (
            f"service did not become healthy in time for container "
            f"{container.name}. URL: {last_url}{suffix}"
        )
        self._emit(
            level=LogLevel.ERROR,
            event="sandbox.node_healthcheck_failed",
            message=message,
            metadata={"node": container.name, "url": last_url},
        )
        raise TimeoutError(message)

    @staticmethod
    def _tcp_probe(host: str, port: int, timeout: float = 1.0, ) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False


    @staticmethod
    def _cleanup_build_context(build_ctx: Path) -> None:
        shutil.rmtree(build_ctx, ignore_errors=True)


