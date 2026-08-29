from __future__ import annotations

import shutil
import socket
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import docker
import httpx
from docker.errors import ImageNotFound
from docker.models.containers import Container

from sandboxd.dataclasses.NodeManifest import NodeManifest
from sandboxd.sandbox_orchestrator.node_runtime.NodeInstance import NodeInstance
from sandboxd.sandbox_orchestrator.node_runtime.helpers import get_ip


class NodeRunner:
    def __init__(self, docker_client: docker.DockerClient | None = None) -> None:
        self._client = docker_client

    def up(self, manifest: NodeManifest) -> Container:

        image_tag = manifest.image_tag

        # Build only if code with that hash has not yet appeared in the system.
        if not self._image_exists(image_tag):
            build_ctx = self._prepare_build_context(manifest.source_path, manifest.hash_excludes)
            try:
                self._build_image(build_ctx, image_tag, manifest.dockerfile)
            finally:
                self._cleanup_build_context(build_ctx)

        container = self._run_container(manifest)
        healthcheck_network = self._healthcheck_network(manifest)
        try:
            self._wait_until_healthy(
                container=container,
                network = healthcheck_network,
                manifest=manifest,
            )
            return container
        except Exception:
            self.down(container)
            raise

    @staticmethod
    def down(container: Container) -> None:
        #container.stop()
        container.remove(force=True)

    @staticmethod
    def _healthcheck_network(manifest: NodeManifest) -> str:
        if not manifest.internal_networks:
            raise RuntimeError(
                f"node has no networks attached (network_mode=none); "
                f"HTTP healthcheck is not possible"
            )
        return manifest.internal_networks[0]

    @staticmethod
    def _prepare_build_context(source_path: Path, excludes: tuple[str, ...] = ()) -> Path:
        build_ctx = Path(f"/tmp/sandbox-build-{uuid.uuid4()}")

        if not excludes:
            shutil.copytree(source_path, build_ctx)
            return build_ctx

        def _ignore(dir_path: str, names: list[str]) -> set[str]:
            rel_dir = Path(dir_path).relative_to(source_path).as_posix()
            skipped = set()
            for name in names:
                rel = f"{rel_dir}/{name}" if rel_dir != "." else name
                rel_posix = PurePosixPath(rel)
                # TODO! he-he...
                if NodeManifest._is_excluded(rel_posix, excludes):
                    skipped.add(name)
            return skipped

        shutil.copytree(source_path, build_ctx, ignore=_ignore)
        return build_ctx

    def _image_exists(self, tag: str) -> bool:
        try:
            self._client.images.get(tag)
            return True
        except ImageNotFound:
            return False

    def _build_image(self, build_ctx: Path, tag: str, dockerfile: str,) -> str:
        # TODO! бля пора бы под логирование переделывать
        print(f" starting Docker image build: {build_ctx}, tag: {tag},")

        for chunk in self._client.api.build(
                path=str(build_ctx),
                tag=tag,
                rm=True,
                decode=True,
                dockerfile=dockerfile):
            if "stream" in chunk:
                print(chunk["stream"], end="")

            if "error" in chunk:
                raise RuntimeError(f"Docker build failed: {chunk['error']}")

        print(f"\n Image {tag} successfully built")
        return tag

    def _run_container(self, manifest: NodeManifest) -> Container:
        run_kwargs: dict[str, Any] = {
            "image": manifest.image_tag,
            "detach": True,
            "environment": manifest.env,
            "ports": {f"{manifest.target_port}/tcp": None},
            "restart_policy": manifest.restart_policy,
            "mem_limit": manifest.mem_limit,
        }

        if manifest.published_port is not None:
            run_kwargs["ports"] = {
                f"{manifest.target_port}/tcp": (
                    "0.0.0.0",
                    str(manifest.published_port),
                )
            }
        else:
             run_kwargs["ports"] = {
                 f"{manifest.target_port}/tcp": None
             }

        if manifest.nano_cpus is not None:
            run_kwargs["nano_cpus"] = manifest.nano_cpus

        run_kwargs.update(manifest.extra_options)

        return self._client.containers.run(**run_kwargs)

    #TODO!
    # При текущей конфигурации это кажется нормально, а вот че дальше хз
    # Че то в моменте плавит от конфигурирования сети здесь так что TODO!
    def _wait_until_healthy(
            self,
            container: Container,
            network: str,
            manifest: NodeManifest) -> None:

        deadline = time.monotonic() + manifest.health_timeout
        last_error: Exception | None = None
        url: str | None = None

        while time.monotonic() < deadline:
            if manifest.health_check_type == "tcp":
                try:
                    container.reload()
                    if container.status != "running":
                        raise RuntimeError(f"Container {container.name} is not running (status={container.status})")
                    ip_address = get_ip(container, manifest.internal_networks[0])
                    if self._tcp_probe(ip_address, manifest.target_port):
                        return
                    last_error = RuntimeError(f"TCP probe to {ip_address}:{manifest.target_port} failed")
                except Exception as error:
                    last_error = error
            else:
                try:
                    container.reload()
                    if container.status != "running":
                        raise RuntimeError(f"Container {container.name} is not running"
                                           f"(status={container.status})")

                    ip_address = get_ip(container, network)
                    url = f"http://{ip_address}:{manifest.target_port}{manifest.health_path}"
                    response = httpx.get(url, timeout=2.0,)
                    if response.status_code == 200:
                        return
                    last_error = RuntimeError(f"Healthcheck returned HTTP {response.status_code}")
                except Exception as error:
                    last_error = error

            time.sleep(1.0)

        error_suffix = ""

        if last_error is not None:
            error_suffix =  f". Last error: {last_error}"

        raise TimeoutError(
            f"Service did not become healthy in time for container {container.name}. URL: {url}"
            f"{error_suffix}"
        )

    @staticmethod
    def _tcp_probe(host: str, port: int, timeout: float = 1.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def _cleanup_build_context(build_ctx: Path) -> None:
        shutil.rmtree(build_ctx, ignore_errors=True)