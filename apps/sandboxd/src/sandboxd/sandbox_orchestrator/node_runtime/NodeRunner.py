from __future__ import annotations

import shutil
import time
import uuid
from pathlib import Path
from typing import Any

import docker
import httpx
from docker.errors import ImageNotFound
from docker.models.containers import Container

from sandboxd.dataclasses.NodeManifest import NodeManifest


class NodeRunner:
    def __init__(self, docker_client: docker.DockerClient | None = None) -> None:
        self._client = docker_client

    def up(self, manifest: NodeManifest) -> Container:

        image_tag = manifest.image_tag

        # Build only if code with that hash has not yet appeared in the system.
        if not self._image_exists(image_tag):
            build_ctx = self._prepare_build_context(manifest.source_path)
            try:
                self._build_image(build_ctx, image_tag)
            finally:
                self._cleanup_build_context(build_ctx)

        container = self._run_container(manifest)

        try:
            self._wait_until_healthy(
                container=container,
                target_port=manifest.target_port,
                health_path=manifest.health_path,
                timeout=manifest.health_timeout,)
            return container
        except Exception:
            self.down(container)
            raise

    @staticmethod
    def down(container: Container) -> None:
        container.stop()
        container.remove()

    @staticmethod
    def _prepare_build_context(source_path: Path) -> Path:
        build_ctx = Path(f"/tmp/sandbox-build-{uuid.uuid4()}")
        shutil.copytree(source_path, build_ctx)
        return build_ctx

    def _image_exists(self, tag: str) -> bool:
        try:
            self._client.images.get(tag)
            return True
        except ImageNotFound:
            return False

    def _build_image(self, build_ctx: Path, tag: str) -> str:
        print(f" Начинаем сборку Docker-образа {tag}...")

        for chunk in self._client.api.build(path=str(build_ctx), tag=tag, rm=True, decode=True):
            if "stream" in chunk:
                print(chunk["stream"], end="")

            if "error" in chunk:
                raise RuntimeError(f"Docker build failed: {chunk['error']}")

        print(f"\n Образ {tag} успешно собран!")
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


    @staticmethod
    def _wait_until_healthy(container: Container, target_port: int, health_path: str, timeout: float) -> None:
        container.reload()
        host_port = container.attrs["NetworkSettings"]["Ports"][f"{target_port}/tcp"][0]["HostPort"]
        url = f"http://localhost:{host_port}{health_path}"

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if httpx.get(url, timeout=2.0).status_code == 200:
                    return

            except httpx.HTTPError:
                pass
            time.sleep(1.0)
        raise TimeoutError(f"service did not become healthy in time: {url}")

    @staticmethod
    def _cleanup_build_context(build_ctx: Path) -> None:
        shutil.rmtree(build_ctx, ignore_errors=True)