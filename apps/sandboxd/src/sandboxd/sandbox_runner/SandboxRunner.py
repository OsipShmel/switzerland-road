from __future__ import annotations

import shutil
import time
import uuid
from pathlib import Path

import docker
import httpx
from docker.models.containers import Container


class SandboxRunner:
    def __init__(self, docker_client: docker.DockerClient | None = None) -> None:
        self._client = docker_client or docker.from_env()

    def start(
        self,
        source_path: Path,
        target_port: int,
        env: dict[str, str] | None = None,
        health_path: str = "/",
        health_timeout: float = 60.0,
    ) -> Container:
        build_ctx = self._prepare_build_context(source_path)
        try:
            tag = self._build_image(build_ctx)
            container = self._run_target(tag, target_port, env or {})
            self._wait_until_healthy(container, target_port, health_path, health_timeout)
            return container
        finally:
            self._cleanup_build_context(build_ctx)

    @staticmethod
    def stop(container: Container) -> None:
        container.stop()
        container.remove()

    @staticmethod
    def _prepare_build_context(source_path: Path) -> Path:
        build_ctx = Path(f"/tmp/sandbox-build-{uuid.uuid4()}")
        shutil.copytree(source_path, build_ctx)
        return build_ctx

    def _build_image(self, build_ctx: Path) -> str:
        tag = f"sandbox-target:{uuid.uuid4().hex[:8]}"
        print(f" Начинаем сборку Docker-образа {tag}...")

        for chunk in self._client.api.build(path=str(build_ctx), tag=tag, rm=True, decode=True):
            if "stream" in chunk:
                print(chunk["stream"], end="")

            if "error" in chunk:
                raise RuntimeError(f"Docker build failed: {chunk['error']}")

        print(f"\n Образ {tag} успешно собран!")
        return tag

    def _run_target(self, tag: str, target_port: int, env: dict[str, str]) -> Container:
        return self._client.containers.run(
            tag,
            detach=True,
            environment=env,
            ports={f"{target_port}/tcp": None},
        )

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

            except (httpx.ConnectError, httpx.ReadError, httpx.HTTPError):
                pass
            time.sleep(1.0)
        raise TimeoutError(f"target did not become healthy in time: {url}")

    @staticmethod
    def _cleanup_build_context(build_ctx: Path) -> None:
        shutil.rmtree(build_ctx, ignore_errors=True)