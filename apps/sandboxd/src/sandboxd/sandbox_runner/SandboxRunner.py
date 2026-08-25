from __future__ import annotations

import hashlib
import os
import shutil
import time
import uuid
from pathlib import Path

import docker
import httpx
from docker.errors import ImageNotFound
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
        disposable: bool = False,  # TRUE - for targets, FALSE - for stable services
    ) -> Container:

        image_tag = f"sandbox-target:{self._calculate_dir_hash(source_path)}"

        # Build only if code with that hash has not yet appeared in the system.
        if not self._image_exists(image_tag):
            build_ctx = self._prepare_build_context(source_path)
            try:
                self._build_image(build_ctx, image_tag)
            finally:
                self._cleanup_build_context(build_ctx)

        container = self._run_target(image_tag, target_port, env or {}, disposable)

        try:
            self._wait_until_healthy(container, target_port, health_path, health_timeout)
            return container
        except Exception:
            self.stop(container)
            raise

    @staticmethod
    def stop(container: Container) -> None:
        container.stop()
        container.remove()

    @staticmethod
    def _calculate_dir_hash(path: Path) -> str:
        hasher = hashlib.md5()
        for root, _, files in sorted(os.walk(path)):
            for file in sorted(files):
                file_path = Path(root) / file
                hasher.update(str(file_path.relative_to(path)).encode())
                try:
                    hasher.update(file_path.read_bytes())
                except IOError:
                    pass
        return hasher.hexdigest()[:12]

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

    def _run_target(self, tag: str, target_port: int, env: dict[str, str], disposable: bool) -> Container:
        if disposable:
            # Стратегия для тестируемого таргета: жесткие лимиты, изоляция, без авто-перезапуска
            return self._client.containers.run(
                tag,
                detach=True,
                environment=env,
                ports={f"{target_port}/tcp": None},
                restart_policy={"Name": "no"},
                # read_only=True,  # TODO!
                # tmpfs={"/tmp": "rw,size=128m", "/run": "rw,size=16m"},  # TODO!
                mem_limit="512m",  # TODO!
                nano_cpus=1000000000, # TODO! – вот ну с этим блять как быть? вот как можно автоматически деплоить без адекватного понимания таргета?
            )
        else:
            return self._client.containers.run(
                tag,
                detach=True,
                environment=env,
                ports={f"{target_port}/tcp": None},
                restart_policy={"Name": "unless-stopped"},
                mem_limit="1g",  # TODO!
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
        raise TimeoutError(f"service did not become healthy in time: {url}")

    @staticmethod
    def _cleanup_build_context(build_ctx: Path) -> None:
        shutil.rmtree(build_ctx, ignore_errors=True)