from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal


@dataclass(frozen=True)
class NodeManifest:
    """Description of a container that can be managed by sandboxd.

    `source_path` is the build-context root. `dockerfile` is relative to that
    root, unless Docker is given an externally prepared context.
    """

    source_path: Path
    target_port: int
    published_port: int | None = None

    image_prefix: str = "sandbox-runtime"
    env: dict[str, str] = field(default_factory=dict)

    health_path: str = "/"
    health_timeout: float = 60.0

    mem_limit: str = "1g"
    nano_cpus: int | None = None
    restart_policy: dict[str, str] = field(
        default_factory=lambda: {"Name": "unless-stopped"}
    ) # "no" = if target. otherwise "unless-stopped"

    internal_networks: tuple[str, ...] = field(default_factory=tuple)
    external_networks: tuple[str, ...] = field(default_factory=tuple)
    dockerfile: str = "Dockerfile"
    extra_options: dict[str, Any] = field(default_factory=dict)

    hash_excludes: tuple[str, ...] = field(default_factory=tuple)
    health_check_type: Literal["http", "tcp"] = "http"

    @property
    def image_tag(self) -> str:
        context_hash = self.calculate_context_hash(self.source_path, self.hash_excludes)
        dockerfile_hash = self._calculate_dockerfile_hash()
        return f"{self.image_prefix}:{context_hash}-{dockerfile_hash}"

    def _calculate_dockerfile_hash(self) -> str:
        dockerfile_path = self.source_path / self.dockerfile
        try:
            content = dockerfile_path.read_bytes()
        except OSError:
            # Keep the image tag deterministic even for manifests that are
            # intentionally resolved by Docker at build time.
            content = self.dockerfile.encode()
        return hashlib.sha256(content).hexdigest()[:6]

    @staticmethod
    def is_excluded(rel_path: PurePosixPath, excludes: tuple[str, ...]) -> bool:
        rel_str = rel_path.as_posix().lstrip("./")
        return any(
            rel_str == ex.rstrip("/")
            or rel_str.startswith(ex.rstrip("/") + "/")
            for ex in excludes
        )

    @staticmethod
    def calculate_context_hash(
        path: Path,
        excludes: tuple[str, ...] = (),
    ) -> str:
        hasher = hashlib.sha256()

        for root, dirnames, files in sorted(os.walk(path)):
            root_path = Path(root)
            rel_root = PurePosixPath(root_path.relative_to(path).as_posix())

            dirnames[:] = sorted(
                d
                for d in dirnames
                if not NodeManifest.is_excluded(rel_root / d, excludes)
            )

            for filename in sorted(files):
                file_path = root_path / filename
                rel_file = PurePosixPath(file_path.relative_to(path).as_posix())
                if NodeManifest.is_excluded(rel_file, excludes):
                    continue

                hasher.update(rel_file.as_posix().encode())
                try:
                    hasher.update(file_path.read_bytes())
                except OSError:
                    # Files changing while a context is hashed should not make
                    # the whole orchestrator crash merely because they vanished.
                    continue

        return hasher.hexdigest()[:12]

    @classmethod
    def create_disposable(
        cls,
        source_path: Path,
        target_port: int,
        **kwargs: Any,
    ) -> NodeManifest:
        defaults: dict[str, Any] = {
            "mem_limit": "512m",
            "nano_cpus": 1_000_000_000,
            "restart_policy": {"Name": "no"},
        }
        defaults.update(kwargs)
        return cls(source_path=source_path, target_port=target_port, **defaults)

    @classmethod
    def create_stable(
        cls,
        source_path: Path,
        target_port: int,
        **kwargs: Any,
    ) -> NodeManifest:
        defaults: dict[str, Any] = {
            "mem_limit": "1g",
            "nano_cpus": None,
            "restart_policy": {"Name": "unless-stopped"},
        }
        defaults.update(kwargs)
        return cls(source_path=source_path, target_port=target_port, **defaults)
