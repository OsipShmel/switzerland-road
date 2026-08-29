import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal


@dataclass(frozen=True)
class NodeManifest:
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
    ) # "no" if for target, else unless-stopped

    internal_networks: tuple[str, ...] = field(default_factory=tuple)
    external_networks: tuple[str, ...] = field(default_factory=tuple)
    dockerfile: str = "Dockerfile"
    extra_options: dict[str, Any] = field(default_factory=dict)

    hash_excludes: tuple[str, ...] = field(default_factory=tuple)
    #TODO! вот это внезапный момент, надо поправить везде где надо
    health_check_type: Literal["http", "tcp"] = "http"
    @property
    def image_tag(self) -> str:
        dir_hash = self._calculate_dir_hash(self.source_path, self.hash_excludes)
        dockerfile_hash = hashlib.md5(self.dockerfile.encode()).hexdigest()[:5]
        return f"{self.image_prefix}:{dir_hash}-{dockerfile_hash}"


    @staticmethod
    def _is_excluded(rel_path: PurePosixPath, excludes: tuple[str, ...]) -> bool:
        rel_str = rel_path.as_posix()
        return any(
            rel_str == ex or rel_str.startswith(ex.rstrip("/") + "/")
            for ex in excludes
        )

    # WARN!
    # Данный подход конфликтует с параллельным запуском нескольких таргетов от одного sandboxd.
    # Сейчас не проблема, стоит помнить
    @staticmethod
    def _calculate_dir_hash(path: Path, excludes: tuple[str, ...] = ()) -> str:
        hasher = hashlib.md5()
        for root, dirnames, files in sorted(os.walk(path)):
            root_path = Path(root)
            rel_root = PurePosixPath(root_path.relative_to(path).as_posix())

            dirnames[:] = sorted(
                d for d in dirnames
                if not NodeManifest._is_excluded(rel_root / d, excludes)
            )

            for file in sorted(files):
                file_path = root_path / file
                rel_file = PurePosixPath(file_path.relative_to(path).as_posix())
                if NodeManifest._is_excluded(rel_file, excludes):
                    continue
                hasher.update(str(rel_file).encode())
                try:
                    hasher.update(file_path.read_bytes())
                except IOError:
                    pass
        return hasher.hexdigest()[:5]

    @classmethod
    def create_disposable(cls, source_path: Path, target_port: int, **kwargs) -> NodeManifest:
        defaults = {
            "mem_limit": "512m",
            "nano_cpus": 1000000000,
            "restart_policy": {"Name": "no"},
        }
        return cls(
            source_path=source_path,
            target_port=target_port,
            **(defaults | kwargs)
        )

    @classmethod
    def create_stable(cls, source_path: Path, target_port: int, **kwargs) -> NodeManifest:
        defaults = {
            "mem_limit": "1g",
            "nano_cpus": None,
            "restart_policy": {"Name": "unless-stopped"},
        }
        return cls(
            source_path=source_path,
            target_port=target_port,
            **(defaults | kwargs)
        )