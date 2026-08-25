import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RuntimeManifest:
    source_path: Path
    target_port: int
    published_port: int | None = None

    image_prefix: str = "sandbox-runtime"
    env: dict[str, str] = field(default_factory=dict)

    health_path: str = "/"
    health_timeout: float = 60.0

    mem_limit: str = "1g"
    nano_cpus: int | None = None
    restart_policy: dict[str, str] = field(default_factory=lambda: {"Name": "unless-stopped"}) # "no" if for target, else unless-stopped

    extra_options: dict[str, Any] = field(default_factory=dict)

    @property
    def image_tag(self) -> str:
        return f"{self.image_prefix}:{self._calculate_dir_hash(self.source_path)}"

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

    @classmethod
    def create_disposable(cls, source_path: Path, target_port: int, **kwargs) -> RuntimeManifest:
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
    def create_stable(cls, source_path: Path, target_port: int, **kwargs) -> RuntimeManifest:
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