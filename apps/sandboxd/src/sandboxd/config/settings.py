from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.lower() not in {"0", "false", "no", "off"}


def _env_paths(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = os.getenv(name)

    if value is None:
        return default

    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class SandboxSettings:
    """Runtime configuration for the sandbox deployment.

    All topology-specific paths and names are injected through environment
    variables. Defaults preserve the current PoC layout.
    """

    # ------------------------------------------------------------------
    # Filesystem
    # ------------------------------------------------------------------

    project_root: Path = Path(_env("SANDBOXD_PROJECT_ROOT", "/app"))
    gateway_logs_dir: Path = Path(_env("SANDBOXD_GATEWAY_LOGS_DIR", "/var/lib/sandboxd/gateway_logs"))
    target_dir: Path = Path(_env("SANDBOXD_TARGET_DIR", "/app/apps/sandboxd/tests/target/juice-shop-master"))
    agent_dir: Path = Path(_env("SANDBOXD_AGENT_DIR", "/app/apps/sandboxd/tests/pentest_stub"))

    # ------------------------------------------------------------------
    # Dockerfiles / build contexts
    # ------------------------------------------------------------------

    target_dockerfile: str = _env("SANDBOXD_TARGET_DOCKERFILE", "Dockerfile")
    agent_dockerfile: str = _env("SANDBOXD_AGENT_DOCKERFILE", "apps/pentest_agent_test/Dockerfile")
    gateway_dockerfile: str = _env("SANDBOXD_GATEWAY_DOCKERFILE", "apps/sandboxd/tests/gateway/Dockerfile")
    llm_egress_dockerfile: str = _env("SANDBOXD_LLM_EGRESS_DOCKERFILE", "apps/sandboxd/tests/llm_egress/Dockerfile")

    # ------------------------------------------------------------------
    # Networks
    # ------------------------------------------------------------------

    target_network: str = _env("SANDBOXD_TARGET_NETWORK", "sandbox-target-net")
    control_network: str = _env("SANDBOXD_CONTROL_NETWORK", "sandbox-control-net")
    egress_network: str = _env("SANDBOXD_EGRESS_NETWORK", "sandbox-egress-net")
    uplink_network: str = _env("SANDBOXD_UPLINK_NETWORK", "sandbox-uplink-net")

    # ------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------

    agent_target_port: int = _env_int("SANDBOXD_AGENT_PORT", 8080)
    gateway_port: int = _env_int("SANDBOXD_GATEWAY_PORT", 9000)
    llm_egress_port: int = _env_int("SANDBOXD_LLM_EGRESS_PORT", 11434)

    # ------------------------------------------------------------------
    # LLM
    # ------------------------------------------------------------------

    ollama_base_url: str = _env("OLLAMA_BASE_URL", "http://host.docker.internal:11435")
    ollama_model: str = _env("OLLAMA_MODEL", "gemma4-26b-think:latest")
    llm_upstream_host: str = _env("LLM_UPSTREAM_HOST", "host.docker.internal")
    llm_upstream_port: str = _env("LLM_UPSTREAM_PORT", "11435")

    # ------------------------------------------------------------------
    # LLM / provider egress
    # ------------------------------------------------------------------

    openai_base_url: str = _env("OPENAI_BASE_URL", "http://llm_egress:11434/v1")
    openai_upstream_path: str = _env("OPENAI_UPSTREAM_PATH","/api",)
    openai_model: str = _env("OPENAI_MODEL", "Qwen3.8-27B")
    openai_upstream_host: str = _env("OPENAI_UPSTREAM_HOST", "deepcode.ci.nsu.ru}")
    openai_upstream_port: str = _env("OPENAI_UPSTREAM_PORT", "443")
    openai_api_key: str = _env("OPENAI_API_KEY", "")

    # ------------------------------------------------------------------
    # Runtime
    # ------------------------------------------------------------------

    llm_bridge_enabled: bool = _env_bool("SANDBOXD_LLM_BRIDGE", True)
    egress_delay_ms: int = _env_int("SANDBOXD_EGRESS_DELAY_MS", 100)

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    common_hash_excludes: tuple[str, ...] = _env_paths(
        "SANDBOXD_HASH_EXCLUDES",
        ("sandboxd/tests/target", ".git", ".venv", "__pycache__"),
    )


settings = SandboxSettings()

COMMON_HASH_EXCLUDES = settings.common_hash_excludes
