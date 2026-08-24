from __future__ import annotations
from enum import StrEnum
from pydantic import BaseModel

class TargetState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    STOPPED = "stopped"
    CRASHED = "crashed"

class TargetManifest(BaseModel):
    source_path: str          # путь к RO-mount с кодовой базой
    entrypoint: str
    env: dict[str, str] = {}
    exposed_ports: list[int] = []

class TargetInstance(BaseModel):
    instance_id: str
    manifest: TargetManifest
    state: TargetState = TargetState.PENDING
    container_ids: list[str] = []