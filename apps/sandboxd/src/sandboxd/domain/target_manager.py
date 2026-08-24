from __future__ import annotations
import uuid
from .target import TargetManifest, TargetInstance, TargetState
from .errors import TargetAlreadyRunning, TargetNotFound

class TargetManager:
    def __init__(self, runtime) -> None:  # runtime — infra-адаптер, ниже
        self._runtime = runtime
        self._instances: dict[str, TargetInstance] = {}

    def start(self, manifest: TargetManifest) -> TargetInstance:
        instance = TargetInstance(
            instance_id=str(uuid.uuid4()),
            manifest=manifest,
        )
        self._instances[instance.instance_id] = instance

        container_ids = self._runtime.up(manifest)
        instance.container_ids = container_ids
        instance.state = TargetState.RUNNING
        return instance

    def stop(self, instance_id: str) -> None:
        instance = self._instances.get(instance_id)
        if instance is None:
            raise TargetNotFound()
        self._runtime.down(instance.container_ids)
        instance.state = TargetState.STOPPED

    def reset(self, instance_id: str) -> TargetInstance:
        instance = self._instances[instance_id]
        self.stop(instance_id)
        return self.start(instance.manifest)