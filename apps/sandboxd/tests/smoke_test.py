import signal
from pathlib import Path

from sandboxd.dataclasses.runtime_manifest import RuntimeManifest
from sandboxd.sandbox_runner.SandboxRunner import SandboxRunner

runner = SandboxRunner()

target_manifest = RuntimeManifest.create_disposable(
    source_path=Path(__file__).parent / "target" / "juice-shop-master",
    target_port=3000,
    published_port=18001,
    mem_limit="512m",
    nano_cpus=1000000000,
)

container = runner.up(
    manifest=target_manifest,
)
print("running, ports:", container.attrs["NetworkSettings"]["Ports"], flush=True)
print("press enter to stop...")

try:
    signal.pause()
finally:
    print("Stopping target...", flush=True)
    runner.down(container)