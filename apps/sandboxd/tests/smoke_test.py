from pathlib import Path
from sandboxd.sandbox_runner.SandboxRunner import SandboxRunner

runner = SandboxRunner()
container = runner.start(
    source_path=Path(__file__).parent / "target" /"juice-shop-master",
    target_port=3000,
    health_path="/",
    health_timeout=60.0,
)
print("running, ports:", container.attrs["NetworkSettings"]["Ports"])

input("press enter to stop...")
runner.stop(container)