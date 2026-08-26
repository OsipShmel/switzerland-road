from __future__ import annotations

from pathlib import Path

import pytest

from sandboxd.dataclasses.NodeManifest import NodeManifest
from sandboxd.sandbox_orchestrator.SandboxOrchestrator import SandboxOrchestrator

TARGET_DIR = Path(__file__).parent / "target" / "juice-shop-master"
AGENT_DIR = Path(__file__).parent / "pentest_stub"

NETWORK_NAME = "sandbox-test-net"

CURL_TO_TARGET = (
    "curl -s -o /dev/null -w '%{http_code}' "
    "http://target:3000/rest/admin/application-version"
)


def target_manifest() -> NodeManifest:
    return NodeManifest.create_disposable(
        source_path=TARGET_DIR,
        target_port=3000,
        health_path="/rest/admin/application-version",
    )


def agent_manifest() -> NodeManifest:
    return NodeManifest.create_disposable(
        source_path=AGENT_DIR,
        target_port=8080,
    )


@pytest.fixture
def orchestrator():
    orch = SandboxOrchestrator()
    try:
        yield orch
    finally:
        orch.stop()  # гарантированный teardown даже если тест упал по ассерту


def test_bridge_between_target_and_agent(orchestrator: SandboxOrchestrator) -> None:
    orchestrator.start(NETWORK_NAME, target=target_manifest(), agent=agent_manifest())

    agent = orchestrator.get("agent")
    status = agent.exec(CURL_TO_TARGET)

    assert status == "200", f"agent could not reach target over bridge, got {status!r}"


def test_target_restart_preserves_agent_and_bridge(orchestrator: SandboxOrchestrator) -> None:
    orchestrator.start(NETWORK_NAME, target=target_manifest(), agent=agent_manifest())

    agent_before = orchestrator.get("agent").raw_access
    agent_container_id_before = agent_before.id

    # baseline: bridge жив до рестарта
    assert orchestrator.get("agent").exec(CURL_TO_TARGET) == "200"

    orchestrator.restart("target")

    # agent физически не пересоздан — тот же контейнер, тот же id
    agent_after = orchestrator.get("agent").raw_access
    assert agent_after.id == agent_container_id_before, (
        "agent container was recreated on target restart, but it shouldn't have been"
    )

    # но target реально новый инстанс (жив, отвечает) — health-check внутри up() это уже проверил
    assert orchestrator.get("target").is_running()

    # bridge всё ещё работает после пересоздания target — DNS подхватил новый IP
    status_after = orchestrator.get("agent").exec(CURL_TO_TARGET)
    assert status_after == "200", (
        f"bridge broken after target restart, agent got {status_after!r}"
    )


def test_restart_without_explicit_manifest_reuses_last_one(orchestrator: SandboxOrchestrator) -> None:
    orchestrator.start(NETWORK_NAME, target=target_manifest(), agent=agent_manifest())

    # restart() без передачи manifest — должен взять тот же, что был в start()
    restarted = orchestrator.restart("target")

    assert restarted.is_running()
    assert orchestrator.get("agent").exec(CURL_TO_TARGET) == "200"