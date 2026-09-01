from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sandbox_supervisor.security_gate import (
    SecurityGateInbox,
    SecurityGateService,
    get_security_gate_service,
    router,
)
from sandbox_supervisor.scan_events import ScanEventBroker


os.environ.setdefault(
    "SUPERVISOR_LOGS_DIR",
    "/tmp/switzerland-supervisor-test-logs",
)


class FakeRegistry:
    def to_records(self) -> list[dict[str, Any]]:
        return [{"id": "test-vls"}]


class FakeCloner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Path]] = []

    async def clone(self, repository_url: str, destination: Path) -> None:
        destination.mkdir(parents=True)
        self.calls.append((repository_url, destination))


class FakePipeline:
    def __init__(self, failure: Exception | None = None) -> None:
        self.failure = failure
        self.calls: list[tuple[Path, dict[str, Any]]] = []

    def __call__(self, target_dir: Path, **kwargs: Any) -> FakeRegistry:
        self.calls.append((target_dir, kwargs))
        if self.failure is not None:
            raise self.failure
        return FakeRegistry()


class SecurityGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cloner = FakeCloner()
        self.pipeline = FakePipeline()
        self.published: list[list[dict[str, Any]]] = []
        self.dispatched: list[tuple[Path, FakeRegistry]] = []
        self.events = ScanEventBroker()

        async def publish(records: list[dict[str, Any]]) -> None:
            self.published.append(records)

        async def dispatch(target_dir: Path, registry: FakeRegistry) -> None:
            self.assertTrue(target_dir.is_dir())
            self.dispatched.append((target_dir, registry))

        self.service = SecurityGateService(
            inbox=SecurityGateInbox(),
            cloner=self.cloner,
            pipeline_runner=self.pipeline,
            registry_publisher=publish,
            sandbox_dispatcher=dispatch,
            event_broker=self.events,
            work_dir=self.temp_dir.name,
            semgrep_config="tests/semgrep.yml",
            semgrep_timeout=12,
        )
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_security_gate_service] = lambda: self.service
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.temp_dir.cleanup()

    def test_request_clones_repository_and_runs_pipeline(self) -> None:
        response = self.client.post(
            "/api/security-gate/scans",
            json={
                "repositoryUrl": "https://github.com/juice-shop/juice-shop",
                "correlationEnabled": True,
            },
        )

        self.assertEqual(response.status_code, 202)
        receipt = response.json()
        self.assertEqual(receipt["status"], "accepted")
        self.assertTrue(receipt["scanId"])

        stored = self.client.get(f"/api/security-gate/scans/{receipt['scanId']}")
        self.assertEqual(stored.status_code, 200)
        self.assertEqual(stored.json()["status"], "sandbox_starting")
        self.assertEqual(stored.json()["findingCount"], 1)

        self.assertEqual(len(self.cloner.calls), 1)
        self.assertEqual(len(self.pipeline.calls), 1)
        _target_dir, pipeline_options = self.pipeline.calls[0]
        self.assertTrue(pipeline_options["correlation_enabled"])
        self.assertEqual(pipeline_options["semgrep_config"], "tests/semgrep.yml")
        self.assertEqual(self.published, [[{"id": "test-vls"}]])
        self.assertEqual(len(self.dispatched), 1)

        registry = self.client.get(
            f"/api/security-gate/scans/{receipt['scanId']}/registry"
        )
        self.assertEqual(registry.status_code, 200)
        self.assertEqual(registry.json(), [{"id": "test-vls"}])

        event_types = [
            event["type"] for event in self.events.events(receipt["scanId"])
        ]
        self.assertIn("progress", event_types)
        self.assertIn("finding", event_types)

        asyncio.run(
            self.service.handle_sandbox_log(
                {
                    "level": "info",
                    "event": "agent_stopped",
                    "message": "done",
                    "metadata": {},
                }
            )
        )
        completed = self.client.get(
            f"/api/security-gate/scans/{receipt['scanId']}"
        )
        self.assertEqual(completed.json()["status"], "completed")
        self.assertEqual(
            self.events.events(receipt["scanId"])[-1]["type"],
            "complete",
        )

    def test_pipeline_failure_is_available_in_scan_status(self) -> None:
        self.pipeline.failure = RuntimeError("semgrep failed")
        with self.assertLogs("sandbox_supervisor.security_gate", level="ERROR"):
            response = self.client.post(
                "/api/security-gate/scans",
                json={
                    "repositoryUrl": "https://github.com/team/project",
                    "correlationEnabled": False,
                },
            )

        scan_id = response.json()["scanId"]
        stored = self.client.get(f"/api/security-gate/scans/{scan_id}")
        self.assertEqual(stored.json()["status"], "failed")
        self.assertEqual(stored.json()["error"], "semgrep failed")
        self.assertEqual(
            self.client.get(f"/api/security-gate/scans/{scan_id}/registry").status_code,
            409,
        )

    def test_rejects_second_scan_while_sandbox_is_active(self) -> None:
        first = self.client.post(
            "/api/security-gate/scans",
            json={
                "repositoryUrl": "https://github.com/team/first",
                "correlationEnabled": False,
            },
        )
        self.assertEqual(first.status_code, 202)

        second = self.client.post(
            "/api/security-gate/scans",
            json={
                "repositoryUrl": "https://github.com/team/second",
                "correlationEnabled": False,
            },
        )
        self.assertEqual(second.status_code, 409)

    def test_rejects_non_http_repository_url(self) -> None:
        response = self.client.post(
            "/api/security-gate/scans",
            json={
                "repositoryUrl": "git@github.com:team/project.git",
                "correlationEnabled": False,
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_rejects_repository_host_outside_allowlist(self) -> None:
        response = self.client.post(
            "/api/security-gate/scans",
            json={
                "repositoryUrl": "https://example.com/team/project.git",
                "correlationEnabled": False,
            },
        )
        self.assertEqual(response.status_code, 422)


class SecurityGateCorsTests(unittest.TestCase):
    def test_local_frontend_origin_is_allowed(self) -> None:
        from sandbox_supervisor.main import app

        client = TestClient(app)
        response = client.options(
            "/api/security-gate/scans",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        client.close()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["access-control-allow-origin"],
            "http://127.0.0.1:5173",
        )


if __name__ == "__main__":
    unittest.main()
