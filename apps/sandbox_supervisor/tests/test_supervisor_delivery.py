from __future__ import annotations

import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import httpx
from vls import VlsRegistry

from sandbox_supervisor.supervisor import Supervisor


class FakeSandboxIOManager:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.archive: bytes | None = None
        self.registry: VlsRegistry | None = None

    async def send_zip(self, archive: bytes) -> bool:
        self.events.append("target")
        self.archive = archive
        return True

    async def send_vls_registry(self, registry: VlsRegistry) -> bool:
        self.events.append("registry")
        self.registry = registry
        return True


class SupervisorDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_sends_target_archive_then_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir)
            (target / "src").mkdir()
            (target / "src" / "app.py").write_text("print('ok')\n")
            (target / ".git").mkdir()
            (target / ".git" / "config").write_text("secret\n")

            async with httpx.AsyncClient() as client:
                io_manager = FakeSandboxIOManager()
                supervisor = Supervisor(client, io_manager=io_manager)
                registry = VlsRegistry()

                await supervisor.start_from_directory(target, registry)

        self.assertEqual(io_manager.events, ["target", "registry"])
        self.assertIs(io_manager.registry, registry)
        self.assertIsNotNone(io_manager.archive)
        with ZipFile(BytesIO(io_manager.archive)) as archive:
            self.assertEqual(archive.namelist(), ["src/app.py"])


if __name__ == "__main__":
    unittest.main()
