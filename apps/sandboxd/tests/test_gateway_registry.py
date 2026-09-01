from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sandboxd.api.agent_gateway.state import GatewayState
from vls import VLSVerdict


class FakeControlClient:
    def __init__(self) -> None:
        self.synced = []

    async def get_vls_registry(self) -> list[dict]:
        return [{"id": "pipeline-vls", "title": "pipeline finding"}]

    async def sync_vls(self, vulnerability) -> None:
        self.synced.append(vulnerability)


class GatewayRegistryTests(unittest.IsolatedAsyncioTestCase):
    async def test_loads_registry_received_by_sandboxd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            control_client = FakeControlClient()
            state = GatewayState(
                logs_dir=Path(temp_dir),
                control_client=control_client,
            )
            await state.load_current_registry()

            session = state.start_check_session()
            vulnerability = state.apply_check_result(
                verdict=VLSVerdict.UNCONFIRMED,
                proof_is_flag=False,
                action_taken="request sent",
                result_details="no exploit evidence",
            )
            await state.sync_vulnerability(vulnerability)

        self.assertEqual(vulnerability.id, "pipeline-vls")
        self.assertTrue(vulnerability.verification_history.pentest.run_executed)
        self.assertEqual(control_client.synced, [vulnerability])


if __name__ == "__main__":
    unittest.main()
