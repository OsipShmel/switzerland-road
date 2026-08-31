from __future__ import annotations

import unittest

from pydantic import ValidationError
from vls import (
    DastReport,
    DastVerificationStep,
    EndpointReference,
    PentestReport,
    PentestVerificationStep,
    SastBlock,
    VLS,
    VlsRegistry,
)


class VLSDefaultsTests(unittest.TestCase):
    def test_new_vls_has_unchecked_verification_steps(self) -> None:
        vls = VLS(
            id="finding-id",
            title="sql injection",
            sast=SastBlock(
                rule_id="python.sql-injection",
                file_path="src/app.py",
                line=10,
            ),
        )

        self.assertFalse(vls.verification_history.dast.run_executed)
        self.assertEqual(
            vls.verification_history.dast.verdict_output,
            "not_tested",
        )
        self.assertIsNone(vls.verification_history.dast.human_report)
        self.assertFalse(vls.verification_history.pentest.run_executed)


class VerificationStepTests(unittest.TestCase):
    def test_dast_step_accepts_dast_report(self) -> None:
        step = DastVerificationStep(
            run_executed=True,
            verdict_output="confirmed",
            human_report=DastReport(
                executor_name="OWASP ZAP",
                action_taken="sent payload",
                result_details="sql error returned",
                target_url="http://localhost/api/users",
                http_method="POST",
                parameter="name",
                payload="' OR 1=1 --",
                evidence="database error",
            ),
        )

        self.assertEqual(step.human_report.parameter, "name")

    def test_pentest_step_accepts_pentest_report(self) -> None:
        step = PentestVerificationStep(
            run_executed=True,
            verdict_output="unconfirmed",
            human_report=PentestReport(
                executor_name="agent-007",
                action_taken="tested alternate payloads",
                result_details="all requests were rejected",
                session_id="session-1",
                attempts=["single quote", "encoded quote"],
            ),
        )

        self.assertEqual(step.human_report.session_id, "session-1")

    def test_not_executed_step_rejects_verdict(self) -> None:
        with self.assertRaises(ValidationError):
            DastVerificationStep(verdict_output="confirmed")

    def test_executed_step_requires_report(self) -> None:
        with self.assertRaises(ValidationError):
            PentestVerificationStep(
                run_executed=True,
                verdict_output="unconfirmed",
            )

    def test_vls_applies_confirmed_dast_step(self) -> None:
        vls = VLS(id="finding-id", title="sql injection")
        step = DastVerificationStep(
            run_executed=True,
            verdict_output="confirmed",
            human_report=DastReport(
                executor_name="OWASP ZAP",
                action_taken="active scan",
                result_details="sql injection found",
            ),
        )

        updated = vls.with_dast_verification(step)

        self.assertTrue(updated.verification_history.dast.run_executed)
        self.assertEqual(updated.status, "checked")
        self.assertEqual(updated.verdict, "confirmed")
        self.assertEqual(updated.confirmed_by, "dast")

    def test_vls_applies_unconfirmed_dast_step(self) -> None:
        vls = VLS(id="finding-id", title="sql injection")
        step = DastVerificationStep(
            run_executed=True,
            verdict_output="unconfirmed",
            human_report=DastReport(
                executor_name="OWASP ZAP",
                action_taken="active scan",
                result_details="issue was not confirmed",
            ),
        )

        updated = vls.with_dast_verification(step)

        self.assertTrue(updated.verification_history.dast.run_executed)
        self.assertEqual(updated.status, "unchecked")
        self.assertIsNone(updated.verdict)
        self.assertIsNone(updated.confirmed_by)

    def test_dast_confirmation_requires_confirmed_step(self) -> None:
        with self.assertRaises(ValidationError):
            VLS(
                id="finding-id",
                title="sql injection",
                status="checked",
                verdict="confirmed",
                confirmed_by="dast",
            )


class SastBlockTests(unittest.TestCase):
    def test_sast_block_has_safe_defaults(self) -> None:
        sast = SastBlock(
            rule_id="python.sql-injection",
            file_path="src/app.py",
            line=10,
        )

        self.assertEqual(sast.tool, "semgrep")
        self.assertEqual(sast.cwe, [])
        self.assertIsNone(sast.score)

    def test_score_must_be_in_cvss_range(self) -> None:
        with self.assertRaises(ValidationError):
            SastBlock(
                rule_id="python.sql-injection",
                file_path="src/app.py",
                line=10,
                score=11,
            )

    def test_sast_block_accepts_endpoint_reference(self) -> None:
        sast = SastBlock(
            rule_id="python.sql-injection",
            file_path="src/app.py",
            line=10,
            endpoint=EndpointReference(
                path="/users",
                http_methods=["POST"],
                evidence=["маршрут найден над обработчиком"],
            ),
        )

        self.assertEqual(sast.endpoint.path, "/users")
        self.assertEqual(sast.endpoint.evidence, ["маршрут найден над обработчиком"])


class VlsRegistryTests(unittest.TestCase):
    def test_records_are_validated_and_serialized(self) -> None:
        registry = VlsRegistry.from_records(
            [{"id": "finding-id", "title": "sql injection"}]
        )

        self.assertEqual(len(registry), 1)
        self.assertIsInstance(registry["finding-id"], VLS)
        self.assertEqual(registry.to_records()[0]["status"], "unchecked")


if __name__ == "__main__":
    unittest.main()
