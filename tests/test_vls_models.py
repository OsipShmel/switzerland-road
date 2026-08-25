from __future__ import annotations

import unittest

from pydantic import ValidationError
from vls import (
    DastReport,
    DastVerificationStep,
    PentestReport,
    PentestVerificationStep,
    SastBlock,
    VLS,
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


if __name__ == "__main__":
    unittest.main()
