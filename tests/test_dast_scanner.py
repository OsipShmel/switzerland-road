from __future__ import annotations

import hashlib
import unittest
from unittest.mock import patch

from orchestrator.dast_scanner import ZapDastScanner


class ZapDastScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = ZapDastScanner("pentest_lab")
        self.vulnerability = {
            "sast": {
                "file_path": "routes/search.ts",
                "line": 23,
                "cwe": ["CWE-89"],
                "endpoint": {
                    "path": "/rest/products/search",
                    "http_methods": ["GET"],
                    "query_parameters": ["q"],
                    "parameters": [
                        {"name": "q", "location": "query", "required": False}
                    ],
                },
            }
        }
        self.report = {
            "site": [
                {
                    "alerts": [
                        {
                            "name": "SQL Injection",
                            "cweid": "89",
                            "riskdesc": "High (Medium)",
                            "instances": [
                                {
                                    "uri": "http://target:3000/rest/products/search?q=1",
                                    "method": "GET",
                                    "param": "q",
                                    "attack": "'",
                                    "evidence": "SQL syntax error",
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        self.trace = {
            "available": True,
            "events": [
                {
                    "sink": "sequelize.query",
                    "cwe": 89,
                    "method": "GET",
                    "url": "/rest/products/search?q=1",
                    "inputs": {
                        "query": {"q": hashlib.sha256(b"'").hexdigest()}
                    },
                    "stack": "Error\n at search (/juice-shop/routes/search.ts:23:22)",
                }
            ],
        }

    def test_builds_target_url_with_query_parameter(self) -> None:
        url, reason = self.scanner._target_url(
            "http://target:3000",
            self.vulnerability["sast"]["endpoint"],
        )

        self.assertIsNone(reason)
        self.assertEqual(url, "http://target:3000/rest/products/search?q=1")

    def test_confirmed_alert_matches_method_parameter_and_runtime_line(self) -> None:
        with (
            patch.object(self.scanner, "_run_zap", return_value=self.report),
            patch.object(self.scanner, "_fetch_runtime_trace", return_value=self.trace),
        ):
            result = self.scanner.scan(
                self.vulnerability,
                "http://target:3000",
            )

        self.assertTrue(result.confirmed)
        self.assertEqual(result.step.verdict_output, "confirmed")
        self.assertEqual(result.step.human_report.http_method, "GET")
        self.assertEqual(result.step.human_report.parameter, "q")
        self.assertEqual(len(result.step.human_report.runtime_evidence), 1)

    def test_same_cwe_on_same_endpoint_but_other_line_is_rejected(self) -> None:
        self.vulnerability["sast"]["line"] = 47

        matches = self.scanner._relevant_alerts(
            self.report,
            self.vulnerability["sast"],
            "http://target:3000/rest/products/search?q=1",
            self.trace,
        )

        self.assertEqual(matches, [])

    def test_same_line_but_other_attack_request_is_rejected(self) -> None:
        self.report["site"][0]["alerts"][0]["instances"][0]["attack"] = "1'"

        matches = self.scanner._relevant_alerts(
            self.report,
            self.vulnerability["sast"],
            "http://target:3000/rest/products/search?q=1",
            self.trace,
        )

        self.assertEqual(matches, [])

    def test_alert_with_other_method_is_rejected(self) -> None:
        self.report["site"][0]["alerts"][0]["instances"][0]["method"] = "POST"

        matches = self.scanner._relevant_alerts(
            self.report,
            self.vulnerability["sast"],
            "http://target:3000/rest/products/search?q=1",
            self.trace,
        )

        self.assertEqual(matches, [])

    def test_runtime_trace_is_required_for_confirmation(self) -> None:
        with (
            patch.object(self.scanner, "_run_zap", return_value=self.report),
            patch.object(
                self.scanner,
                "_fetch_runtime_trace",
                return_value={"available": False, "events": []},
            ),
        ):
            result = self.scanner.scan(
                self.vulnerability,
                "http://target:3000",
            )

        self.assertFalse(result.confirmed)
        self.assertEqual(result.step.verdict_output, "unconfirmed")

    def test_openapi_supports_post_body_and_path_parameters(self) -> None:
        endpoint = {
            "path": "/users/:id",
            "http_methods": ["POST", "PATCH"],
            "parameters": [
                {"name": "id", "location": "path", "required": True},
                {"name": "email", "location": "body", "required": True},
            ],
        }

        specification = self.scanner._openapi_spec("http://target:3000", endpoint)

        operations = specification["paths"]["/users/{id}"]
        self.assertEqual(set(operations), {"post", "patch"})
        self.assertEqual(
            operations["post"]["parameters"][0]["in"],
            "path",
        )
        body = operations["post"]["requestBody"]["content"]["application/json"]
        self.assertIn("email", body["schema"]["properties"])

    def test_post_endpoint_is_executed(self) -> None:
        self.vulnerability["sast"]["endpoint"]["http_methods"] = ["POST"]
        self.vulnerability["sast"]["endpoint"]["parameters"] = [
            {"name": "q", "location": "body", "required": True}
        ]
        self.report["site"][0]["alerts"][0]["instances"][0]["method"] = "POST"
        self.trace["events"][0]["method"] = "POST"

        with (
            patch.object(self.scanner, "_run_zap", return_value=self.report) as run,
            patch.object(self.scanner, "_fetch_runtime_trace", return_value=self.trace),
        ):
            result = self.scanner.scan(
                self.vulnerability,
                "http://target:3000",
            )

        self.assertIsNotNone(result.step)
        run.assert_called_once()

    def test_different_cwe_does_not_confirm_sast_finding(self) -> None:
        self.report["site"][0]["alerts"][0]["cweid"] = "693"

        matches = self.scanner._relevant_alerts(
            self.report,
            self.vulnerability["sast"],
            "http://target:3000/rest/products/search?q=1",
            self.trace,
        )

        self.assertEqual(matches, [])


if __name__ == "__main__":
    unittest.main()
