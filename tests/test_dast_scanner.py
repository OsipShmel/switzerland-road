from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from orchestrator.dast_scanner import ZapDastScanner


class ZapDastScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = ZapDastScanner("pentest_lab")
        self.vulnerability = {
            "sast": {
                "cwe": ["CWE-89"],
                "endpoint": {
                    "path": "/rest/products/search",
                    "http_methods": ["GET"],
                    "query_parameters": ["q"],
                },
            }
        }

    def test_builds_target_url_with_query_parameter(self) -> None:
        url, reason = self.scanner._target_url(
            "http://target:3000",
            self.vulnerability["sast"]["endpoint"],
        )

        self.assertIsNone(reason)
        self.assertEqual(url, "http://target:3000/rest/products/search?q=1")

    def test_confirmed_alert_must_match_endpoint_and_cwe(self) -> None:
        report = {
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

        def run_zap(command, **kwargs):
            volume = command[command.index("--volume") + 1]
            host_directory = volume.split(":/zap/wrk:rw", 1)[0]
            Path(host_directory, "report.json").write_text(
                json.dumps(report),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch(
            "orchestrator.dast_scanner.subprocess.run",
            side_effect=run_zap,
        ) as run:
            result = self.scanner.scan(
                self.vulnerability,
                "http://target:3000",
            )

        self.assertTrue(result.confirmed)
        self.assertEqual(result.step.verdict_output, "confirmed")
        self.assertEqual(result.step.human_report.parameter, "q")
        command = run.call_args.args[0]
        self.assertIn("--pull=never", command)
        self.assertEqual(command[command.index("--network") + 1], "pentest_lab")

    def test_post_endpoint_is_not_marked_as_scanned(self) -> None:
        self.vulnerability["sast"]["endpoint"]["http_methods"] = ["POST"]

        with patch("orchestrator.dast_scanner.subprocess.run") as run:
            result = self.scanner.scan(
                self.vulnerability,
                "http://target:3000",
            )

        self.assertIsNone(result.step)
        self.assertIn("POST", result.skip_reason)
        run.assert_not_called()

    def test_different_cwe_does_not_confirm_sast_finding(self) -> None:
        report = {
            "site": [
                {
                    "alerts": [
                        {
                            "name": "Missing CSP",
                            "cweid": "693",
                            "instances": [
                                {
                                    "uri": "http://target:3000/rest/products/search?q=1",
                                }
                            ],
                        }
                    ]
                }
            ]
        }

        with patch.object(self.scanner, "_run_zap", return_value=report):
            result = self.scanner.scan(
                self.vulnerability,
                "http://target:3000",
            )

        self.assertFalse(result.confirmed)
        self.assertEqual(result.step.verdict_output, "unconfirmed")


if __name__ == "__main__":
    unittest.main()
