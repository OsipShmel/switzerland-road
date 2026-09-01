from __future__ import annotations

import unittest

from data_enricher import VLSBuilder


class VLSBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = VLSBuilder()
        self.semgrep = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.sql-injection",
                    "path": "src/auth.py",
                    "start": {"line": 42, "col": 5},
                    "end": {"line": 44, "col": 12},
                    "extra": {
                        "message": "SQL Injection in auth query",
                        "severity": "ERROR",
                        "fingerprint": "finding-fingerprint",
                        "metadata": {"cwe": ["CWE-89"]},
                    },
                }
            ]
        }

    def test_finding_becomes_unchecked_vls(self) -> None:
        record = self.builder.build(self.semgrep)[0]

        self.assertEqual(record["status"], "unchecked")
        self.assertIsNone(record["verdict"])
        self.assertIsNone(record["confirmed_by"])
        self.assertEqual(record["sast"]["file_path"], "src/auth.py")
        self.assertEqual(record["sast"]["end_line"], 44)
        self.assertEqual(record["sast"]["column"], 5)
        self.assertEqual(record["sast"]["cwe"], ["CWE-89"])
        self.assertEqual(
            record["verification_history"]["dast"]["verdict_output"],
            "not_tested",
        )
        self.assertIsNone(
            record["verification_history"]["dast"]["human_report"]
        )

    def test_ids_are_stable(self) -> None:
        first = self.builder.build(self.semgrep)[0]["id"]
        second = self.builder.build(self.semgrep)[0]["id"]
        self.assertEqual(first, second)

    def test_vls_keeps_only_compact_endpoint_data(self) -> None:
        self.semgrep["results"][0]["endpoint"] = {
            "framework": "fastapi",
            "path": "/users",
            "http_methods": ["POST"],
            "handler": "create_user",
            "declaration_file": "src/auth.py",
            "declaration_line": 40,
            "query_parameters": [],
            "parameters": [
                {"name": "name", "location": "body", "required": True}
            ],
            "locator_confidence": 0.9,
            "locator_evidence": ["маршрут найден над обработчиком"],
        }

        endpoint = self.builder.build(self.semgrep)[0]["sast"]["endpoint"]

        self.assertEqual(
            set(endpoint),
            {"path", "http_methods", "query_parameters", "parameters", "evidence"},
        )
        self.assertEqual(endpoint["evidence"], ["маршрут найден над обработчиком"])

    def test_invalid_result_shape_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "results.*list"):
            self.builder.build({"results": {}})


if __name__ == "__main__":
    unittest.main()
