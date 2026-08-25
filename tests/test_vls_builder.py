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
                    "start": {"line": 42},
                    "extra": {"message": "SQL Injection in auth query"},
                }
            ]
        }

    def test_finding_becomes_unchecked_vls(self) -> None:
        record = self.builder.build(self.semgrep)[0]

        self.assertEqual(record["status"], "unchecked")
        self.assertIsNone(record["verdict"])
        self.assertIsNone(record["confirmed_by"])
        self.assertEqual(record["sast"]["file_path"], "src/auth.py")
        self.assertEqual(
            record["verification_history"]["dast"]["verdict_output"],
            "not_tested",
        )

    def test_ids_are_stable(self) -> None:
        first = self.builder.build(self.semgrep)[0]["id"]
        second = self.builder.build(self.semgrep)[0]["id"]
        self.assertEqual(first, second)

    def test_invalid_result_shape_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "results.*list"):
            self.builder.build({"results": {}})


if __name__ == "__main__":
    unittest.main()
