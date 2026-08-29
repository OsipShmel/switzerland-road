from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from orchestrator.cli import main


class CLITests(unittest.TestCase):
    def test_target_dir_is_supplied_to_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            output = target / "result.json"

            with patch(
                "orchestrator.pipeline_runner.SemgrepScanner.scan",
                return_value={"results": []},
            ) as scan:
                main(
                    [
                        "--target-dir",
                        str(target),
                        "--output",
                        str(output),
                    ]
                )

            scan.assert_called_once_with(target.resolve())
            self.assertTrue(output.is_file())

    def test_disable_correlation_writes_separate_dast_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            output = target / "result.json"
            logs = target / "logs"
            with patch(
                "orchestrator.pipeline_runner.SemgrepScanner.scan",
                return_value={"results": []},
            ), patch(
                "orchestrator.pipeline_runner.ZapDastScanner.scan_standalone",
                return_value={"site": []},
            ) as standalone_scan:
                main(
                    [
                        "--target-dir",
                        str(target),
                        "--output",
                        str(output),
                        "--dast-base-url",
                        "http://target:3000",
                        "--zap-network",
                        "pentest_lab",
                        "--disable-correlation",
                        "--logs-dir",
                        str(logs),
                    ]
                )

            records = json.loads(output.read_text(encoding="utf-8"))
            dast_report = json.loads(
                (logs / "dast-report.json").read_text(encoding="utf-8")
            )

        self.assertEqual(records, [])
        self.assertEqual(dast_report, {"site": []})
        standalone_scan.assert_called_once_with("http://target:3000")


if __name__ == "__main__":
    unittest.main()
