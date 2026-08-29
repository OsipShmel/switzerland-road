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
                "orchestrator.cli.SemgrepScanner.scan",
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

    def test_disable_correlation_does_not_require_zap_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            output = target / "result.json"
            with patch(
                "orchestrator.cli.SemgrepScanner.scan",
                return_value={"results": []},
            ):
                main(
                    [
                        "--target-dir",
                        str(target),
                        "--output",
                        str(output),
                        "--dast-base-url",
                        "http://target:3000",
                        "--disable-correlation",
                    ]
                )

            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertFalse(report["locator"]["enabled"])
        self.assertEqual(report["dast"]["executed"], 0)


if __name__ == "__main__":
    unittest.main()
