from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from data_enricher import VLSBuilder
from orchestrator.pipeline_runner import PipelineError, SecurityPipeline, SemgrepScanner


class SemgrepScannerTests(unittest.TestCase):
    def test_scan_runs_inside_target_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.CompletedProcess(
                args=["semgrep"],
                returncode=0,
                stdout='{"results": []}',
                stderr="",
            )
            with patch(
                "orchestrator.pipeline_runner.subprocess.run",
                return_value=process,
            ) as run:
                SemgrepScanner().scan(directory)

        command = run.call_args.args[0]
        self.assertEqual(command[-3:], ["--project-root", ".", "."])
        self.assertEqual(run.call_args.kwargs["cwd"], Path(directory).resolve())

    def test_failure_is_not_reported_as_empty_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.CompletedProcess(
                args=["semgrep"], returncode=2, stdout="", stderr="broken config"
            )
            with patch(
                "orchestrator.pipeline_runner.subprocess.run",
                return_value=process,
            ):
                with self.assertRaisesRegex(PipelineError, "broken config"):
                    SemgrepScanner().scan(directory)

    def test_json_shape_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.CompletedProcess(
                args=["semgrep"], returncode=0, stdout='{"errors": []}', stderr=""
            )
            with patch(
                "orchestrator.pipeline_runner.subprocess.run",
                return_value=process,
            ):
                with self.assertRaisesRegex(PipelineError, "results list"):
                    SemgrepScanner().scan(directory)


class SecurityPipelineTests(unittest.TestCase):
    def test_pipeline_returns_vulnerability_list(self) -> None:
        scanner = Mock()
        scanner.scan.return_value = {"results": []}
        pipeline = SecurityPipeline(scanner, VLSBuilder())

        result = pipeline.run(".")

        self.assertEqual(result["vulnerabilities"], [])
        scanner.scan.assert_called_once_with(Path.cwd().resolve())


if __name__ == "__main__":
    unittest.main()
