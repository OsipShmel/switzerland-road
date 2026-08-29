from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from data_enricher import VLSBuilder
from orchestrator.dast_scanner import DastScanResult
from orchestrator.endpoint_locator import EndpointLocator
from orchestrator.pipeline_runner import (
    PipelineError,
    SecurityPipeline,
    SemgrepScanner,
    run_pipeline,
)
from vls import DastReport, DastVerificationStep, VlsRegistry


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
    def test_public_method_returns_vls_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch(
            "orchestrator.pipeline_runner.SemgrepScanner.scan",
            return_value={"results": []},
        ):
            result = run_pipeline(directory)

        self.assertIsInstance(result, VlsRegistry)

    def test_pipeline_returns_vls_registry(self) -> None:
        scanner = Mock()
        scanner.scan.return_value = {"results": []}
        pipeline = SecurityPipeline(scanner, VLSBuilder())

        result = pipeline.run(".")

        self.assertIsInstance(result, VlsRegistry)
        self.assertEqual(result.all(), [])
        scanner.scan.assert_called_once_with(Path.cwd().resolve())

    def test_pipeline_can_disable_correlation(self) -> None:
        scanner = Mock()
        scanner.scan.return_value = {
            "results": [
                {
                    "check_id": "python.sql-injection",
                    "path": "app.py",
                    "start": {"line": 1},
                    "extra": {"message": "sql injection"},
                }
            ]
        }
        locator = Mock()
        dast = Mock()
        pipeline = SecurityPipeline(
            scanner,
            VLSBuilder(),
            endpoint_locator=locator,
            dast_scanner=dast,
        )

        dast.scan_standalone.return_value = {"site": []}
        with tempfile.TemporaryDirectory() as directory:
            logs_dir = Path(directory) / "logs"
            result = pipeline.run(
                ".",
                "http://target:8000",
                correlation_enabled=False,
                logs_dir=logs_dir,
            )
            report = (logs_dir / "dast-report.json").read_text(encoding="utf-8")

        locator.enrich.assert_not_called()
        dast.scan.assert_not_called()
        dast.scan_standalone.assert_called_once_with("http://target:8000")
        vulnerability = result.all()[0]
        self.assertIsNone(vulnerability.sast.endpoint)
        self.assertFalse(vulnerability.verification_history.dast.run_executed)
        self.assertEqual(
            vulnerability.verification_history.dast.verdict_output,
            "not_tested",
        )
        self.assertIn('"site": []', report)

    def test_pipeline_adds_endpoint_to_vls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            source = target / "app.py"
            source.write_text(
                textwrap.dedent(
                    """
                    from fastapi import FastAPI

                    app = FastAPI()

                    @app.post("/users")
                    async def create_user(name: str):
                        query = "SELECT * FROM users WHERE name = " + name
                        return query
                    """
                ).lstrip(),
                encoding="utf-8",
            )
            scanner = Mock()
            scanner.scan.return_value = {
                "results": [
                    {
                        "check_id": "python.sql-injection",
                        "path": "app.py",
                        "start": {"line": 7, "col": 5},
                        "end": {"line": 7, "col": 30},
                        "extra": {"message": "sql injection"},
                    }
                ]
            }

            result = SecurityPipeline(scanner, VLSBuilder()).run(target)

        endpoint = result.all()[0].sast.endpoint
        self.assertEqual(endpoint.path, "/users")
        self.assertEqual(endpoint.http_methods, ["POST"])
        self.assertTrue(endpoint.evidence)

    def test_pipeline_applies_confirmed_dast_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "app.py").write_text(
                textwrap.dedent(
                    """
                    @app.get("/search")
                    def search(q: str):
                        return raw_query(q)
                    """
                ).lstrip(),
                encoding="utf-8",
            )
            scanner = Mock()
            scanner.scan.return_value = {
                "results": [
                    {
                        "check_id": "python.sql-injection",
                        "path": "app.py",
                        "start": {"line": 3},
                        "extra": {
                            "message": "sql injection",
                            "metadata": {"cwe": ["CWE-89"]},
                        },
                    }
                ]
            }
            dast = Mock()
            dast.scan.return_value = DastScanResult(
                step=DastVerificationStep(
                    run_executed=True,
                    verdict_output="confirmed",
                    human_report=DastReport(
                        executor_name="OWASP ZAP",
                        action_taken="active scan",
                        result_details="SQL injection found",
                    ),
                ),
                target_url="http://target:8000/search",
                confirmed=True,
            )

            result = SecurityPipeline(
                scanner,
                VLSBuilder(),
                dast_scanner=dast,
            ).run(target, "http://target:8000")

        vulnerability = result.all()[0]
        self.assertEqual(vulnerability.status, "checked")
        self.assertEqual(vulnerability.confirmed_by, "dast")
        self.assertTrue(vulnerability.verification_history.dast.run_executed)
        self.assertEqual(
            vulnerability.verification_history.dast.verdict_output,
            "confirmed",
        )
        self.assertEqual(vulnerability.sast.endpoint.path, "/search")

    def test_pipeline_keeps_unconfirmed_dast_step_in_vls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "app.py").write_text(
                "@app.get('/search')\ndef search(q: str):\n    return raw_query(q)\n",
                encoding="utf-8",
            )
            scanner = Mock()
            scanner.scan.return_value = {
                "results": [
                    {
                        "check_id": "python.sql-injection",
                        "path": "app.py",
                        "start": {"line": 3},
                        "extra": {"message": "sql injection"},
                    }
                ]
            }
            dast = Mock()
            dast.scan.return_value = DastScanResult(
                step=DastVerificationStep(
                    run_executed=True,
                    verdict_output="unconfirmed",
                    human_report=DastReport(
                        executor_name="OWASP ZAP",
                        action_taken="active scan",
                        result_details="issue was not confirmed",
                    ),
                ),
                target_url="http://target:8000/search",
                confirmed=False,
            )

            result = SecurityPipeline(
                scanner,
                VLSBuilder(),
                dast_scanner=dast,
            ).run(target, "http://target:8000")

        vulnerability = result.all()[0]
        self.assertEqual(vulnerability.status, "unchecked")
        self.assertTrue(vulnerability.verification_history.dast.run_executed)
        self.assertEqual(
            vulnerability.verification_history.dast.verdict_output,
            "unconfirmed",
        )


class EndpointLocatorTests(unittest.TestCase):
    def test_finds_spring_mapping_above_method(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            source = target / "UserController.java"
            source.write_text(
                textwrap.dedent(
                    """
                    @RequestMapping("/api")
                    public class UserController {
                        @GetMapping("/users/{id}")
                        public String getUser(String id) {
                            return repository.rawQuery(id);
                        }
                    }
                    """
                ).lstrip(),
                encoding="utf-8",
            )
            output = EndpointLocator().enrich(
                target,
                {
                    "results": [
                        {
                            "path": "UserController.java",
                            "start": {"line": 5},
                        }
                    ]
                },
            )

        endpoint = output["results"][0]["endpoint"]
        self.assertEqual(endpoint["framework"], "spring")
        self.assertEqual(endpoint["path"], "/api/users/{id}")
        self.assertEqual(endpoint["http_methods"], ["GET"])

    def test_finds_spring_method_and_parameter_locations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            source = target / "UserController.java"
            source.write_text(
                textwrap.dedent(
                    """
                    @RequestMapping("/api")
                    public class UserController {
                        @RequestMapping(path = "/users/{id}", method = {RequestMethod.PUT, RequestMethod.PATCH})
                        public String update(@PathVariable("id") String id, @RequestParam(name = "q", required = false) String query, @RequestBody String payload) {
                            return repository.rawQuery(query);
                        }
                    }
                    """
                ).lstrip(),
                encoding="utf-8",
            )

            output = EndpointLocator().enrich(
                target,
                {"results": [{"path": "UserController.java", "start": {"line": 5}}]},
            )

        endpoint = output["results"][0]["endpoint"]
        self.assertEqual(endpoint["http_methods"], ["PUT", "PATCH"])
        self.assertIn(
            {"name": "id", "location": "path", "required": True},
            endpoint["parameters"],
        )
        self.assertIn(
            {"name": "q", "location": "query", "required": False},
            endpoint["parameters"],
        )
        self.assertIn(
            {"name": "payload", "location": "body", "required": True},
            endpoint["parameters"],
        )

    def test_finds_fastapi_patch_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "app.py").write_text(
                textwrap.dedent(
                    """
                    @app.patch("/users/{user_id}")
                    async def update_user(user_id: int, payload: str = Body(...), q: str | None = None):
                        return raw_query(q)
                    """
                ).lstrip(),
                encoding="utf-8",
            )

            output = EndpointLocator().enrich(
                target,
                {"results": [{"path": "app.py", "start": {"line": 3}}]},
            )

        endpoint = output["results"][0]["endpoint"]
        self.assertEqual(endpoint["http_methods"], ["PATCH"])
        self.assertIn(
            {"name": "user_id", "location": "path", "required": True},
            endpoint["parameters"],
        )
        self.assertIn(
            {"name": "payload", "location": "body", "required": True},
            endpoint["parameters"],
        )
        self.assertIn("q", endpoint["query_parameters"])

    def test_finds_django_path_in_urls_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "views.py").write_text(
                textwrap.dedent(
                    """
                    def search(request):
                        query = request.GET["q"]
                        return raw_query(query)
                    """
                ).lstrip(),
                encoding="utf-8",
            )
            (target / "urls.py").write_text(
                'path("search/", views.search, name="search")\n',
                encoding="utf-8",
            )
            output = EndpointLocator().enrich(
                target,
                {"results": [{"path": "views.py", "start": {"line": 3}}]},
            )

        endpoint = output["results"][0]["endpoint"]
        self.assertEqual(endpoint["framework"], "django")
        self.assertEqual(endpoint["path"], "/search/")
        self.assertEqual(endpoint["declaration_file"], "urls.py")
        self.assertIn("q", endpoint["query_parameters"])

    def test_does_not_read_file_outside_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = EndpointLocator().enrich(
                directory,
                {"results": [{"path": "../app.py", "start": {"line": 1}}]},
            )

        self.assertNotIn("endpoint", output["results"][0])

    def test_finds_imported_express_handler(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            routes = target / "routes"
            routes.mkdir()
            (routes / "search.ts").write_text(
                textwrap.dedent(
                    """
                    export function searchProducts () {
                      return (req, res) => {
                        return database.query(req.query.q)
                      }
                    }
                    """
                ).lstrip(),
                encoding="utf-8",
            )
            (target / "server.ts").write_text(
                textwrap.dedent(
                    """
                    import { searchProducts } from './routes/search'

                    app.get(
                      '/rest/products/search',
                      utils.asyncHandler(searchProducts())
                    )
                    """
                ).lstrip(),
                encoding="utf-8",
            )

            output = EndpointLocator().enrich(
                target,
                {"results": [{"path": "routes/search.ts", "start": {"line": 3}}]},
            )

        endpoint = output["results"][0]["endpoint"]
        self.assertEqual(endpoint["framework"], "express")
        self.assertEqual(endpoint["path"], "/rest/products/search")
        self.assertEqual(endpoint["http_methods"], ["GET"])
        self.assertEqual(endpoint["handler"], "searchProducts")
        self.assertEqual(endpoint["declaration_file"], "server.ts")
        self.assertEqual(endpoint["query_parameters"], ["q"])
        self.assertEqual(endpoint["locator_confidence"], 0.95)
        self.assertEqual(len(endpoint["locator_evidence"]), 3)

    def test_combines_express_router_mount_with_local_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            routes = target / "routes"
            routes.mkdir()
            (routes / "profile.ts").write_text(
                textwrap.dedent(
                    """
                    const router = express.Router()

                    router.post('/image', (req, res) => {
                      return saveUnsafe(req.body.url)
                    })

                    export default router
                    """
                ).lstrip(),
                encoding="utf-8",
            )
            (target / "server.ts").write_text(
                textwrap.dedent(
                    """
                    import profile from './routes/profile'

                    app.use('/profile', profile)
                    """
                ).lstrip(),
                encoding="utf-8",
            )

            output = EndpointLocator().enrich(
                target,
                {"results": [{"path": "routes/profile.ts", "start": {"line": 4}}]},
            )

        endpoint = output["results"][0]["endpoint"]
        self.assertEqual(endpoint["path"], "/profile/image")
        self.assertEqual(endpoint["http_methods"], ["POST"])
        self.assertIn(
            {"name": "url", "location": "body", "required": False},
            endpoint["parameters"],
        )

    def test_finds_all_express_methods_and_parameter_locations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "server.ts").write_text(
                textwrap.dedent(
                    """
                    app.put('/users/:id', (req, res) => {
                      return unsafe(req.params.id, req.body.email, req.headers.authorization)
                    })
                    """
                ).lstrip(),
                encoding="utf-8",
            )

            output = EndpointLocator().enrich(
                target,
                {"results": [{"path": "server.ts", "start": {"line": 2}}]},
            )

        endpoint = output["results"][0]["endpoint"]
        self.assertEqual(endpoint["http_methods"], ["PUT"])
        locations = {(item["name"], item["location"]) for item in endpoint["parameters"]}
        self.assertEqual(
            locations,
            {("id", "path"), ("email", "body"), ("authorization", "header")},
        )

    def test_finds_endpoint_in_juice_shop_stack(self) -> None:
        target = Path(__file__).resolve().parents[1] / "target" / "juice-shop-master"
        source = target / "routes" / "search.ts"
        if not source.is_file():
            self.skipTest("juice shop target is not available")
        vulnerable_line = next(
            index
            for index, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1)
            if "models.sequelize.query" in line
        )

        output = EndpointLocator().enrich(
            target,
            {"results": [{"path": "routes/search.ts", "start": {"line": vulnerable_line}}]},
        )

        endpoint = output["results"][0]["endpoint"]
        self.assertEqual(endpoint["path"], "/rest/products/search")
        self.assertEqual(endpoint["http_methods"], ["GET"])
        self.assertEqual(endpoint["handler"], "searchProducts")


if __name__ == "__main__":
    unittest.main()
