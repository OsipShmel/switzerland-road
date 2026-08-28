from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from data_enricher import VLSBuilder
from orchestrator.endpoint_locator import EndpointLocator
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

        endpoint = result["vulnerabilities"][0]["sast"]["endpoint"]
        self.assertEqual(endpoint["framework"], "fastapi")
        self.assertEqual(endpoint["path"], "/users")
        self.assertEqual(endpoint["http_methods"], ["POST"])
        self.assertEqual(endpoint["handler"], "create_user")


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
