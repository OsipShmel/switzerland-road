from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from scoring_agent import RegistryScoringAgent
from scoring_agent.schemas import ScoringDecision, ScoringResponse
from vls import EndpointReference, SastBlock, VLS, VlsRegistry


class RegistryScoringAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.topology = {
            "nodes": [
                {"id": "gateway", "type": "gateway"},
                {"id": "juice-shop", "type": "service"},
                {"id": "database", "type": "database"},
            ],
            "edges": [
                {"source": "gateway", "target": "juice-shop"},
                {"source": "juice-shop", "target": "database"},
            ],
        }

    def test_scoring_updates_and_returns_same_registry(self) -> None:
        client = self._client_with_scores({"finding-1": 8.7})
        registry = VlsRegistry(
            [
                VLS(
                    id="finding-1",
                    title="sql injection",
                    sast=SastBlock(
                        rule_id="typescript.sql-injection",
                        file_path="routes/search.ts",
                        line=2,
                        endpoint=EndpointReference(
                            path="/rest/products/search",
                            http_methods=["GET"],
                        ),
                    ),
                )
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "routes").mkdir()
            (target / "routes" / "search.ts").write_text(
                "const q = request.query.q\ndatabase.query(q)\n",
                encoding="utf-8",
            )
            scorer = RegistryScoringAgent(
                self.topology,
                "juice-shop",
                client=client,
            )

            result = scorer.score_registry(registry, target)

        self.assertIs(result, registry)
        self.assertEqual(registry["finding-1"].sast.score, 8.7)
        prompt = client.beta.chat.completions.parse.call_args.kwargs["messages"][1]
        self.assertIn("database.query(q)", prompt["content"])
        self.assertIn("/rest/products/search", prompt["content"])

    def test_scoring_requires_decision_for_every_vls(self) -> None:
        client = self._client_with_scores({})
        registry = VlsRegistry(
            [
                VLS(
                    id="finding-1",
                    title="sql injection",
                    sast=SastBlock(rule_id="sqli", file_path="app.py", line=1),
                )
            ]
        )
        scorer = RegistryScoringAgent(
            self.topology,
            "juice-shop",
            client=client,
        )

        with self.assertRaisesRegex(ValueError, "missing=.*finding-1"):
            scorer.score_registry(registry, ".")

        self.assertIsNone(registry["finding-1"].sast.score)

    @staticmethod
    def _client_with_scores(scores: dict[str, float]) -> Mock:
        parsed = ScoringResponse(
            items=[
                ScoringDecision(
                    vulnerability_id=vulnerability_id,
                    score=score,
                    priority="HIGH",
                )
                for vulnerability_id, score in scores.items()
            ]
        )
        client = Mock()
        client.beta.chat.completions.parse.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(parsed=parsed))]
        )
        return client


if __name__ == "__main__":
    unittest.main()
