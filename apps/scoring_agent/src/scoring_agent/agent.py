from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from openai import OpenAI
from vls import SastBlock, VLS, VlsRegistry

from .config import API_KEY, BASE_URL, MODEL, THRESHOLD
from .graph_tools import extract_node_metrics, parse_topology
from .schemas import ScoringDecision, ScoringResponse


SYS_PROMPT = """Ты — экспертная система AppSec-скоринга.
Верни ровно одно решение для каждого vulnerability_id из входа.
Оцени риск от 0 до 10 с учетом кода, endpoint и топологии.
Внешняя доступность и достижимость критических активов повышают оценку.
Явная безопасная обработка входа и изоляция сервиса снижают оценку.
Не придумывай новые vulnerability_id и не изменяй endpoint.
Для вероятного false positive установи is_false_positive=true и score ниже порога.
"""


class RegistryScoringAgent:
    """добавляет score в существующий vls registry."""

    def __init__(
        self,
        topology: Mapping[str, Any],
        service_name: str,
        *,
        client: Any | None = None,
        model: str = MODEL,
        threshold: float = THRESHOLD,
    ) -> None:
        if not service_name:
            raise ValueError("для скоринга требуется service_name")
        self.graph = parse_topology(topology)
        if service_name not in self.graph:
            raise ValueError(
                f"service_name отсутствует в topology: {service_name}"
            )
        self.service_name = service_name
        if client is None and not API_KEY:
            raise ValueError(
                "OPENAI_API_KEY не задан: добавь его в "
                "apps/scoring_agent/.env"
            )
        self.client = client or OpenAI(api_key=API_KEY, base_url=BASE_URL)
        self.model = model
        self.threshold = threshold

    @classmethod
    def from_topology_file(
        cls,
        topology_path: str | Path,
        service_name: str,
        **kwargs: Any,
    ) -> "RegistryScoringAgent":
        path = Path(topology_path).expanduser().resolve()
        try:
            topology = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"не удалось прочитать topology: {path}"
            ) from exc
        if not isinstance(topology, dict):
            raise ValueError("topology должна быть json-объектом")
        return cls(topology, service_name, **kwargs)

    def score_registry(
        self,
        registry: VlsRegistry,
        target_dir: str | Path,
    ) -> VlsRegistry:
        records = [item for item in registry.all() if item.sast is not None]
        if not records:
            return registry

        payload = self._prompt_payload(records, target_dir)
        response = self.client.beta.chat.completions.parse(
            model=self.model,
            messages=[
                {"role": "system", "content": SYS_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Порог false positive: {self.threshold}. "
                        f"Оцени находки:\n{payload}"
                    ),
                },
            ],
            response_format=ScoringResponse,
        )
        parsed = response.choices[0].message.parsed
        if parsed is None:
            raise ValueError(
                "llm не вернула структурированный результат"
            )

        decisions = self._validated_decisions(parsed.items, records)
        for vulnerability in records:
            registry.upsert(
                self._with_score(
                    vulnerability,
                    decisions[vulnerability.id].score,
                )
            )
        return registry

    def _prompt_payload(
        self,
        records: list[VLS],
        target_dir: str | Path,
    ) -> str:
        metrics = extract_node_metrics(self.graph, self.service_name)
        payload = []
        for vulnerability in records:
            sast = vulnerability.sast
            assert sast is not None
            payload.append(
                {
                    "vulnerability_id": vulnerability.id,
                    "title": vulnerability.title,
                    "rule_id": sast.rule_id,
                    "file_path": sast.file_path,
                    "line": sast.line,
                    "severity": sast.severity,
                    "cwe": sast.cwe,
                    "endpoint": (
                        sast.endpoint.model_dump(mode="json")
                        if sast.endpoint is not None
                        else None
                    ),
                    "code_snippet": self._code_snippet(
                        target_dir,
                        sast.file_path,
                        sast.line,
                    ),
                    "service": self.service_name,
                    "graph_metrics": metrics.model_dump(mode="json"),
                }
            )
        return json.dumps(payload, ensure_ascii=False, indent=2)

    @staticmethod
    def _validated_decisions(
        items: list[ScoringDecision],
        records: list[VLS],
    ) -> dict[str, ScoringDecision]:
        expected = {item.id for item in records}
        decisions: dict[str, ScoringDecision] = {}
        for item in items:
            if item.vulnerability_id in decisions:
                raise ValueError(
                    f"llm продублировала id: {item.vulnerability_id}"
                )
            decisions[item.vulnerability_id] = item
        actual = set(decisions)
        if actual != expected:
            missing = sorted(expected - actual)
            unknown = sorted(actual - expected)
            raise ValueError(
                "llm вернула неверный набор id: "
                f"missing={missing}, unknown={unknown}"
            )
        return decisions

    @staticmethod
    def _with_score(vulnerability: VLS, score: float) -> VLS:
        assert vulnerability.sast is not None
        sast_data = vulnerability.sast.model_dump(mode="python")
        sast_data["score"] = score
        data = vulnerability.model_dump(mode="python")
        data["sast"] = SastBlock.model_validate(sast_data)
        return VLS.model_validate(data)

    @staticmethod
    def _code_snippet(
        target_dir: str | Path,
        file_path: str,
        line: int,
    ) -> str | None:
        target = Path(target_dir).expanduser().resolve()
        source = (target / file_path).resolve()
        try:
            source.relative_to(target)
            lines = source.read_text(encoding="utf-8").splitlines()
        except (ValueError, OSError, UnicodeDecodeError):
            return None
        start = max(0, line - 3)
        end = min(len(lines), line + 2)
        return "\n".join(
            f"{number}: {lines[number - 1]}"
            for number in range(start + 1, end + 1)
        )
