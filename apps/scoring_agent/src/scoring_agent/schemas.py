from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field
from vls import VLS


class GraphMetrics(BaseModel):
    is_exposed: bool
    hops: int
    path: list[str]
    crit_assets: list[str]
    centrality: float


class ScoringDecision(BaseModel):
    vulnerability_id: str
    score: float = Field(ge=0.0, le=10.0)
    priority: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "DISCARDED"]
    is_false_positive: bool = False
    reason: str | None = None
    hypothesis: str | None = None
    remediation: str | None = None


class ScoringResponse(BaseModel):
    items: list[ScoringDecision]


class ScoreRequest(BaseModel):
    vulnerabilities: list[VLS]
    topology: dict
    service_name: str
    target_dir: str = "."


class ScoreResponse(BaseModel):
    vulnerabilities: list[VLS]
