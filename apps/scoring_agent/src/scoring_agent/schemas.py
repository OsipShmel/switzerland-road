from typing import Literal
from pydantic import BaseModel, Field


class TargetCoords(BaseModel):
    endpoint: str
    method: str
    param: str


class GraphMetrics(BaseModel):
    is_exposed: bool
    hops: int
    path: list[str]
    crit_assets: list[str]
    centrality: float


class LLMScoringItem(BaseModel):
    task_id: str
    service: str
    vuln_type: str
    context_score: float = Field(ge=0.0, le=10.0)
    priority: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "DISCARDED"]
    is_false_positive: bool
    discard_reason: str | None = None
    target: TargetCoords
    hypothesis: str
    remediation: str | None = None


class LLMScoringResponse(BaseModel):
    items: list[LLMScoringItem]


class SastBlock(BaseModel):
    tool: str = "semgrep"
    rule_id: str
    file_path: str
    line: int
    score: float
    code_snippet: str | None = None


class HumanReport(BaseModel):
    executor_name: str
    action_taken: str
    result_details: str


class VerificationStep(BaseModel):
    run_executed: bool = False
    verdict_output: Literal["confirmed", "unconfirmed", "not_tested"] = "not_tested"
    human_report: HumanReport | None = None


class VerificationHistory(BaseModel):
    dast: VerificationStep = Field(default_factory=VerificationStep)
    pentest: VerificationStep = Field(default_factory=VerificationStep)


class VLSObject(BaseModel):
    vulnerability_id: str
    title: str
    status: Literal["unchecked", "checked"] = "unchecked"
    verdict: Literal["confirmed", "unconfirmed"] | None = None
    confirmed_by: Literal["dast", "pentest-agent"] | None = None
    sast: SastBlock | None = None
    target: TargetCoords | None = None
    hypothesis: str | None = None
    verification_history: VerificationHistory = Field(default_factory=VerificationHistory)


class ScoringPipelineResult(BaseModel):
    total_count: int
    discarded_count: int
    queue: list[VLSObject]
    discarded: list[LLMScoringItem]