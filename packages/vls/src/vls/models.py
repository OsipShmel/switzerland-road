from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PositiveInt, model_validator


class VLSStatus(StrEnum):
    UNCHECKED = "unchecked"
    CHECKED = "checked"


class VLSVerdict(StrEnum):
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"


class ConfirmedBy(StrEnum):
    DAST = "dast"
    PENTEST_AGENT = "pentest-agent"


class VerdictOutput(StrEnum):
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    NOT_TESTED = "not_tested"


class EndpointReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: str
    path: str
    http_methods: list[str] = Field(default_factory=list)
    handler: str
    declaration_file: str
    declaration_line: PositiveInt
    query_parameters: list[str] = Field(default_factory=list)
    locator_confidence: float = Field(default=0, ge=0, le=1)
    locator_evidence: list[str] = Field(default_factory=list)


class SastBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: Literal["semgrep"] = "semgrep"
    rule_id: str = Field(min_length=1)
    file_path: str = Field(min_length=1)
    line: PositiveInt
    end_line: PositiveInt | None = None
    column: PositiveInt | None = None
    message: str | None = None
    severity: str | None = None
    cwe: list[str] = Field(default_factory=list)
    fingerprint: str | None = None
    score: float | None = Field(default=None, ge=0, le=10)
    endpoint: EndpointReference | None = None


class InstrumentReport(BaseModel):
    executor_name: str
    action_taken: str
    result_details: str


class DastReport(InstrumentReport):
    target_url: str | None = None
    http_method: str | None = None
    parameter: str | None = None
    payload: str | None = None
    evidence: str | None = None


class PentestReport(InstrumentReport):
    session_id: str | None = None
    attempts: list[str] = Field(default_factory=list)
    exploit_chain: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)


class _VerificationStep(BaseModel):
    run_executed: bool = False
    verdict_output: VerdictOutput = VerdictOutput.NOT_TESTED

    @model_validator(mode="after")
    def check_state(self) -> "_VerificationStep":
        human_report = getattr(self, "human_report", None)

        if not self.run_executed:
            if self.verdict_output != VerdictOutput.NOT_TESTED:
                raise ValueError("невыполненный этап должен иметь not_tested")
            if human_report is not None:
                raise ValueError("невыполненный этап не должен иметь отчет")

        if self.run_executed:
            if self.verdict_output == VerdictOutput.NOT_TESTED:
                raise ValueError("выполненный этап должен иметь результат")
            if human_report is None:
                raise ValueError("выполненный этап должен иметь отчет")

        return self


class DastVerificationStep(_VerificationStep):
    human_report: DastReport | None = None


class PentestVerificationStep(_VerificationStep):
    human_report: PentestReport | None = None


class VerificationHistory(BaseModel):
    dast: DastVerificationStep = Field(default_factory=DastVerificationStep)
    pentest: PentestVerificationStep = Field(
        default_factory=PentestVerificationStep
    )


class VLS(BaseModel):
    id: str
    title: str

    status: VLSStatus = VLSStatus.UNCHECKED
    verdict: VLSVerdict | None = None
    confirmed_by: ConfirmedBy | list[ConfirmedBy] | None = None

    sast: SastBlock | None = None
    verification_history: VerificationHistory = Field(
        default_factory=VerificationHistory
    )

    @model_validator(mode="after")
    def check_state_matrix(self) -> "VLS":
        if self.status == VLSStatus.UNCHECKED:
            if self.verdict is not None or self.confirmed_by is not None:
                raise ValueError(
                    "status=unchecked requires verdict=null and confirmed_by=null"
                )

        if self.status == VLSStatus.CHECKED and self.verdict is None:
            raise ValueError("status=checked requires a verdict")

        if self.verdict == VLSVerdict.CONFIRMED and self.confirmed_by is None:
            raise ValueError("verdict=confirmed requires confirmed_by")

        if self.verdict == VLSVerdict.UNCONFIRMED and self.confirmed_by is not None:
            raise ValueError("verdict=unconfirmed requires confirmed_by=null")

        if isinstance(self.confirmed_by, list) and not self.confirmed_by:
            raise ValueError("confirmed_by list must not be empty")

        return self
