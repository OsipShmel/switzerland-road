from __future__ import annotations
from enum import StrEnum
from pydantic import BaseModel, model_validator

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

# TODO!
class SastBlock(BaseModel):
    ...

class InstrumentReport(BaseModel):
    executor_name: str
    action_taken: str
    result_details: str

# сейчас для даста и пентеста один. Потенциально, все нужные поля dast'а заносятся в report, так что ес че надо допиливать
# TODO?
class VerificationStep(BaseModel):
    run_executed: bool
    verdict_output: VerdictOutput
    report: InstrumentReport | None = None


class VerificationHistory(BaseModel):
    dast: VerificationStep | None = None
    pentest: VerificationStep | None = None

class VLS(BaseModel):
    id: str
    title: str

    status: VLSStatus = VLSStatus.UNCHECKED
    verdict: VLSVerdict | None = None
    confirmed_by: ConfirmedBy | list[ConfirmedBy] | None = None

    sast: SastBlock | None = None
    verification_history: VerificationHistory

    @model_validator(mode = "after")
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

        return self

