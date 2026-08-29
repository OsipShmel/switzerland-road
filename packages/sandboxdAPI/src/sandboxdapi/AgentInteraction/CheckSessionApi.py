from __future__ import annotations

from enum import StrEnum
from pydantic import BaseModel, ConfigDict, Field
from vls import VLS


# --- start_check_session ---
class SessionState(StrEnum):
    ACTIVE = "active"
    FINISHED = "finished"


# depressed вроде как
# class StartCheckSessionRequest(BaseModel):
#     model_config = ConfigDict(frozen=True, extra="forbid")
#     vulnerability_id: str = Field(min_length=1)


class StartCheckSessionResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    session_id: str
    vulnerability: VLS
    state: SessionState = SessionState.ACTIVE



# --- submit_check_result ---

class Verdict(StrEnum):
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"


class ProofType(StrEnum):
    FLAG = "flag"
    NONE = "none"


class VulnerabilityReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    action_taken: str = Field(min_length=1)
    result_details: str = Field(min_length=1)


class Proof(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    type: ProofType
    details: str = Field(min_length=0)


class SubmitCheckResultRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    verdict: Verdict
    report: VulnerabilityReport
    proof: Proof


class SubmitCheckResultResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    accepted: bool
    vulnerability_id: str
    status: str  # VLSStatus.CHECKED сериализованный — так что решил держать строкой, чтобы не тянуть VLSStatus сюда ради одного поля, имей ввиду
    verdict: Verdict


# --- finish_check_session ---

class FinishCheckSessionResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    session_id: str
    state: SessionState = SessionState.FINISHED