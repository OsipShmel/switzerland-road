from __future__ import annotations

from fastapi import APIRouter, Request

from sandboxdapi.AgentInteraction import (
    StartCheckSessionResponse, SessionState,
    SubmitCheckResultRequest, SubmitCheckResultResponse, Verdict, ProofType,
    FinishCheckSessionResponse,
)
from vls import VLSVerdict
from ..state import GatewayState

router = APIRouter(tags=["check-session"])


def _gw(request: Request) -> GatewayState:
    return request.app.state.gateway_state


@router.post("/check-sessions", response_model=StartCheckSessionResponse)
def start_check_session(request: Request) -> StartCheckSessionResponse:
    session = _gw(request).start_check_session()
    return StartCheckSessionResponse(session_id=session.session_id, vulnerability=session.vulnerability, state=SessionState.ACTIVE)


@router.get("/check-sessions/current", response_model=StartCheckSessionResponse)
def get_check_session(request: Request) -> StartCheckSessionResponse:
    """DEPRESSED по идее, но из контракта забыл своевременно выпилить так что вот"""
    session = _gw(request).get_active_check_session()
    return StartCheckSessionResponse(session_id=session.session_id, vulnerability=session.vulnerability, state=SessionState.ACTIVE)


@router.post("/check-sessions/current/result", response_model=SubmitCheckResultResponse)
def submit_check_result(body: SubmitCheckResultRequest, request: Request) -> SubmitCheckResultResponse:
    verdict = VLSVerdict(body.verdict.value)
    updated = _gw(request).apply_check_result(
        verdict=verdict,
        proof_is_flag=(body.proof.type == ProofType.FLAG),
        action_taken=body.report.action_taken,
        result_details=body.report.result_details,
    )
    return SubmitCheckResultResponse(
        accepted=True, vulnerability_id=updated.id, status=updated.status.value, verdict=Verdict(verdict.value),
    )


@router.post("/check-sessions/current/finish", response_model=FinishCheckSessionResponse)
def finish_check_session(request: Request) -> FinishCheckSessionResponse:
    session = _gw(request).finish_check_session()
    return FinishCheckSessionResponse(session_id=session.session_id)