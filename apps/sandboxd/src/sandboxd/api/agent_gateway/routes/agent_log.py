from __future__ import annotations

from fastapi import APIRouter, Request
from sandboxdapi.AgentInteraction import AgentLog, AgentLogAcceptedResponse
from ..state import GatewayState

router = APIRouter(tags=["log"])


@router.post("/log", response_model=AgentLogAcceptedResponse)
def log(body: AgentLog, request: Request) -> AgentLogAcceptedResponse:
    gw: GatewayState = request.app.state.gateway_state
    gw.log(
        level=body.level.value, event=body.event, message=body.message,
        metadata=body.metadata, explicit_context=(body.context.value if body.context else None),
    )
    return AgentLogAcceptedResponse()