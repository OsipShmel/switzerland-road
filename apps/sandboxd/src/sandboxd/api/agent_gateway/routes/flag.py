from __future__ import annotations

from fastapi import APIRouter, Request
from sandboxdapi.AgentInteraction import CheckSecretFlagRequest, CheckSecretFlagResponse
from ..state import GatewayState

router = APIRouter(tags=["flag"])


@router.post("/flag/check", response_model=CheckSecretFlagResponse)
def check_secret_flag(body: CheckSecretFlagRequest, request: Request) -> CheckSecretFlagResponse:
    gw: GatewayState = request.app.state.gateway_state
    valid = gw.verify_flag(body.flag)
    if valid:
        gw.confirm_flag()
    return CheckSecretFlagResponse(valid=valid)