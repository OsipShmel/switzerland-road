from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse
from sandboxdapi.errors import SandboxdApiError

_STATUS_MAP = {
    "SESSION_ALREADY_ACTIVE": 409,
    "VULNERABILITY_NOT_FOUND": 404,
    "NO_UNCHECKED_VULNERABILITIES": 409,
    "VULNERABILITY_ALREADY_CHECKED": 409,
    "INVALID_REQUEST": 400,
    "NO_ACTIVE_SESSION": 409,
    "INVALID_VLS_TRANSITION": 409,
    "FLAG_NOT_CONFIRMED": 422,
    "RESULT_NOT_SUBMITTED": 409,
}


def sandboxd_api_error_handler(request: Request, exc: SandboxdApiError) -> JSONResponse:
    return JSONResponse(
        status_code=_STATUS_MAP.get(exc.code, 400),
        content={"error": exc.code, "detail": exc.detail},
    )