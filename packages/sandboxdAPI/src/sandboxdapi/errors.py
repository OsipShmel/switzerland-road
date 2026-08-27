from __future__ import annotations


class SandboxdApiError(Exception):
    code: str = "INTERNAL_ERROR"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail or self.code)
        self.detail = detail


# --- start_check_session ---
class SessionAlreadyActive(SandboxdApiError):
    code = "SESSION_ALREADY_ACTIVE"


class VulnerabilityNotFound(SandboxdApiError):
    code = "VULNERABILITY_NOT_FOUND"


class VulnerabilityAlreadyChecked(SandboxdApiError):
    code = "VULNERABILITY_ALREADY_CHECKED"


class InvalidRequest(SandboxdApiError):
    code = "INVALID_REQUEST"


# --- submit_check_result ---
class NoActiveSession(SandboxdApiError):
    code = "NO_ACTIVE_SESSION"


class InvalidVlsTransition(SandboxdApiError):
    code = "INVALID_VLS_TRANSITION"


class FlagNotConfirmed(SandboxdApiError):
    code = "FLAG_NOT_CONFIRMED"


# --- finish_check_session ---
class ResultNotSubmitted(SandboxdApiError):
    code = "RESULT_NOT_SUBMITTED"