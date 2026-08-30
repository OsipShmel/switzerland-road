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

class NoUncheckedVulnerabilities(SandboxdApiError):
    code = "NO_UNCHECKED_VULNERABILITIES"

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



_ERROR_REGISTRY: dict[str, type[SandboxdApiError]] = {
    cls.code: cls
    for cls in [
        SessionAlreadyActive, VulnerabilityNotFound, VulnerabilityAlreadyChecked,
        InvalidRequest, NoUncheckedVulnerabilities, NoActiveSession,
        InvalidVlsTransition, FlagNotConfirmed, ResultNotSubmitted,
    ]
}


def raise_for_sandboxd_error(response) -> None:

    if response.is_success:
        return
    try:
        body = response.json()
        code = body.get("error")
        detail = body.get("detail")
    except Exception:
        response.raise_for_status()
        return

    error_cls = _ERROR_REGISTRY.get(code)
    if error_cls is not None:
        raise error_cls(detail)
    response.raise_for_status()