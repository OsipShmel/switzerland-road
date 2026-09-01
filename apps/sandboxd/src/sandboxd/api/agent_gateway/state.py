from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from uuid import uuid4

from sandboxdapi import AgentLog
from vls import VLS, VLSStatus, VLSVerdict, ConfirmedBy, VlsRegistry
from sandboxdapi.errors import (
    SessionAlreadyActive, NoActiveSession, ResultNotSubmitted,
    FlagNotConfirmed, NoUncheckedVulnerabilities,
)

from sandboxd.control_plane.gateway_client import SandboxdControlClient

@dataclass
class ActiveCheckSession:
    session_id: str
    vulnerability: VLS
    flag_confirmed: bool = False
    result_submitted: bool = False


class GatewayState:
    """
    Единственный на sandboxd объект состояния control-plane:
    В рамках PoC у нас один пентест на демона
    """

    def __init__(self, logs_dir: Path, on_flag_confirmed: Callable[[], None] | None = None) -> None:
        self._vulnerabilities: VlsRegistry = VlsRegistry()
        self.active_check: ActiveCheckSession | None = None
        self._is_target_discredited: bool = False
        self._on_flag_confirmed = on_flag_confirmed or (lambda: None)
        self._logs_dir = logs_dir
        self._logs_dir.mkdir(parents=True, exist_ok=True)

        self._control_client = SandboxdControlClient(socket_path="/run/sandboxd/control.sock")

        self._event_loop: asyncio.AbstractEventLoop | None = None


    def load_vulnerabilities(self, vls_registry: VlsRegistry) -> None:
        self._vulnerabilities = vls_registry

    # --- check-session lifecycle ---

    def start_check_session(self) -> ActiveCheckSession:
        if self.active_check is not None:
            raise SessionAlreadyActive()

        vls = self._get_next_vls()
        if vls is None:
            raise NoUncheckedVulnerabilities()

        session = ActiveCheckSession(session_id=str(uuid4()), vulnerability=vls)
        self.active_check = session
        self._log("global", {
            "level": "info", "event": "check_session_started",
            "message": "Check session started",
            "metadata": {"vulnerability_id": vls.id, "session_id": session.session_id},
        })
        return session

    def get_active_check_session(self) -> ActiveCheckSession:
        if self.active_check is None:
            raise NoActiveSession()
        return self.active_check

    def apply_check_result(self, verdict: VLSVerdict, proof_is_flag: bool, action_taken: str, result_details: str) -> VLS:
        session = self.active_check
        if session is None:
            raise NoActiveSession()
        if proof_is_flag and not session.flag_confirmed:
            raise FlagNotConfirmed()

        confirmed_by = ConfirmedBy.PENTEST_AGENT if verdict == VLSVerdict.CONFIRMED else None
        updated = session.vulnerability.model_copy(update={
            "status": VLSStatus.CHECKED,
            "verdict": verdict,
            "confirmed_by": confirmed_by,
        })
        self._vulnerabilities.upsert(updated)
        session.vulnerability = updated
        session.result_submitted = True

        self._log(self._current_log_context(), {
            "level": "info", "event": "check_result_submitted",
            "message": action_taken,
            "metadata": {"verdict": verdict.value, "result_details": result_details},
        })
        return updated

    def finish_check_session(self) -> ActiveCheckSession:
        session = self.active_check
        if session is None:
            raise NoActiveSession()
        if not session.result_submitted:
            raise ResultNotSubmitted()

        self.active_check = None
        self._log("global", {
            "level": "info", "event": "check_session_finished",
            "message": "Check session finished",
            "metadata": {"session_id": session.session_id},
        })
        return session

    # --- flag ---

    def verify_flag(self, flag: str) -> bool:
        # TODO: реальная сверка с flag-инжектором — см. открытый вопрос про key.py.
        # Пока затычка: всегда невалидно, чтобы не давать ложных confirm.
        return False

    def confirm_flag(self) -> None:
        if self.active_check is not None:
            self.active_check.flag_confirmed = True
        self._is_target_discredited = True
        self._on_flag_confirmed()

    def bind_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._event_loop = loop

    # --- logging ---

    def log(self, level: str, event: str, message: str, metadata: dict, explicit_context: str | None) -> None:
        context = "global" if explicit_context == "global" else self._current_log_context()
        self._log(context, {"level": level, "event": event, "message": message, "metadata": metadata})

    def _current_log_context(self) -> str:
        if self.active_check is not None:
            return f"check_session_{self.active_check.session_id}"
        return "global"

    def _log(self, context: str, payload: dict) -> None:
        path = self._logs_dir / f"{context}.jsonl"

        with path.open("a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "ts": time.time(),
                        **payload,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

        log = AgentLog.model_validate(payload)

        if self._event_loop is None:
            print(
                "[agent-gateway] log forwarding skipped: "
                "event loop is not bound"
            )
            return

        async def forward() -> None:
            try:
                await self._control_client.publish_log(
                    log,
                    context=context,
                )
                print(
                    f"[agent-gateway] forwarded log "
                    f"event={log.event!r} context={context!r}"
                )
            except Exception as exc:
                print(
                    f"[agent-gateway] FAILED to forward log "
                    f"event={log.event!r} context={context!r}: {exc!r}"
                )

        future = asyncio.run_coroutine_threadsafe(
            forward(),
            self._event_loop,
        )

        def _forward_done(future) -> None:
            try:
                future.result()
            except Exception as exc:
                print(
                    f"[agent-gateway] log forwarding task failed: "
                    f"{exc!r}"
                )

        future.add_done_callback(_forward_done)
    # --- vls ---

    def _get_next_vls(self) -> VLS | None:
        unchecked = [v for v in self._vulnerabilities.all() if v.status == VLSStatus.UNCHECKED]
        if not unchecked:
            return None

        def sorting_key(vls: VLS):
            sast_score = vls.sast.score if (vls.sast and vls.sast.score is not None) else 0.0
            return -sast_score, vls.id

        return min(unchecked, key=sorting_key)