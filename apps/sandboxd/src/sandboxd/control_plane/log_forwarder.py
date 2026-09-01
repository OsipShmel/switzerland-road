from __future__ import annotations

import asyncio
import time

from sandboxdapi.AgentInteraction import AgentLog, ExplicitLogContext, LogLevel

from sandboxd.control_plane.supervisor_client import SupervisorClient


class SupervisorLogForwarder:
    """Thread-safe, non-blocking bridge from sandboxd runtime logs to supervisor."""

    def __init__(self, supervisor: SupervisorClient) -> None:
        self._supervisor = supervisor
        self._queue: asyncio.Queue[AgentLog | None] = asyncio.Queue()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._worker: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._worker is not None and not self._worker.done():
            return
        self._loop = asyncio.get_running_loop()
        self._worker = asyncio.create_task(self._run(), name="sandboxd-supervisor-log-forwarder")

    def emit(
        self,
        *,
        level: LogLevel,
        event: str,
        message: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        """Safe to call from orchestrator/Docker worker threads."""
        log = AgentLog(
            level=level,
            event=event,
            message=message,
            metadata={
                "timestamp": time.time(),
                **(metadata or {}),
            },
            context=ExplicitLogContext.GLOBAL,
        )

        loop = self._loop
        if loop is None or loop.is_closed():
            return

        loop.call_soon_threadsafe(self._queue.put_nowait, log)

    async def stop(self) -> None:
        worker = self._worker
        if worker is None:
            return

        await self._queue.put(None)
        await worker
        self._worker = None

    async def _run(self) -> None:
        while True:
            log = await self._queue.get()
            try:
                if log is None:
                    return
                try:
                    await self._supervisor.send_log(log)
                except Exception as exc:
                    # Supervisor logging must never make sandbox startup fail.
                    print(f"[sandboxd] supervisor log forwarding failed: {exc}")
            finally:
                self._queue.task_done()
