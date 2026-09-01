from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator
from typing import Any


class ScanEventBroker:
    """хранит короткую историю событий и раздает ее подписчикам."""

    def __init__(self, history_limit: int = 500) -> None:
        self._history_limit = history_limit
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(
            set
        )
        self._next_id: dict[str, int] = defaultdict(int)
        self._last_progress: dict[str, int] = defaultdict(int)
        self._active_scan_id: str | None = None

    @property
    def active_scan_id(self) -> str | None:
        return self._active_scan_id

    def activate(self, scan_id: str) -> None:
        self._active_scan_id = scan_id

    def events(self, scan_id: str) -> list[dict[str, Any]]:
        return list(self._history.get(scan_id, ()))

    async def publish(self, scan_id: str, event: dict[str, Any]) -> None:
        event = dict(event)
        if event.get("type") == "progress":
            progress = max(
                self._last_progress[scan_id],
                int(event.get("progress") or 0),
            )
            event["progress"] = progress
            self._last_progress[scan_id] = progress

        self._next_id[scan_id] += 1
        stored = {
            "id": self._next_id[scan_id],
            "scanId": scan_id,
            **event,
        }
        history = self._history[scan_id]
        history.append(stored)
        if len(history) > self._history_limit:
            del history[: len(history) - self._history_limit]

        for queue in tuple(self._subscribers.get(scan_id, ())):
            queue.put_nowait(stored)

    async def subscribe(
        self,
        scan_id: str,
        after_event_id: int = 0,
    ) -> AsyncIterator[dict[str, Any] | None]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers[scan_id].add(queue)
        last_event_id = after_event_id
        try:
            # история закрывает промежуток между созданием заявки и подпиской
            for event in self.events(scan_id):
                if int(event["id"]) > last_event_id:
                    last_event_id = int(event["id"])
                    yield event

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield None
                    continue
                if int(event["id"]) <= last_event_id:
                    continue
                last_event_id = int(event["id"])
                yield event
        finally:
            subscribers = self._subscribers.get(scan_id)
            if subscribers is not None:
                subscribers.discard(queue)
                if not subscribers:
                    self._subscribers.pop(scan_id, None)


scan_event_broker = ScanEventBroker()
