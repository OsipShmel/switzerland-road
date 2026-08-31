from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .models import VLS


class VlsRegistry:
    """хранит vls по уникальному идентификатору."""

    def __init__(self, initial: Iterable[VLS] | None = None) -> None:
        self._items: dict[str, VLS] = {}
        for vuln in initial or []:
            self._items[vuln.id] = vuln

    @classmethod
    def from_records(
        cls,
        records: Iterable[VLS | Mapping[str, Any]],
    ) -> "VlsRegistry":
        """валидирует записи перед добавлением."""
        return cls(
            record if isinstance(record, VLS) else VLS.model_validate(record)
            for record in records
        )

    def __getitem__(self, vulnerability_id: str) -> VLS:
        if vulnerability_id not in self._items:
            raise KeyError(f"Vulnerability with id {vulnerability_id} not found")
        return self._items[vulnerability_id]

    def get(self, vulnerability_id: str) -> VLS | None:
        return self._items.get(vulnerability_id)

    def all(self) -> list[VLS]:
        return list(self._items.values())

    def to_records(self) -> list[dict[str, Any]]:
        """готовит registry для json."""
        return [item.model_dump(mode="json") for item in self._items.values()]

    def upsert(self, vls: VLS) -> bool:
        self._items[vls.id] = vls
        return True

    def __len__(self) -> int:
        return len(self._items)
