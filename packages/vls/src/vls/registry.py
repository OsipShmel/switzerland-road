from __future__ import annotations
from vls.models import VLS


class VlsRegistry:
    """VLS массив — используется во всей системе.
    Обновления происходят по upsert схеме (простая перезапись)."""

    def __init__(self, initial: list[VLS] | None = None) -> None:
        self._items: dict[str, VLS] = {}
        for vuln in initial or []:
            self._items[vuln.id] = vuln


    def __getitem__(self, vulnerability_id: str) -> VLS:
        if vulnerability_id not in self._items:
            raise KeyError(f"Vulnerability with id {vulnerability_id} not found")
        return self._items[vulnerability_id]

    def get(self, vulnerability_id: str) -> VLS | None:
      """DEPRESSED – надеюсь еще никто не юзал, на всяк оставляю а то логика поломается"""
      return self._items.get(vulnerability_id)

    def all(self) -> list[VLS]:
        return list(self._items.values())

    def upsert(self, vls: VLS) -> bool:
        self._items[vls.id] = vls
        return True
