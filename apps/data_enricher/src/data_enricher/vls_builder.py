from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from vls import SastBlock, VLS


class VLSBuilder:
    """собирает vls из результатов sast."""

    def build(self, semgrep_output: Mapping[str, Any]) -> list[dict[str, Any]]:
        results = semgrep_output.get("results", [])
        if not isinstance(results, list):
            raise ValueError("Semgrep JSON field 'results' must be a list")

        records: list[dict[str, Any]] = []
        for finding in results:
            if not isinstance(finding, Mapping):
                continue
            sast = self._build_sast_block(finding)
            records.append(self._build_record(sast))
        return records

    def _build_sast_block(self, finding: Mapping[str, Any]) -> SastBlock:
        extra = self._mapping(finding.get("extra"))
        metadata = self._mapping(extra.get("metadata"))
        start = self._mapping(finding.get("start"))
        end = self._mapping(finding.get("end"))
        rule_id = str(finding.get("check_id") or "unknown-semgrep-rule")
        severity = extra.get("severity")
        fingerprint = extra.get("fingerprint")
        return SastBlock(
            rule_id=rule_id,
            file_path=str(finding.get("path") or ""),
            line=self._integer(start.get("line")),
            end_line=self._integer(end.get("line")),
            column=self._integer(start.get("col")),
            message=str(extra.get("message") or rule_id),
            severity=str(severity) if severity is not None else None,
            cwe=self._string_list(metadata.get("cwe")),
            fingerprint=str(fingerprint) if fingerprint is not None else None,
        )

    def _build_record(self, sast: SastBlock) -> dict[str, Any]:
        vls = VLS(
            id=self._build_id(sast),
            title=sast.message or sast.rule_id,
            sast=sast,
        )
        return vls.model_dump(mode="json")

    def _build_id(self, sast: SastBlock) -> str:
        identity = {
            "rule_id": sast.rule_id,
            "file_path": sast.file_path,
            "line": sast.line,
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return str(uuid5(NAMESPACE_URL, canonical))

    @staticmethod
    def _mapping(value: Any) -> Mapping[str, Any]:
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _integer(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value]
        return []
