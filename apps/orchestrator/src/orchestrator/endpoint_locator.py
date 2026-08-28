from __future__ import annotations

import ast
import copy
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .typescript_endpoint_locator import TypeScriptEndpointIndex


class EndpointLocator:
    """ищет маршрут обработчика для sast-находки."""

    _http_decorators = {"get", "post", "put", "patch", "delete", "head", "options"}
    _spring_methods = {
        "GetMapping": "GET",
        "PostMapping": "POST",
        "PutMapping": "PUT",
        "PatchMapping": "PATCH",
        "DeleteMapping": "DELETE",
    }

    def enrich(
        self,
        target_dir: str | Path,
        semgrep_output: Mapping[str, Any],
    ) -> dict[str, Any]:
        target = Path(target_dir).expanduser().resolve()
        enriched = copy.deepcopy(dict(semgrep_output))
        results = enriched.get("results", [])
        if not isinstance(results, list):
            return enriched

        ts_index = TypeScriptEndpointIndex(target) if self._has_typescript_findings(results) else None

        for finding in results:
            if not isinstance(finding, dict):
                continue
            endpoint = self._locate_finding(target, finding, ts_index)
            if endpoint is not None:
                finding["endpoint"] = endpoint
        return enriched

    def _locate_finding(
        self,
        target: Path,
        finding: Mapping[str, Any],
        ts_index: TypeScriptEndpointIndex | None,
    ) -> dict[str, Any] | None:
        source = self._source_path(target, finding.get("path"))
        line = self._finding_line(finding)
        if source is None or line is None:
            return None

        suffix = source.suffix.lower()
        if suffix == ".py":
            return self._locate_python(target, source, line)
        if suffix == ".java":
            return self._locate_spring(target, source, line)
        if suffix in {".ts", ".tsx"} and ts_index is not None:
            return ts_index.find(source, line)
        return None

    @staticmethod
    def _has_typescript_findings(results: list[Any]) -> bool:
        return any(
            isinstance(finding, Mapping)
            and isinstance(finding.get("path"), str)
            and Path(finding["path"]).suffix.lower() in {".ts", ".tsx"}
            for finding in results
        )

    @staticmethod
    def _source_path(target: Path, value: Any) -> Path | None:
        if not isinstance(value, str) or not value:
            return None
        candidate = (target / value).resolve()
        try:
            candidate.relative_to(target)
        except ValueError:
            return None
        return candidate if candidate.is_file() else None

    @staticmethod
    def _finding_line(finding: Mapping[str, Any]) -> int | None:
        start = finding.get("start")
        if not isinstance(start, Mapping):
            return None
        try:
            line = int(start.get("line"))
        except (TypeError, ValueError):
            return None
        return line if line > 0 else None

    def _locate_python(
        self,
        target: Path,
        source: Path,
        finding_line: int,
    ) -> dict[str, Any] | None:
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            return None

        handlers = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.lineno <= finding_line <= (node.end_lineno or node.lineno)
        ]
        if not handlers:
            return None
        handler = min(handlers, key=lambda node: (node.end_lineno or node.lineno) - node.lineno)

        for decorator in handler.decorator_list:
            endpoint = self._python_decorator(decorator, handler.name, source, target)
            if endpoint is not None:
                return endpoint

        return self._locate_django(target, handler.name)

    def _python_decorator(
        self,
        decorator: ast.expr,
        handler_name: str,
        source: Path,
        target: Path,
    ) -> dict[str, Any] | None:
        if not isinstance(decorator, ast.Call):
            return None
        name = self._call_name(decorator.func)
        short_name = name.rsplit(".", 1)[-1]

        if short_name in self._http_decorators:
            path = self._string_argument(decorator, "path")
            if path is None:
                return None
            return self._endpoint(
                "fastapi",
                path,
                [short_name.upper()],
                handler_name,
                source,
                decorator.lineno,
                target,
            )

        if short_name in {"route", "api_route"}:
            path = self._string_argument(decorator, "path", "rule")
            if path is None:
                return None
            methods = self._string_list_keyword(decorator, "methods") or ["GET"]
            framework = "flask" if short_name == "route" else "fastapi"
            return self._endpoint(
                framework,
                path,
                methods,
                handler_name,
                source,
                decorator.lineno,
                target,
            )
        return None

    def _locate_django(self, target: Path, handler_name: str) -> dict[str, Any] | None:
        pattern = re.compile(
            rf"\b(?P<kind>path|re_path)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*"
            rf"(?:[A-Za-z_]\w*\.)*{re.escape(handler_name)}(?:\.as_view\(\))?\b"
        )
        for urls_file in sorted(target.rglob("urls.py")):
            try:
                content = urls_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            match = pattern.search(content)
            if match:
                line = content.count("\n", 0, match.start()) + 1
                return self._endpoint(
                    "django",
                    "/" + match.group("path").lstrip("/"),
                    [],
                    handler_name,
                    urls_file,
                    line,
                    target,
                )
        return None

    def _locate_spring(
        self,
        target: Path,
        source: Path,
        finding_line: int,
    ) -> dict[str, Any] | None:
        try:
            lines = source.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            return None
        method_line = self._spring_method_line(lines, finding_line)
        if method_line is None:
            return None

        annotation = self._spring_annotation(lines, method_line)
        if annotation is None:
            return None
        annotation_line, annotation_text = annotation
        mapping = re.search(
            r"@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\b(?P<args>[\s\S]*)",
            annotation_text,
        )
        if mapping is None:
            return None

        annotation_name = mapping.group(1)
        args = mapping.group("args")
        path_match = re.search(r"['\"]([^'\"]+)['\"]", args)
        if path_match is None:
            return None
        class_path = self._spring_class_path(lines, method_line)
        path = self._join_paths(class_path, path_match.group(1))
        methods = [self._spring_methods[annotation_name]] if annotation_name in self._spring_methods else re.findall(
            r"RequestMethod\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)", args
        )
        handler_match = re.search(r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws\s+[^\{]+)?\{?", lines[method_line - 1])
        handler_name = handler_match.group(1) if handler_match else "unknown"
        return self._endpoint(
            "spring",
            path,
            methods,
            handler_name,
            source,
            annotation_line,
            target,
        )

    @staticmethod
    def _spring_method_line(lines: list[str], finding_line: int) -> int | None:
        method_pattern = re.compile(
            r"\b(?:public|protected|private)\s+(?:static\s+)?(?:[\w<>?,.\[\]]+\s+)+[A-Za-z_]\w*\s*\([^;]*\)"
        )
        for line_number in range(min(finding_line, len(lines)), max(0, finding_line - 200), -1):
            if method_pattern.search(lines[line_number - 1]):
                return line_number
        return None

    def _spring_class_path(self, lines: list[str], method_line: int) -> str:
        for line_number in range(method_line - 1, 0, -1):
            if not re.search(r"\bclass\s+[A-Za-z_]\w*", lines[line_number - 1]):
                continue
            annotation = self._spring_annotation(lines, line_number)
            if annotation is None:
                return ""
            mapping = re.search(
                r"@RequestMapping\b[\s\S]*?['\"]([^'\"]+)['\"]",
                annotation[1],
            )
            return mapping.group(1) if mapping else ""
        return ""

    @staticmethod
    def _spring_annotation(lines: list[str], method_line: int) -> tuple[int, str] | None:
        collected: list[str] = []
        first_line = method_line
        balance = 0
        for line_number in range(method_line - 1, max(0, method_line - 20), -1):
            text = lines[line_number - 1].strip()
            if not text:
                if collected:
                    break
                continue
            collected.insert(0, text)
            first_line = line_number
            balance += text.count("(") - text.count(")")
            if text.startswith("@") and balance <= 0:
                joined = " ".join(collected)
                if re.search(r"@(\w+Mapping)\b", joined):
                    return first_line, joined
                collected = []
                balance = 0
        return None

    @staticmethod
    def _call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = EndpointLocator._call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    @staticmethod
    def _string_argument(call: ast.Call, *keywords: str) -> str | None:
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            return call.args[0].value
        for keyword in call.keywords:
            if keyword.arg in keywords and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                return keyword.value.value
        return None

    @staticmethod
    def _string_list_keyword(call: ast.Call, name: str) -> list[str]:
        for keyword in call.keywords:
            if keyword.arg != name or not isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                continue
            return [
                str(item.value).upper()
                for item in keyword.value.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            ]
        return []

    @staticmethod
    def _endpoint(
        framework: str,
        path: str,
        methods: list[str],
        handler: str,
        source: Path,
        line: int,
        target: Path,
    ) -> dict[str, Any]:
        return {
            "framework": framework,
            "path": path,
            "http_methods": methods,
            "handler": handler,
            "declaration_file": source.relative_to(target).as_posix(),
            "declaration_line": line,
        }

    @staticmethod
    def _join_paths(prefix: str, path: str) -> str:
        if not prefix:
            return path
        if not path:
            return prefix
        return "/" + "/".join(
            part.strip("/") for part in (prefix, path) if part.strip("/")
        )
