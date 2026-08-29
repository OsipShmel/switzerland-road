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

    _all_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]
    _http_decorators = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
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

        # расширение выбирает нужный локатор
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

        # ast ищет ближайший обработчик вокруг строки sast
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
            endpoint = self._python_decorator(decorator, handler, source, target)
            if endpoint is not None:
                return endpoint

        parameters = self._python_parameters(handler, "django", "")
        return self._locate_django(target, handler, parameters)

    def _python_decorator(
        self,
        decorator: ast.expr,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
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
                handler.name,
                source,
                decorator.lineno,
                target,
                self._python_parameters(handler, "fastapi", path),
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
                handler.name,
                source,
                decorator.lineno,
                target,
                self._python_parameters(handler, framework, path),
            )
        return None

    def _locate_django(
        self,
        target: Path,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        parameters: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        handler_name = handler.name
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
                    self._django_methods(handler),
                    handler_name,
                    urls_file,
                    line,
                    target,
                    self._merge_parameters(
                        parameters,
                        self._path_parameters("/" + match.group("path").lstrip("/")),
                    ),
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
        # путь метода дополняется путем контроллера
        class_path = self._spring_class_path(lines, method_line)
        path = self._join_paths(class_path, path_match.group(1) if path_match else "")
        methods = [self._spring_methods[annotation_name]] if annotation_name in self._spring_methods else re.findall(
            r"RequestMethod\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)", args
        )
        declaration = self._spring_method_declaration(lines, method_line)
        handler_match = re.search(r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:throws\s+[^\{]+)?\{?", declaration)
        handler_name = handler_match.group(1) if handler_match else "unknown"
        parameters = self._spring_parameters(declaration, path)
        return self._endpoint(
            "spring",
            path,
            methods,
            handler_name,
            source,
            annotation_line,
            target,
            parameters,
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

    @staticmethod
    def _spring_method_declaration(lines: list[str], method_line: int) -> str:
        parts: list[str] = []
        balance = 0
        for text in lines[method_line - 1:method_line + 30]:
            parts.append(text.strip())
            balance += text.count("(") - text.count(")")
            if balance <= 0 and ("{" in text or ";" in text):
                break
        return " ".join(parts)

    @classmethod
    def _spring_parameters(cls, declaration: str, path: str) -> list[dict[str, Any]]:
        parameters = cls._path_parameters(path)
        annotations = {
            "RequestParam": "query",
            "PathVariable": "path",
            "RequestHeader": "header",
            "CookieValue": "cookie",
            "RequestBody": "body",
        }
        pattern = re.compile(
            r"@(?P<annotation>RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody)"
            r"(?:\s*\((?P<args>[^)]*)\))?\s+"
            r"(?:final\s+)?(?:[\w<>?,.\[\]]+\s+)+(?P<variable>[A-Za-z_]\w*)"
        )
        for match in pattern.finditer(declaration):
            args = match.group("args") or ""
            explicit_name = re.search(
                r"(?:\b(?:name|value)\s*=\s*)?['\"]([^'\"]+)['\"]",
                args,
            )
            name = explicit_name.group(1) if explicit_name else match.group("variable")
            location = annotations[match.group("annotation")]
            required = location == "path" or (
                "required = false" not in args and "defaultValue" not in args
            )
            cls._add_parameter(parameters, name, location, required)
        return parameters

    @classmethod
    def _python_parameters(
        cls,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        framework: str,
        path: str,
    ) -> list[dict[str, Any]]:
        parameters = cls._path_parameters(path)
        if framework == "fastapi":
            positional = list(handler.args.posonlyargs) + list(handler.args.args)
            defaults: list[ast.expr | None] = [None] * (
                len(positional) - len(handler.args.defaults)
            )
            defaults.extend(handler.args.defaults)
            arguments = list(zip(positional, defaults, strict=True))
            arguments.extend(
                zip(handler.args.kwonlyargs, handler.args.kw_defaults, strict=True)
            )
            path_names = {item["name"] for item in parameters}
            ignored_types = {"Request", "Response", "BackgroundTasks", "WebSocket"}
            for argument, default in arguments:
                annotation = cls._call_name(argument.annotation) if argument.annotation else ""
                if (
                    argument.arg in {"self", "cls", "request", "response"}
                    or annotation in ignored_types
                ):
                    continue
                location = "path" if argument.arg in path_names else "query"
                if isinstance(default, ast.Call):
                    marker = cls._call_name(default.func).rsplit(".", 1)[-1].lower()
                    location = {
                        "query": "query",
                        "path": "path",
                        "body": "body",
                        "form": "body",
                        "header": "header",
                        "cookie": "cookie",
                    }.get(marker, location)
                marker_required = isinstance(default, ast.Call) and any(
                    isinstance(value, ast.Constant) and value.value is Ellipsis
                    for value in default.args
                )
                required = location == "path" or default is None or (
                    isinstance(default, ast.Constant) and default.value is Ellipsis
                ) or marker_required
                cls._add_parameter(parameters, argument.arg, location, required)

        request_locations = {
            "args": "query",
            "get": "query",
            "query_params": "query",
            "form": "body",
            "post": "body",
            "json": "body",
            "headers": "header",
            "cookies": "cookie",
        }
        for node in ast.walk(handler):
            if isinstance(node, ast.Call):
                name = cls._call_name(node.func).lower().split(".")
                if (
                    len(name) >= 3
                    and name[0] == "request"
                    and name[-1] == "get"
                    and node.args
                ):
                    source_name = name[-2]
                    parameter_name = cls._constant_string(node.args[0])
                    if parameter_name and source_name in request_locations:
                        cls._add_parameter(
                            parameters,
                            parameter_name,
                            request_locations[source_name],
                            False,
                        )
            if isinstance(node, ast.Subscript):
                source_name = cls._call_name(node.value).lower().split(".")
                parameter_name = cls._subscript_string(node.slice)
                if (
                    parameter_name
                    and len(source_name) >= 2
                    and source_name[0] == "request"
                    and source_name[-1] in request_locations
                ):
                    cls._add_parameter(
                        parameters,
                        parameter_name,
                        request_locations[source_name[-1]],
                        True,
                    )
        return parameters

    @classmethod
    def _django_methods(
        cls,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[str]:
        for decorator in handler.decorator_list:
            name = cls._call_name(
                decorator.func if isinstance(decorator, ast.Call) else decorator
            )
            short_name = name.rsplit(".", 1)[-1]
            if short_name.startswith("require_") and short_name != "require_http_methods":
                method = short_name.removeprefix("require_").upper()
                if method in cls._all_methods:
                    return [method]
            if short_name == "require_http_methods" and isinstance(decorator, ast.Call):
                if decorator.args and isinstance(
                    decorator.args[0], (ast.List, ast.Tuple, ast.Set)
                ):
                    return [
                        str(item.value).upper()
                        for item in decorator.args[0].elts
                        if isinstance(item, ast.Constant) and isinstance(item.value, str)
                    ]
        return list(cls._all_methods)

    @staticmethod
    def _constant_string(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    @classmethod
    def _subscript_string(cls, node: ast.expr) -> str | None:
        return cls._constant_string(node)

    @staticmethod
    def _path_parameters(path: str) -> list[dict[str, Any]]:
        matches = re.findall(
            r"\{([A-Za-z_]\w*)\}|<(?:(?:[^:>]+):)?([A-Za-z_]\w*)>|:([A-Za-z_]\w*)",
            path,
        )
        return [
            {
                "name": next(name for name in match if name),
                "location": "path",
                "required": True,
            }
            for match in matches
        ]

    @staticmethod
    def _add_parameter(
        parameters: list[dict[str, Any]],
        name: str,
        location: str,
        required: bool,
    ) -> None:
        if not any(
            item["name"] == name and item["location"] == location
            for item in parameters
        ):
            parameters.append(
                {"name": name, "location": location, "required": required}
            )

    @staticmethod
    def _merge_parameters(
        first: list[dict[str, Any]],
        second: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        merged = list(first)
        for item in second:
            if item not in merged:
                merged.append(item)
        return merged

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
        parameters: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        parameters = parameters or []
        return {
            "framework": framework,
            "path": path,
            "http_methods": methods,
            "handler": handler,
            "declaration_file": source.relative_to(target).as_posix(),
            "declaration_line": line,
            "query_parameters": [
                item["name"] for item in parameters if item["location"] == "query"
            ],
            "parameters": parameters,
            "locator_confidence": 0.9,
            "locator_evidence": [
                f"строка sast находится внутри обработчика {handler}",
                f"маршрут объявлен в {source.relative_to(target).as_posix()}:{line}",
            ],
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
