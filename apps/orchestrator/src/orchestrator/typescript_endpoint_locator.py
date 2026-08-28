from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class _FunctionSpan:
    name: str
    start: int
    end: int


@dataclass(frozen=True)
class _RouteCall:
    method: str
    path: str
    arguments: str
    start: int
    end: int
    line: int


@dataclass
class _SourceFile:
    path: Path
    text: str
    masked: str
    functions: list[_FunctionSpan]
    routes: list[_RouteCall]
    named_imports: dict[str, tuple[Path, str]]
    namespace_imports: dict[str, Path]
    default_imports: dict[str, Path]


class TypeScriptEndpointIndex:
    """строит индекс express-маршрутов для typescript."""

    _route_pattern = re.compile(
        r"\b(?:app|router)\s*\.\s*(get|post|put|patch|delete|head|options|use)\s*\("
    )
    _ignored_parts = {
        "node_modules",
        ".git",
        "build",
        "dist",
        "coverage",
        "test",
        "tests",
        "cypress",
        "codefixes",
    }

    def __init__(self, target: Path) -> None:
        self.target = target
        self.files = self._read_sources()
        self.module_prefixes = self._build_module_prefixes()
        self.routes_by_handler = self._build_route_index()

    def find(self, source: Path, finding_line: int) -> dict[str, Any] | None:
        parsed = self.files.get(source)
        if parsed is None:
            return None
        offset = self._line_offset(parsed.text, finding_line)
        if offset is None:
            return None

        inline_routes = [route for route in parsed.routes if route.start <= offset <= route.end]
        if inline_routes:
            route = min(inline_routes, key=lambda item: item.end - item.start)
            return self._endpoint(parsed.path, route, "inline")

        handlers = [
            function
            for function in parsed.functions
            if function.start <= offset <= function.end
        ]
        if not handlers:
            return None
        handler = min(handlers, key=lambda item: item.end - item.start)
        endpoints = self.routes_by_handler.get((source, handler.name), [])
        return endpoints[0] if endpoints else None

    def _read_sources(self) -> dict[Path, _SourceFile]:
        files: dict[Path, _SourceFile] = {}
        sources = set(self.target.rglob("*.ts")) | set(self.target.rglob("*.tsx"))
        for source in sorted(sources):
            if any(part in self._ignored_parts for part in source.relative_to(self.target).parts):
                continue
            try:
                text = source.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            masked = self._mask(text)
            files[source.resolve()] = _SourceFile(
                path=source.resolve(),
                text=text,
                masked=masked,
                functions=self._functions(masked),
                routes=self._routes(text, masked),
                named_imports=self._named_imports(source, text),
                namespace_imports=self._namespace_imports(source, text),
                default_imports=self._default_imports(source, text),
            )
        return files

    def _build_module_prefixes(self) -> dict[Path, str]:
        prefixes: dict[Path, str] = {}
        for parsed in self.files.values():
            for route in parsed.routes:
                if route.method != "use":
                    continue
                tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", route.arguments))
                for local_name in tokens:
                    imported_file = parsed.default_imports.get(local_name)
                    if imported_file is not None:
                        prefixes.setdefault(imported_file, route.path)
        return prefixes

    def _build_route_index(self) -> dict[tuple[Path, str], list[dict[str, Any]]]:
        # ключ из файла и имени различает одноименные обработчики
        index: dict[tuple[Path, str], list[dict[str, Any]]] = {}
        for parsed in self.files.values():
            local_names = {function.name for function in parsed.functions}
            for route in parsed.routes:
                references = self._handler_references(parsed, route.arguments, local_names)
                for source, handler in references:
                    endpoint = self._endpoint(parsed.path, route, handler)
                    bucket = index.setdefault((source, handler), [])
                    if endpoint not in bucket:
                        bucket.append(endpoint)
        return index

    def _handler_references(
        self,
        parsed: _SourceFile,
        arguments: str,
        local_names: set[str],
    ) -> set[tuple[Path, str]]:
        references: set[tuple[Path, str]] = set()
        for match in re.finditer(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)", arguments):
            source = parsed.namespace_imports.get(match.group(1))
            if source is not None:
                references.add((source, match.group(2)))
        tokens = set(re.findall(r"\b[A-Za-z_]\w*\b", arguments))
        for name in tokens:
            named_import = parsed.named_imports.get(name)
            if named_import is not None:
                references.add(named_import)
            default_source = parsed.default_imports.get(name)
            if default_source is not None:
                references.add((default_source, name))
            if name in local_names:
                references.add((parsed.path, name))
        return references

    def _endpoint(
        self,
        declaration_file: Path,
        route: _RouteCall,
        handler: str,
    ) -> dict[str, Any]:
        methods = [] if route.method == "use" else [route.method.upper()]
        return {
            "framework": "express",
            "path": self._join_paths(
                self.module_prefixes.get(declaration_file, ""),
                route.path,
            ),
            "http_methods": methods,
            "handler": handler,
            "declaration_file": declaration_file.relative_to(self.target).as_posix(),
            "declaration_line": route.line,
        }

    @classmethod
    def _routes(cls, text: str, masked: str) -> list[_RouteCall]:
        routes: list[_RouteCall] = []
        for match in cls._route_pattern.finditer(masked):
            opening = match.end() - 1
            closing = cls._closing_delimiter(masked, opening, "(", ")")
            if closing is None:
                continue
            original_args = text[opening + 1:closing]
            masked_args = masked[opening + 1:closing]
            parts = cls._split_arguments(original_args, masked_args)
            if not parts:
                continue
            path = cls._literal_path(parts[0])
            if path is None:
                continue
            routes.append(
                _RouteCall(
                    method=match.group(1),
                    path=path,
                    arguments=",".join(parts[1:]),
                    start=match.start(),
                    end=closing,
                    line=text.count("\n", 0, match.start()) + 1,
                )
            )
        return routes

    @staticmethod
    def _functions(masked: str) -> list[_FunctionSpan]:
        patterns = [
            re.compile(
                r"\b(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\("
            ),
            re.compile(
                r"\b(?:export\s+)?(?:const|let)\s+([A-Za-z_]\w*)\s*=\s*(?:async\s*)?\("
            ),
        ]
        functions: list[_FunctionSpan] = []
        for pattern in patterns:
            for match in pattern.finditer(masked):
                opening = masked.find("{", match.end())
                if opening < 0:
                    continue
                closing = TypeScriptEndpointIndex._closing_delimiter(
                    masked,
                    opening,
                    "{",
                    "}",
                )
                if closing is not None:
                    functions.append(_FunctionSpan(match.group(1), match.start(), closing))
        return functions

    def _named_imports(self, source: Path, text: str) -> dict[str, tuple[Path, str]]:
        imports: dict[str, tuple[Path, str]] = {}
        pattern = re.compile(
            r"\bimport\s*\{(?P<names>[\s\S]*?)\}\s*from\s*['\"](?P<module>\.[^'\"]+)['\"]"
        )
        for match in pattern.finditer(text):
            imported_file = self._resolve_import(source, match.group("module"))
            if imported_file is None:
                continue
            for item in match.group("names").split(","):
                name = re.sub(r"\btype\s+", "", item).strip()
                if not name:
                    continue
                pieces = re.split(r"\s+as\s+", name)
                exported_name = pieces[0].strip()
                local_name = pieces[-1].strip()
                if re.fullmatch(r"[A-Za-z_]\w*", local_name):
                    imports[local_name] = (imported_file, exported_name)
        return imports

    def _namespace_imports(self, source: Path, text: str) -> dict[str, Path]:
        imports: dict[str, Path] = {}
        pattern = re.compile(
            r"\bimport\s+\*\s+as\s+([A-Za-z_]\w*)\s+from\s*['\"](\.[^'\"]+)['\"]"
        )
        for match in pattern.finditer(text):
            imported_file = self._resolve_import(source, match.group(2))
            if imported_file is not None:
                imports[match.group(1)] = imported_file
        return imports

    def _default_imports(self, source: Path, text: str) -> dict[str, Path]:
        imports: dict[str, Path] = {}
        pattern = re.compile(
            r"\bimport\s+([A-Za-z_]\w*)\s+from\s*['\"](\.[^'\"]+)['\"]"
        )
        for match in pattern.finditer(text):
            imported_file = self._resolve_import(source, match.group(2))
            if imported_file is not None:
                imports[match.group(1)] = imported_file
        return imports

    @staticmethod
    def _resolve_import(source: Path, module: str) -> Path | None:
        base = (source.parent / module).resolve()
        candidates = [base.with_suffix(".ts"), base / "index.ts"]
        return next((candidate for candidate in candidates if candidate.is_file()), None)

    @staticmethod
    def _literal_path(argument: str) -> str | None:
        match = re.fullmatch(r"\s*(['\"])(.*?)\1\s*", argument, re.DOTALL)
        return match.group(2) if match else None

    @staticmethod
    def _split_arguments(original: str, masked: str) -> list[str]:
        parts: list[str] = []
        start = 0
        depth = 0
        for index, character in enumerate(masked):
            if character in "([{":
                depth += 1
            elif character in ")]}":
                depth -= 1
            elif character == "," and depth == 0:
                parts.append(original[start:index].strip())
                start = index + 1
        parts.append(original[start:].strip())
        return parts

    @staticmethod
    def _closing_delimiter(
        text: str,
        opening: int,
        left: str,
        right: str,
    ) -> int | None:
        depth = 0
        for index in range(opening, len(text)):
            if text[index] == left:
                depth += 1
            elif text[index] == right:
                depth -= 1
                if depth == 0:
                    return index
        return None

    @staticmethod
    def _line_offset(text: str, line: int) -> int | None:
        if line < 1:
            return None
        offset = 0
        for _ in range(line - 1):
            newline = text.find("\n", offset)
            if newline < 0:
                return None
            offset = newline + 1
        return offset

    @staticmethod
    def _join_paths(prefix: str, path: str) -> str:
        if not prefix:
            return path
        if not path or path == "/":
            return prefix
        return "/" + "/".join(
            part.strip("/") for part in (prefix, path) if part.strip("/")
        )

    @staticmethod
    def _mask(text: str) -> str:
        # маска сохраняет позиции, но убирает строки и комментарии
        result = list(text)
        index = 0
        state = "code"
        quote = ""
        regex_class = False
        while index < len(text):
            current = text[index]
            following = text[index + 1] if index + 1 < len(text) else ""
            if state == "code" and current == "/" and following == "/":
                result[index] = result[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if state == "code" and current == "/" and following == "*":
                result[index] = result[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if state == "code" and current == "/":
                previous = text[index - 1] if index > 0 else ""
                if previous in "(=,:![{;?":
                    result[index] = " "
                    state = "regex"
                    regex_class = False
                    index += 1
                    continue
            if state == "code" and current in "'\"`":
                result[index] = " "
                quote = current
                state = "string"
                index += 1
                continue
            if state == "line_comment":
                if current == "\n":
                    state = "code"
                else:
                    result[index] = " "
                index += 1
                continue
            if state == "block_comment":
                if current == "*" and following == "/":
                    result[index] = result[index + 1] = " "
                    index += 2
                    state = "code"
                else:
                    if current != "\n":
                        result[index] = " "
                    index += 1
                continue
            if state == "string":
                if current == "\\":
                    result[index] = " "
                    if index + 1 < len(text):
                        result[index + 1] = " "
                    index += 2
                    continue
                if current == quote:
                    result[index] = " "
                    state = "code"
                elif current != "\n":
                    result[index] = " "
                index += 1
                continue
            if state == "regex":
                if current == "\\":
                    result[index] = " "
                    if index + 1 < len(text):
                        result[index + 1] = " "
                    index += 2
                    continue
                if current == "[":
                    regex_class = True
                elif current == "]":
                    regex_class = False
                elif current == "/" and not regex_class:
                    result[index] = " "
                    state = "code"
                elif current != "\n":
                    result[index] = " "
                index += 1
                continue
            index += 1
        return "".join(result)
