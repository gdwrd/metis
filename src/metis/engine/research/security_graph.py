# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import Any

from metis.engine.analysis.treesitter_ast import (
    collect_tree_sitter_ast,
    normalize_analyzer_config,
    read_signature,
)
from metis.engine.analysis.treesitter_runtime import TreeSitterRuntime
from metis.engine.code_index import FunctionEntry, FunctionIndex
from metis.engine.research.models import (
    SECURITY_GRAPH_SCHEMA_VERSION,
    SecurityGraph,
    SecurityGraphEdge,
    SecurityGraphNode,
    SecurityTag,
)

GUARD_KEYWORDS = (
    "require_",
    "check_",
    "authorize",
    "permission",
    "owner",
    "tenant",
    "admin",
    "authenticated",
    "login_required",
    "jwt_required",
    "policy",
    "acl",
    "privileged",
    "secure_state",
    "lifecycle",
    "locked",
    "authorized",
    "allow_debug",
)
SOURCE_KEYWORDS = (
    "req",
    "request",
    "param",
    "params",
    "query",
    "form",
    "file",
    "files",
    "args",
    "argv",
    "stdin",
    "$_get",
    "$_post",
    "$_request",
    "$_cookie",
    "@argv",
    "$argv",
    "input",
    "environ",
    "getenv",
    "process.env",
    "env",
    "socket",
    "network",
    "http",
    "url",
    "uri",
    "ipc",
    "body",
    "headers",
    "cookie",
    "cookies",
    "msg.sender",
    "msg.value",
    "tx.origin",
    "callback",
    "work",
    "thread",
    "irq",
    "interrupt",
    "handler",
    "bus_write",
    "mmio",
    "jtag",
    "debug_req",
    "strap",
    "write_en",
    "host_wdata",
)
SINK_KEYWORDS = (
    "sql_query",
    "query",
    "queryrow",
    "mysql_query",
    "mysqli_query",
    "pg_query",
    "sqlite_query",
    "pdo.query",
    "pdo.exec",
    "db.query",
    "db.exec",
    "dbh.do",
    "execute",
    "executemany",
    "raw",
    "system",
    "check_output",
    "popen",
    "spawn",
    "spawn_sync",
    "child_process",
    "function",
    "eval",
    "exec",
    "execsync",
    "shell_exec",
    "passthru",
    "proc_open",
    "backticks",
    "open",
    "readfile",
    "fopen",
    "send_file",
    "urlopen",
    "requests.get",
    "requests.post",
    "fetch",
    "http.get",
    "http.post",
    "axios.get",
    "axios.post",
    "pickle.loads",
    "yaml.load",
    "marshal.load",
    "loads",
    "deserialize",
    "unserialize",
    "memcpy",
    "strncpy",
    "strcpy",
    "sprintf",
    "free",
    "kfree",
    "delete",
    "drop",
    "destroy",
    "release",
    "register_write",
    "write_reg",
    "mmio_write",
    "csr_write",
    "privilege",
    "debug_enable",
    "call",
    "delegatecall",
    "staticcall",
    "boot_key",
    "seed",
    "secret",
    "key",
    "fuse",
    "otp",
)
SANITIZER_KEYWORDS = (
    "sanitize",
    "validate",
    "escape",
    "escapeshellarg",
    "escapeshellcmd",
    "htmlspecialchars",
    "canonical",
    "normalize",
    "safe_join",
    "allowlist",
    "whitelist",
    "parameterize",
    "prepare",
    "bind_param",
    "bindvalue",
    "quote",
    "real_escape_string",
    "intval",
    "filter_input",
    "parse_url",
    "new_url",
    "zeroize",
    "memset_s",
    "clear",
)
CONFIG_KEYWORDS = ("config", "settings", "environ", "getenv")
TEXT_METADATA_EXTENSIONS = {
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".rs",
    ".sv",
    ".svh",
    ".v",
    ".vh",
    ".php",
    ".phps",
    ".phtm",
    ".phtml",
    ".phpt",
    ".pht",
    ".php2",
    ".php3",
    ".php4",
    ".php5",
    ".php6",
    ".php7",
    ".php8",
    ".inc",
    ".pl",
    ".pm",
    ".cgi",
}
CONTROL_STATEMENT_NAMES = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
}
TEXT_CALL_EXCLUDE_NAMES = CONTROL_STATEMENT_NAMES | {
    "module",
    "endmodule",
    "always",
    "assign",
}


@dataclass(frozen=True)
class _PythonFunctionMetadata:
    file_id: str
    language: str
    symbol: str
    line: int
    end_line: int | None
    decorators: tuple[str, ...]
    route: str | None
    route_decorator: str | None
    parameters: tuple[str, ...]
    returns: tuple[str, ...]
    call_names: tuple[str, ...]
    imports: tuple[str, ...]
    config_refs: tuple[str, ...]
    node_type: str = "function"

    @property
    def qualified_name(self) -> str:
        return f"{self.file_id}::{self.symbol}"

    @property
    def guards(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    _normalized_name(name)
                    for name in (*self.decorators, *self.call_names)
                    if _matches_keyword(name, GUARD_KEYWORDS)
                    and not _is_route_decorator(name)
                }
            )
        )


class SecurityGraphBuilder:
    def __init__(self, repository) -> None:
        self._repository = repository

    def load_or_build(
        self,
        root: str | Path | None = None,
        *,
        rebuild: bool = False,
    ) -> SecurityGraph:
        root_path = self._root_path(root)
        function_index = self._repository.load_function_index() or FunctionIndex()
        current_hashes = self._current_file_hashes(function_index, root_path)
        graph_path = Path(self._repository.get_security_graph_path())
        if not rebuild and graph_path.exists():
            try:
                graph = SecurityGraph.model_validate_json(
                    graph_path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                graph = None
            if (
                graph is not None
                and graph.schema_version == SECURITY_GRAPH_SCHEMA_VERSION
                and graph.analysis_root == str(root_path)
                and graph.file_hashes == current_hashes
            ):
                return graph
        return self.build(
            root_path,
            function_index=function_index,
            file_hashes=current_hashes,
        )

    def build(
        self,
        root: str | Path | None = None,
        *,
        function_index: FunctionIndex | None = None,
        file_hashes: dict[str, str] | None = None,
    ) -> SecurityGraph:
        root_path = self._root_path(root)
        function_index = function_index or self._repository.load_function_index()
        function_index = function_index or FunctionIndex()
        current_hashes = file_hashes or self._current_file_hashes(
            function_index,
            root_path,
        )
        codebase_path = Path(self._repository._config.codebase_path).resolve()
        python_metadata = self._scan_python_metadata(root_path, codebase_path)
        text_metadata = self._scan_text_metadata(root_path, codebase_path)
        plugin_metadata = self._scan_plugin_metadata(root_path, codebase_path)
        all_metadata = [
            *python_metadata.functions,
            *text_metadata.functions,
            *plugin_metadata.functions,
        ]
        metadata_by_qname = {item.qualified_name: item for item in all_metadata}

        nodes_by_id: dict[str, SecurityGraphNode] = {}
        edges: list[SecurityGraphEdge] = []
        indexed_qnames: set[str] = set()
        for entry in sorted(
            function_index.functions.values(),
            key=lambda item: item.qualified_name,
        ):
            if not _entry_under_root(entry, root_path, codebase_path):
                continue
            metadata = metadata_by_qname.get(entry.qualified_name)
            node = self._node_from_entry(entry, metadata)
            nodes_by_id[node.id] = node
            indexed_qnames.add(entry.qualified_name)

        for metadata in all_metadata:
            if metadata.qualified_name in indexed_qnames:
                continue
            node = self._node_from_metadata(metadata)
            nodes_by_id[node.id] = node

        for entry in sorted(
            function_index.functions.values(),
            key=lambda item: item.qualified_name,
        ):
            source_id = _function_node_id(entry.qualified_name)
            if source_id not in nodes_by_id:
                continue
            for callee in sorted(entry.callees):
                edges.append(
                    SecurityGraphEdge(
                        source=source_id,
                        target=_function_node_id(callee),
                        kind="call",
                    )
                )

        self._add_metadata_nodes_and_edges(nodes_by_id, edges, python_metadata)
        self._add_metadata_nodes_and_edges(nodes_by_id, edges, text_metadata)
        self._add_metadata_nodes_and_edges(nodes_by_id, edges, plugin_metadata)
        graph = SecurityGraph(
            analysis_root=str(root_path),
            project_root_hash=_project_root_hash(current_hashes),
            file_hashes=dict(sorted(current_hashes.items())),
            nodes=sorted(nodes_by_id.values(), key=lambda item: item.id),
            edges=sorted(
                _dedupe_edges(edges),
                key=lambda item: (item.source, item.kind, item.target),
            ),
            metadata={
                "source": "function_index+python_ast+text+plugin_treesitter",
                "root": str(root_path),
            },
        )
        self.write(graph)
        return graph

    def write(self, graph: SecurityGraph) -> None:
        graph_path = Path(self._repository.get_security_graph_path())
        graph_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = graph_path.with_suffix(graph_path.suffix + ".tmp")
        tmp_path.write_text(
            json.dumps(graph.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp_path, graph_path)

    def _root_path(self, root: str | Path | None) -> Path:
        return self._repository.resolve_inside_codebase(
            root or self._repository._config.codebase_path,
            purpose="Security graph root",
        )

    def _current_file_hashes(
        self,
        function_index: FunctionIndex,
        root_path: Path,
    ) -> dict[str, str]:
        codebase_path = Path(self._repository._config.codebase_path).resolve()
        if function_index.file_hashes:
            scoped_hashes = {
                os.path.normpath(str(file_path)): str(file_hash)
                for file_path, file_hash in sorted(function_index.file_hashes.items())
                if (
                    resolved_path := _resolve_graph_file(
                        str(file_path),
                        codebase_path,
                    )
                ).exists()
                and _path_under_root(resolved_path, root_path)
            }
        else:
            scoped_hashes = {}
        hashes: dict[str, str] = {}
        hash_extensions = sorted(
            set(self._repository.get_all_supported_code_extensions())
            | TEXT_METADATA_EXTENSIONS
        )
        for path in _iter_source_files(root_path, hash_extensions):
            file_id = _file_id_for_path(path, codebase_path)
            hashes[file_id] = _hash_file(path)
        for file_id, file_hash in scoped_hashes.items():
            hashes.setdefault(file_id, file_hash)
        return dict(sorted(hashes.items()))

    def _scan_python_metadata(
        self,
        root_path: Path,
        codebase_path: Path,
    ) -> "_PythonMetadata":
        functions: list[_PythonFunctionMetadata] = []
        imports_by_file: dict[str, tuple[str, ...]] = {}
        for path in _iter_source_files(root_path, [".py"]):
            file_id = _file_id_for_path(path, codebase_path)
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue
            module_imports = tuple(sorted(_imports_for_module(tree)))
            imports_by_file[file_id] = module_imports
            for node in ast.walk(tree):
                if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
                    continue
                decorators = tuple(
                    name
                    for decorator in node.decorator_list
                    if (name := _call_name(decorator))
                )
                route_decorator = next(
                    (name for name in decorators if _is_route_decorator(name)),
                    None,
                )
                route = _route_for(node)
                call_names = tuple(sorted(_calls_for_node(node)))
                functions.append(
                    _PythonFunctionMetadata(
                        file_id=file_id,
                        language="python",
                        symbol=node.name,
                        line=int(getattr(node, "lineno", 1) or 1),
                        end_line=getattr(node, "end_lineno", None),
                        decorators=decorators,
                        route=route,
                        route_decorator=route_decorator,
                        parameters=tuple(_parameters_for_node(node)),
                        returns=tuple(_returns_for_node(node)),
                        call_names=call_names,
                        imports=module_imports,
                        config_refs=tuple(sorted(_config_refs_for_node(node))),
                    )
                )
        return _PythonMetadata(functions=functions, imports_by_file=imports_by_file)

    def _scan_text_metadata(
        self,
        root_path: Path,
        codebase_path: Path,
    ) -> "_PythonMetadata":
        functions: list[_PythonFunctionMetadata] = []
        imports_by_file: dict[str, tuple[str, ...]] = {}
        for path in _iter_source_files(root_path, list(TEXT_METADATA_EXTENSIONS)):
            if path.suffix.lower() not in TEXT_METADATA_EXTENSIONS:
                continue
            file_id = _file_id_for_path(path, codebase_path)
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            language = _text_language_for_path(path)
            imports_by_file[file_id] = tuple(sorted(_text_imports(source, language)))
            if language in {"systemverilog", "verilog"}:
                functions.extend(
                    _systemverilog_modules_for_file(
                        file_id=file_id,
                        source=source,
                        language=language,
                    )
                )
                continue
            if language in {"php", "perl"}:
                functions.extend(
                    _server_script_units_for_file(
                        file_id=file_id,
                        source=source,
                        language=language,
                    )
                )
                continue
            functions.extend(
                _text_functions_for_file(
                    file_id=file_id,
                    source=source,
                    language=language,
                )
            )
        return _PythonMetadata(functions=functions, imports_by_file=imports_by_file)

    def _scan_plugin_metadata(
        self,
        root_path: Path,
        codebase_path: Path,
    ) -> "_PythonMetadata":
        functions: list[_PythonFunctionMetadata] = []
        imports_by_file: dict[str, tuple[str, ...]] = {}
        skipped_extensions = {".py"} | TEXT_METADATA_EXTENSIONS
        for path in _iter_source_files(
            root_path,
            self._repository.get_all_supported_code_extensions(),
        ):
            if path.suffix.lower() in skipped_extensions:
                continue
            plugin = self._repository.get_plugin_for_path(path.name)
            if plugin is None:
                continue
            language = _parser_language_for_path(path, str(plugin.get_name() or ""))
            analyzer_config = _plugin_analyzer_config(plugin)
            if (
                not language
                or not analyzer_config.function_node_types
                or not analyzer_config.call_node_types
            ):
                continue
            file_id = _file_id_for_path(path, codebase_path)
            try:
                source_text = path.read_text(encoding="utf-8", errors="ignore")
                parsed = TreeSitterRuntime(language).parse_file(str(codebase_path), file_id)
            except (OSError, RuntimeError, UnicodeDecodeError, ValueError):
                continue
            source = source_text.encode("utf-8", errors="ignore")
            ast_index = collect_tree_sitter_ast(
                parsed.tree.root_node,
                source,
                analyzer_config,
            )
            imports_by_file[file_id] = tuple(sorted(_text_imports(source_text, language)))
            used_qnames: set[str] = set()
            for variants in ast_index.functions.values():
                for function in variants:
                    signature = read_signature(function.node, source)
                    body = _slice_lines(
                        source_text,
                        function.line_start,
                        function.line_end,
                    )
                    call_names = {call.symbol for call in function.calls if call.symbol}
                    call_names.update(
                        check.symbol or check.detail
                        for check in function.checks
                        if check.symbol or check.detail
                    )
                    call_names.update(_generic_security_markers(body))
                    qname = _dedup_text_qname(
                        file_id,
                        function.name,
                        function.line_start,
                        used_qnames,
                    )
                    functions.append(
                        _PythonFunctionMetadata(
                            file_id=qname.rsplit("::", 1)[0],
                            language=language,
                            symbol=qname.rsplit("::", 1)[-1].split("@", 1)[0],
                            line=function.line_start,
                            end_line=function.line_end,
                            decorators=(),
                            route=None,
                            route_decorator=None,
                            parameters=tuple(_text_parameters(signature)),
                            returns=("value",) if re.search(r"\breturn\b", body) else (),
                            call_names=tuple(sorted(call_names)),
                            imports=(),
                            config_refs=tuple(sorted(_text_config_refs(body))),
                        )
                    )
        return _PythonMetadata(functions=functions, imports_by_file=imports_by_file)

    def _node_from_entry(
        self,
        entry: FunctionEntry,
        metadata: _PythonFunctionMetadata | None,
    ) -> SecurityGraphNode:
        call_names = _combined_call_names(entry, metadata)
        parameters = (
            list(metadata.parameters)
            if metadata is not None
            else _parameters_from_signature(entry.signature)
        )
        returns = list(metadata.returns) if metadata is not None else []
        tags = _security_tags_for_function(
            file=entry.file,
            line=metadata.line if metadata is not None else entry.start_line,
            symbol=entry.name,
            signature=entry.signature,
            call_names=call_names,
            metadata=metadata,
        )
        return SecurityGraphNode(
            id=_function_node_id(entry.qualified_name),
            type="function",
            file=entry.file,
            line=(metadata.line if metadata is not None else entry.start_line) or None,
            end_line=(metadata.end_line if metadata is not None else entry.end_line)
            or None,
            symbol=entry.name,
            language=entry.language,
            signature=entry.signature,
            parameters=parameters,
            returns=returns,
            tags=tags,
            metadata=_function_metadata(call_names, metadata),
        )

    def _node_from_metadata(
        self,
        metadata: _PythonFunctionMetadata,
    ) -> SecurityGraphNode:
        tags = _security_tags_for_function(
            file=metadata.file_id,
            line=metadata.line,
            symbol=metadata.symbol,
            signature="",
            call_names=metadata.call_names,
            metadata=metadata,
        )
        return SecurityGraphNode(
            id=_function_node_id(metadata.qualified_name),
            type=metadata.node_type,
            file=metadata.file_id,
            line=metadata.line,
            end_line=metadata.end_line,
            symbol=metadata.symbol,
            language=metadata.language,
            signature=None,
            parameters=list(metadata.parameters),
            returns=list(metadata.returns),
            tags=tags,
            metadata=_function_metadata(metadata.call_names, metadata),
        )

    def _add_metadata_nodes_and_edges(
        self,
        nodes_by_id: dict[str, SecurityGraphNode],
        edges: list[SecurityGraphEdge],
        python_metadata: "_PythonMetadata",
    ) -> None:
        function_ids_by_file_and_symbol = {
            (metadata.file_id, metadata.symbol): _function_node_id(
                metadata.qualified_name
            )
            for metadata in python_metadata.functions
        }
        for file_id, imports in python_metadata.imports_by_file.items():
            for import_name in imports:
                import_id = f"import:{file_id}:{import_name}"
                nodes_by_id.setdefault(
                    import_id,
                    SecurityGraphNode(
                        id=import_id,
                        type="import",
                        file=file_id,
                        symbol=import_name,
                        metadata={"module": import_name},
                    ),
                )
        for metadata in python_metadata.functions:
            source_id = _function_node_id(metadata.qualified_name)
            if source_id not in nodes_by_id:
                continue
            if metadata.route:
                route_id = f"route:{metadata.file_id}:{metadata.line}:{metadata.route}"
                nodes_by_id.setdefault(
                    route_id,
                    SecurityGraphNode(
                        id=route_id,
                        type="route",
                        file=metadata.file_id,
                        line=metadata.line,
                        symbol=metadata.symbol,
                        tags=[
                            SecurityTag(
                                kind="entrypoint",
                                value=metadata.route,
                                detail="HTTP route registration",
                                file=metadata.file_id,
                                line=metadata.line,
                                symbol=metadata.symbol,
                            )
                        ],
                        metadata={
                            "route_path": metadata.route,
                            "route_group": _route_group(
                                metadata.route,
                                metadata.file_id,
                            ),
                            "decorator": metadata.route_decorator,
                        },
                    ),
                )
                edges.append(
                    SecurityGraphEdge(
                        source=route_id,
                        target=source_id,
                        kind="framework_registration",
                        metadata={"framework": "route"},
                    )
                )
            for import_name in metadata.imports:
                edges.append(
                    SecurityGraphEdge(
                        source=source_id,
                        target=f"import:{metadata.file_id}:{import_name}",
                        kind="import",
                    )
                )
            for call_name in metadata.call_names:
                target_id = function_ids_by_file_and_symbol.get(
                    (metadata.file_id, _normalized_name(call_name))
                )
                if target_id is None or target_id == source_id:
                    continue
                edges.append(
                    SecurityGraphEdge(
                        source=source_id,
                        target=target_id,
                        kind="call",
                    )
                )
            for config_ref in metadata.config_refs:
                config_id = f"config:{metadata.file_id}:{config_ref}"
                nodes_by_id.setdefault(
                    config_id,
                    SecurityGraphNode(
                        id=config_id,
                        type="config",
                        file=metadata.file_id,
                        symbol=config_ref,
                        tags=[
                            SecurityTag(
                                kind="source",
                                value=config_ref,
                                detail="configuration reference",
                                file=metadata.file_id,
                                symbol=metadata.symbol,
                                confidence=0.7,
                            )
                        ],
                        metadata={"reference": config_ref},
                    ),
                )
                edges.append(
                    SecurityGraphEdge(
                        source=source_id,
                        target=config_id,
                        kind="configuration",
                    )
                )


@dataclass(frozen=True)
class _PythonMetadata:
    functions: list[_PythonFunctionMetadata]
    imports_by_file: dict[str, tuple[str, ...]]


def _text_language_for_path(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {
        ".php",
        ".phps",
        ".phtm",
        ".phtml",
        ".phpt",
        ".pht",
        ".php2",
        ".php3",
        ".php4",
        ".php5",
        ".php6",
        ".php7",
        ".php8",
        ".inc",
    }:
        return "php"
    if suffix in {".pl", ".pm", ".cgi"}:
        return "perl"
    if suffix in {".cc", ".cpp", ".hpp"}:
        return "cpp"
    if suffix == ".rs":
        return "rust"
    if suffix in {".sv", ".svh"}:
        return "systemverilog"
    if suffix in {".v", ".vh"}:
        return "verilog"
    return "c"


def _parser_language_for_path(path: Path, plugin_name: str) -> str:
    if path.suffix.lower() in {".jsx", ".tsx"}:
        return "tsx"
    return plugin_name


def _plugin_analyzer_config(plugin) -> Any:
    try:
        return normalize_analyzer_config(plugin.get_analyzer_config())
    except Exception:
        return normalize_analyzer_config({})


def _text_imports(source: str, language: str) -> set[str]:
    imports: set[str] = set()
    if language in {"c", "cpp"}:
        for match in re.finditer(
            r"^\s*#\s*include\s+[<\"]([^>\"]+)[>\"]", source, re.M
        ):
            imports.add(match.group(1))
    elif language == "rust":
        for match in re.finditer(r"^\s*use\s+([^;]+);", source, re.M):
            imports.add(match.group(1).strip())
    elif language in {"systemverilog", "verilog"}:
        for match in re.finditer(r"^\s*`include\s+\"([^\"]+)\"", source, re.M):
            imports.add(match.group(1))
    elif language == "php":
        for match in re.finditer(
            r"\b(?:include|include_once|require|require_once)\s*\(?\s*['\"]([^'\"]+)['\"]",
            source,
        ):
            imports.add(match.group(1))
    elif language == "perl":
        for match in re.finditer(r"^\s*(?:use|require)\s+([A-Za-z_][\w:]*)", source, re.M):
            imports.add(match.group(1))
    return imports


def _server_script_units_for_file(
    *,
    file_id: str,
    source: str,
    language: str,
) -> list[_PythonFunctionMetadata]:
    functions = _server_script_functions_for_file(
        file_id=file_id,
        source=source,
        language=language,
    )
    script_source = _server_script_runtime_source(source, language)
    script_markers = tuple(sorted(_server_script_markers(script_source, language)))
    if functions and not script_markers:
        return functions
    line_count = len(script_source.splitlines()) or 1
    symbol = Path(file_id).stem or "script"
    script_metadata = _PythonFunctionMetadata(
        file_id=file_id,
        language=language,
        symbol=symbol,
        line=1,
        end_line=line_count,
        decorators=(),
        route=None,
        route_decorator=None,
        parameters=(),
        returns=(),
        call_names=script_markers,
        imports=(),
        config_refs=tuple(sorted(_text_config_refs(script_source))),
    )
    if functions:
        return [*functions, script_metadata]
    return [script_metadata]


def _server_script_runtime_source(source: str, language: str) -> str:
    if language == "perl":
        return source.split("\n__END__", 1)[0]
    return source


def _server_script_functions_for_file(
    *,
    file_id: str,
    source: str,
    language: str,
) -> list[_PythonFunctionMetadata]:
    if language == "php":
        pattern = re.compile(r"(?im)^\s*function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
    else:
        pattern = re.compile(r"(?im)^\s*sub\s+([A-Za-z_]\w*)\b")
    matches = list(pattern.finditer(source))
    functions: list[_PythonFunctionMetadata] = []
    used_qnames: set[str] = set()
    lines = source.splitlines()
    for index, match in enumerate(matches):
        symbol = match.group(1)
        line = _line_number_for_offset(source, match.start())
        if language == "php":
            end_line = _brace_end_line(source, match.end())
            body = _slice_lines(source, line, end_line)
            parameters = tuple(_text_parameters(match.group(0)))
        else:
            brace = source.find("{", match.end())
            next_sub = matches[index + 1].start() if index + 1 < len(matches) else -1
            if brace >= 0 and (next_sub < 0 or brace < next_sub):
                end_line = _brace_end_line(source, brace)
            else:
                next_line = (
                    _line_number_for_offset(source, next_sub)
                    if next_sub >= 0
                    else len(lines) + 1
                )
                end_line = max(line, next_line - 1)
            body = _slice_lines(source, line, end_line)
            parameters = ()
        qname = _dedup_text_qname(file_id, symbol, line, used_qnames)
        functions.append(
            _PythonFunctionMetadata(
                file_id=qname.rsplit("::", 1)[0],
                language=language,
                symbol=qname.rsplit("::", 1)[-1].split("@", 1)[0],
                line=line,
                end_line=end_line,
                decorators=(),
                route=None,
                route_decorator=None,
                parameters=parameters,
                returns=("value",) if re.search(r"\breturn\b", body) else (),
                call_names=tuple(sorted(_server_script_markers(body, language))),
                imports=(),
                config_refs=tuple(sorted(_text_config_refs(body))),
            )
        )
    return functions


def _text_functions_for_file(
    *,
    file_id: str,
    source: str,
    language: str,
) -> list[_PythonFunctionMetadata]:
    if language == "rust":
        pattern = re.compile(
            r"(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)\s*\("
        )
    else:
        pattern = re.compile(
            r"(?m)^\s*(?:[A-Za-z_][\w\s\*]*\s+)+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
        )
    functions: list[_PythonFunctionMetadata] = []
    used_qnames: set[str] = set()
    for match in pattern.finditer(source):
        symbol = match.group(1)
        if symbol in CONTROL_STATEMENT_NAMES:
            continue
        line = _line_number_for_offset(source, match.start())
        end_line = _brace_end_line(source, match.end() - 1)
        body = _slice_lines(source, line, end_line)
        signature = source[match.start() : match.end()].split("{", 1)[0].strip()
        qname = _dedup_text_qname(file_id, symbol, line, used_qnames)
        metadata = _PythonFunctionMetadata(
            file_id=qname.rsplit("::", 1)[0],
            language=language,
            symbol=qname.rsplit("::", 1)[-1].split("@", 1)[0],
            line=line,
            end_line=end_line,
            decorators=(),
            route=None,
            route_decorator=None,
            parameters=tuple(_text_parameters(signature)),
            returns=("value",) if re.search(r"\breturn\b", body) else (),
            call_names=tuple(sorted(_text_call_names(body))),
            imports=(),
            config_refs=tuple(sorted(_text_config_refs(body))),
        )
        functions.append(metadata)
    return functions


def _systemverilog_modules_for_file(
    *,
    file_id: str,
    source: str,
    language: str,
) -> list[_PythonFunctionMetadata]:
    modules: list[_PythonFunctionMetadata] = []
    used_qnames: set[str] = set()
    pattern = re.compile(r"(?m)^\s*module\s+([A-Za-z_]\w*)\b")
    for match in pattern.finditer(source):
        symbol = match.group(1)
        line = _line_number_for_offset(source, match.start())
        end_match = re.search(r"(?m)^\s*endmodule\b", source[match.end() :])
        if end_match is None:
            end_line = len(source.splitlines()) or line
            body = source[match.start() :]
        else:
            end_offset = match.end() + end_match.end()
            end_line = _line_number_for_offset(source, end_offset)
            body = source[match.start() : end_offset]
        qname = _dedup_text_qname(file_id, symbol, line, used_qnames)
        modules.append(
            _PythonFunctionMetadata(
                file_id=qname.rsplit("::", 1)[0],
                language=language,
                symbol=qname.rsplit("::", 1)[-1].split("@", 1)[0],
                line=line,
                end_line=end_line,
                decorators=(),
                route=None,
                route_decorator=None,
                parameters=tuple(_systemverilog_ports(body)),
                returns=(),
                call_names=tuple(sorted(_text_identifiers(body))),
                imports=(),
                config_refs=(),
                node_type="module",
            )
        )
    return modules


def _dedup_text_qname(
    file_id: str,
    symbol: str,
    line: int,
    used_qnames: set[str],
) -> str:
    base = f"{file_id}::{symbol}"
    qname = base
    if qname in used_qnames:
        qname = f"{base}@{line}"
    used_qnames.add(qname)
    return qname


def _line_number_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, max(0, offset)) + 1


def _brace_end_line(source: str, opening_brace_offset: int) -> int:
    depth = 0
    for idx, char in enumerate(
        source[opening_brace_offset:], start=opening_brace_offset
    ):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth <= 0:
                return _line_number_for_offset(source, idx)
    return len(source.splitlines()) or _line_number_for_offset(
        source, opening_brace_offset
    )


def _slice_lines(source: str, start_line: int, end_line: int | None) -> str:
    lines = source.splitlines()
    end = end_line or len(lines)
    return "\n".join(lines[max(0, start_line - 1) : end])


def _text_parameters(signature: str) -> list[str]:
    match = re.search(r"\((.*?)\)", signature, re.S)
    if not match:
        return []
    params: list[str] = []
    for raw in match.group(1).split(","):
        cleaned = raw.strip()
        if not cleaned or cleaned == "void":
            continue
        name = cleaned.split("=")[0].strip().split()[-1].strip("*&")
        if name and name not in params:
            params.append(name)
    return params


def _systemverilog_ports(body: str) -> list[str]:
    ports: list[str] = []
    for match in re.finditer(
        r"\b(?:input|output|inout)\b\s+(?:\w+\s+)*([A-Za-z_]\w*)", body
    ):
        name = match.group(1)
        if name not in ports:
            ports.append(name)
    return ports


def _text_call_names(body: str) -> set[str]:
    names: set[str] = set()
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body):
        name = match.group(1)
        if name not in TEXT_CALL_EXCLUDE_NAMES:
            names.add(name)
    return names


def _server_script_markers(body: str, language: str) -> set[str]:
    names: set[str] = set()
    if language == "php":
        for match in re.finditer(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b", body, re.I):
            names.add(match.group(0))
        for match in re.finditer(r"\$([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\(", body):
            receiver = match.group(1).lower()
            method = match.group(2).lower()
            if method in {"query", "do", "exec", "execute"}:
                names.add(f"{receiver}.{method}")
                names.add("sql_query")
            elif method in {"system", "shell_exec", "passthru", "popen", "proc_open"}:
                names.add(method)
        for match in re.finditer(
            r"\b(mysql_query|mysqli_query|pg_query|sqlite_query|system|shell_exec|passthru|proc_open|popen|eval)\s*\(",
            body,
            re.I,
        ):
            names.add(match.group(1))
        if re.search(r"\b(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\(", body, re.I):
            names.add("sql_query")
        return names

    for match in re.finditer(r"[@$]ARGV\b|\$ARGV\s*\[", body):
        names.add(match.group(0))
    for match in re.finditer(r"\$ENV\s*\{", body):
        names.add("$ENV")
    for match in re.finditer(r"\$([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\(", body):
        receiver = match.group(1).lower()
        method = match.group(2).lower()
        if method in {"do", "prepare", "execute"}:
            names.add(f"{receiver}.{method}")
            names.add("sql_query")
    for match in re.finditer(r"\b(system|open|opendir|exec|eval)\s*\(", body, re.I):
        names.add(match.group(1))
    if re.search(r"`[^`]+`|\bqx\s*[/({]", body):
        names.add("exec")
    return names


def _generic_security_markers(body: str) -> set[str]:
    markers: set[str] = set()
    lowered = body.lower()
    for keyword in SOURCE_KEYWORDS + SINK_KEYWORDS + SANITIZER_KEYWORDS:
        normalized = keyword.lower()
        if normalized == "function":
            continue
        if "." in normalized or "$" in normalized:
            if normalized in lowered:
                markers.add(keyword)
            continue
        if re.search(rf"\b{re.escape(normalized)}\b", lowered):
            markers.add(keyword)
    return markers


def _text_identifiers(body: str) -> set[str]:
    return {
        match.group(0)
        for match in re.finditer(r"\b[A-Za-z_]\w*\b", body)
        if match.group(0) not in TEXT_CALL_EXCLUDE_NAMES
    }


def _text_config_refs(body: str) -> set[str]:
    return {
        name
        for name in _text_identifiers(body)
        if _matches_keyword(name, CONFIG_KEYWORDS)
    }


def _function_node_id(qualified_name: str) -> str:
    return f"function:{qualified_name}"


def _function_metadata(
    call_names: tuple[str, ...] | list[str],
    metadata: _PythonFunctionMetadata | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"call_names": sorted(set(call_names))}
    if metadata is None:
        return result
    result.update(
        {
            "decorators": list(metadata.decorators),
            "route_path": metadata.route,
            "route_group": (
                _route_group(metadata.route, metadata.file_id)
                if metadata.route
                else None
            ),
            "route_decorator": metadata.route_decorator,
            "guards": list(metadata.guards),
            "imports": list(metadata.imports),
            "config_refs": list(metadata.config_refs),
        }
    )
    return result


def _security_tags_for_function(
    *,
    file: str,
    line: int,
    symbol: str,
    signature: str,
    call_names: tuple[str, ...],
    metadata: _PythonFunctionMetadata | None,
) -> list[SecurityTag]:
    behavior_items = [*call_names]
    context_items = [symbol, signature, *call_names]
    if metadata is not None:
        behavior_items.extend(metadata.parameters)
        behavior_items.extend(metadata.config_refs)
        context_items.extend(metadata.decorators)
        context_items.extend(metadata.parameters)
        context_items.extend(metadata.config_refs)
    tags: list[SecurityTag] = []
    if metadata is not None and metadata.route:
        tags.append(
            SecurityTag(
                kind="entrypoint",
                value=metadata.route,
                detail="HTTP route handler",
                file=file,
                line=line,
                symbol=symbol,
            )
        )
        tags.append(
            SecurityTag(
                kind="framework",
                value="route",
                detail=metadata.route_decorator,
                file=file,
                line=line,
                symbol=symbol,
            )
        )
    for value in _matching_source_values(behavior_items):
        tags.append(
            SecurityTag(
                kind="source",
                value=value,
                detail="heuristic source marker",
                file=file,
                line=line,
                symbol=symbol,
                confidence=0.7,
            )
        )
    for value in _matching_values(behavior_items, SINK_KEYWORDS):
        tags.append(
            SecurityTag(
                kind="sink",
                value=value,
                detail="heuristic sink marker",
                file=file,
                line=line,
                symbol=symbol,
                confidence=0.7,
            )
        )
    for value in _matching_values(context_items, GUARD_KEYWORDS):
        if _is_route_decorator(value):
            continue
        tags.append(
            SecurityTag(
                kind="guard",
                value=_normalized_name(value),
                detail="heuristic guard marker",
                file=file,
                line=line,
                symbol=symbol,
                confidence=0.8,
            )
        )
    for value in _matching_values(context_items, SANITIZER_KEYWORDS):
        tags.append(
            SecurityTag(
                kind="sanitizer",
                value=_normalized_name(value),
                detail="heuristic sanitizer marker",
                file=file,
                line=line,
                symbol=symbol,
                confidence=0.7,
            )
        )
    return _dedupe_tags(tags)


def _matching_values(values: list[str] | tuple[str, ...], keywords: tuple[str, ...]):
    matches: list[str] = []
    for value in values:
        if _matches_keyword(value, keywords):
            matches.append(value)
    return sorted(set(matches))


def _matching_source_values(values: list[str] | tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    for value in values:
        if _matches_source_keyword(value):
            matches.append(value)
    return sorted(set(matches))


def _matches_keyword(value: str | None, keywords: tuple[str, ...]) -> bool:
    lowered = str(value or "").lower()
    return any(keyword in lowered for keyword in keywords)


def _matches_source_keyword(value: str | None) -> bool:
    lowered = str(value or "").lower()
    for keyword in SOURCE_KEYWORDS:
        normalized = keyword.lower()
        if any(char in normalized for char in ".$@"):
            if normalized in lowered:
                return True
            continue
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(normalized)}(?![A-Za-z0-9_])", lowered):
            return True
    return False


def _dedupe_tags(tags: list[SecurityTag]) -> list[SecurityTag]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[SecurityTag] = []
    for tag in tags:
        key = (tag.kind, tag.value, tag.symbol)
        if key in seen:
            continue
        seen.add(key)
        result.append(tag)
    return result


def _dedupe_edges(edges: list[SecurityGraphEdge]) -> list[SecurityGraphEdge]:
    seen: set[tuple[str, str, str]] = set()
    result: list[SecurityGraphEdge] = []
    for edge in edges:
        key = (edge.source, edge.target, edge.kind)
        if key in seen:
            continue
        seen.add(key)
        result.append(edge)
    return result


def _iter_source_files(root: Path, supported_exts: list[str]) -> list[Path]:
    supported = {ext.lower() for ext in supported_exts}
    if not root.exists():
        return []
    result: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or ".metis" in path.parts:
            continue
        if path.suffix.lower() in supported:
            result.append(path)
    return sorted(result)


def _hash_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _project_root_hash(file_hashes: dict[str, str]) -> str:
    payload = json.dumps(dict(sorted(file_hashes.items())), sort_keys=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def _file_id_for_path(path: Path, codebase_path: Path) -> str:
    try:
        return path.resolve().relative_to(codebase_path).as_posix()
    except ValueError:
        try:
            return path.resolve().relative_to(codebase_path.parent).as_posix()
        except ValueError:
            return path.as_posix()


def _entry_under_root(
    entry: FunctionEntry,
    root_path: Path,
    codebase_path: Path,
) -> bool:
    path = _resolve_graph_file(entry.file, codebase_path)
    return path.exists() and _path_under_root(path, root_path)


def _combined_call_names(
    entry: FunctionEntry,
    metadata: _PythonFunctionMetadata | None,
) -> tuple[str, ...]:
    call_names = set(entry.call_names)
    if metadata is not None:
        call_names.update(metadata.call_names)
    return tuple(sorted(call_names))


def _path_under_root(path: Path, root_path: Path) -> bool:
    try:
        path.resolve().relative_to(root_path)
        return True
    except ValueError:
        return False


def _resolve_graph_file(file_path: str, codebase_path: Path) -> Path:
    path = Path(file_path)
    if path.is_absolute():
        return path.resolve()
    codebase_candidate = (codebase_path / path).resolve()
    if codebase_candidate.exists():
        return codebase_candidate
    parent_candidate = (codebase_path.parent / path).resolve()
    if parent_candidate.exists():
        return parent_candidate
    return parent_candidate


def _imports_for_module(tree: ast.Module) -> set[str]:
    imports: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


def _calls_for_node(node: ast.AsyncFunctionDef | ast.FunctionDef) -> set[str]:
    calls: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _call_name(child)
            if name:
                calls.add(name)
                calls.add(_normalized_name(name))
    return calls


def _config_refs_for_node(node: ast.AsyncFunctionDef | ast.FunctionDef) -> set[str]:
    refs: set[str] = set()
    for child in ast.walk(node):
        name = _call_name(child)
        if name and _matches_keyword(name, CONFIG_KEYWORDS):
            refs.add(name)
        if isinstance(child, ast.Attribute):
            attr_name = _call_name(child)
            if attr_name and _matches_keyword(attr_name, CONFIG_KEYWORDS):
                refs.add(attr_name)
    return refs


def _parameters_for_node(node: ast.AsyncFunctionDef | ast.FunctionDef) -> list[str]:
    args = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    names = [arg.arg for arg in args]
    if node.args.vararg is not None:
        names.append(node.args.vararg.arg)
    if node.args.kwarg is not None:
        names.append(node.args.kwarg.arg)
    return names


def _returns_for_node(node: ast.AsyncFunctionDef | ast.FunctionDef) -> list[str]:
    if node.returns is not None:
        try:
            return [ast.unparse(node.returns)]
        except Exception:
            return ["annotation"]
    if any(
        isinstance(child, ast.Return) and child.value is not None
        for child in ast.walk(node)
    ):
        return ["value"]
    return []


def _parameters_from_signature(signature: str) -> list[str]:
    match = re.search(r"\((.*?)\)", signature or "")
    if not match:
        return []
    params = []
    for raw in match.group(1).split(","):
        name = raw.strip().split(":", 1)[0].split("=", 1)[0].strip()
        if name:
            params.append(name)
    return params


def _route_for(node: ast.AsyncFunctionDef | ast.FunctionDef) -> str | None:
    for decorator in node.decorator_list:
        name = _call_name(decorator)
        if not _is_route_decorator(name):
            continue
        route = _first_string_argument(decorator)
        if route:
            return route
    return None


def _is_route_decorator(name: str | None) -> bool:
    if not name:
        return False
    normalized = _normalized_name(name).lower()
    return normalized in {"route", "get", "post", "put", "patch", "delete"} or (
        "." in name and normalized == "route"
    )


def _route_group(route: str, fallback: str) -> str:
    cleaned = route.strip()
    parts = [part for part in cleaned.split("/") if part and not part.startswith("<")]
    return parts[0] if parts else Path(fallback).stem


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _first_string_argument(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    for keyword in node.keywords:
        if keyword.arg not in {"path", "rule", "route"}:
            continue
        value = keyword.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
    return None


def _normalized_name(name: str) -> str:
    return name.rsplit(".", 1)[-1]
