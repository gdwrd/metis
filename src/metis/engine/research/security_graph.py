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
from metis.engine.research.parser_inventory import (
    CONFIG_GRAPH_EXTENSIONS,
    CONFIG_GRAPH_PATTERNS,
    runtime_language_for,
)
from metis.engine.research.rules import (
    CONFIG_KEYWORDS,
    GUARD_KEYWORDS,
    SANITIZER_KEYWORDS,
    SINK_KEYWORDS,
    SOURCE_KEYWORDS,
    VULNERABILITY_RULES,
)

GRAPH_METADATA_SOURCE = (
    "function_index+python_ast+text+plugin_treesitter+config_resource"
)
GRAPH_CAPABILITY_VERSION = "parser_config_resource_v4"
SCRIPT_ROUTE_EXCLUDED_SUFFIXES = (".inc", ".pm")
ROUTE_DETECTOR_CAPABILITY = {
    "version": 2,
    "framework_registration_languages": (
        "csharp",
        "go",
        "javascript",
        "jsx",
        "php",
        "ruby",
        "rust",
        "tsx",
        "typescript",
    ),
    "framework_annotation_languages": ("csharp", "java", "kotlin", "rust", "scala"),
    "file_route_languages": ("javascript", "jsx", "tsx", "typescript"),
    "script_route_languages": ("php", "perl"),
    "script_route_excluded_suffixes": SCRIPT_ROUTE_EXCLUDED_SUFFIXES,
    "detector_kinds": (
        "file_route",
        "framework_annotation",
        "framework_dsl",
        "framework_command",
        "framework_minimal_api",
        "framework_route",
        "framework_signature",
        "script_handler",
        "server_script",
    ),
    "script_handler_languages": ("bash", "lua", "perl"),
    "signature_route_languages": ("go", "java", "kotlin", "rust", "scala"),
    "dsl_route_languages": ("ruby",),
}
TEXT_METADATA_EXTENSIONS = {
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".c++",
    ".hpp",
    ".hh",
    ".hxx",
    ".ipp",
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
SERVER_SCRIPT_TEXT_EXTENSIONS = {
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
CONFIG_METADATA_EXTENSIONS = CONFIG_GRAPH_EXTENSIONS
CONFIG_METADATA_PATTERNS = CONFIG_GRAPH_PATTERNS


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
        expected_metadata = self._graph_metadata(root_path)
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
                and graph.metadata.get("capability_fingerprint")
                == expected_metadata["capability_fingerprint"]
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
        config_metadata = self._scan_config_metadata(root_path, codebase_path)
        all_metadata = [
            *python_metadata.functions,
            *text_metadata.functions,
            *plugin_metadata.functions,
            *config_metadata.functions,
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
        self._add_metadata_nodes_and_edges(nodes_by_id, edges, config_metadata)
        graph = SecurityGraph(
            analysis_root=str(root_path),
            project_root_hash=_project_root_hash(current_hashes),
            file_hashes=dict(sorted(current_hashes.items())),
            nodes=sorted(nodes_by_id.values(), key=lambda item: item.id),
            edges=sorted(
                _dedupe_edges(edges),
                key=lambda item: (item.source, item.kind, item.target),
            ),
            metadata=self._graph_metadata(root_path),
        )
        self.write(graph)
        return graph

    def _graph_metadata(self, root_path: Path) -> dict[str, Any]:
        return {
            "source": GRAPH_METADATA_SOURCE,
            "root": str(root_path),
            "capability_version": GRAPH_CAPABILITY_VERSION,
            "capability_fingerprint": _graph_capability_fingerprint(self._repository),
        }

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
            | CONFIG_METADATA_EXTENSIONS
            | CONFIG_METADATA_PATTERNS
            | set(_repository_supported_path_patterns(self._repository))
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
        skipped_extensions = {".py"} | (
            TEXT_METADATA_EXTENSIONS - SERVER_SCRIPT_TEXT_EXTENSIONS
        )
        for path in _iter_source_files(
            root_path,
            _repository_supported_path_tokens(self._repository),
        ):
            if path.suffix.lower() in skipped_extensions:
                continue
            if _is_config_metadata_path(path):
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
                parsed = TreeSitterRuntime(language).parse_file(
                    str(codebase_path), file_id
                )
            except (OSError, RuntimeError, UnicodeDecodeError, ValueError):
                continue
            source = source_text.encode("utf-8", errors="ignore")
            ast_index = collect_tree_sitter_ast(
                parsed.tree.root_node,
                source,
                analyzer_config,
            )
            imports_by_file[file_id] = tuple(
                sorted(_text_imports(source_text, language))
            )
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
                    route, route_decorator = _framework_route_for_function(
                        file_id=file_id,
                        language=language,
                        source=source_text,
                        body=body,
                        signature=signature,
                        symbol=function.name,
                        line=function.line_start,
                    )
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
                            route=route,
                            route_decorator=route_decorator,
                            parameters=tuple(_text_parameters(signature)),
                            returns=("value",)
                            if re.search(r"\breturn\b", body)
                            else (),
                            call_names=tuple(sorted(call_names)),
                            imports=(),
                            config_refs=tuple(sorted(_text_config_refs(body))),
                        )
                    )
        return _PythonMetadata(functions=functions, imports_by_file=imports_by_file)

    def _scan_config_metadata(
        self,
        root_path: Path,
        codebase_path: Path,
    ) -> "_PythonMetadata":
        functions: list[_PythonFunctionMetadata] = []
        for path in _iter_source_files(
            root_path,
            sorted(CONFIG_METADATA_EXTENSIONS | CONFIG_METADATA_PATTERNS),
        ):
            if not _is_config_metadata_path(path):
                continue
            file_id = _file_id_for_path(path, codebase_path)
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            functions.extend(
                _config_nodes_for_file(
                    file_id=file_id,
                    source=source,
                    language=_config_language_for_path(path),
                )
            )
        return _PythonMetadata(functions=functions, imports_by_file={})

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
                                detail=_entrypoint_registration_detail(
                                    metadata.route_decorator
                                ),
                                file=metadata.file_id,
                                line=metadata.line,
                                symbol=metadata.symbol,
                                confidence=_route_detector_confidence(
                                    metadata.route_decorator
                                ),
                            )
                        ],
                        metadata={
                            "route_path": metadata.route,
                            "route_group": _route_group(
                                metadata.route,
                                metadata.file_id,
                            ),
                            "decorator": metadata.route_decorator,
                            "detector": metadata.route_decorator,
                            "detector_confidence": _route_detector_confidence(
                                metadata.route_decorator
                            ),
                        },
                    ),
                )
                edges.append(
                    SecurityGraphEdge(
                        source=route_id,
                        target=source_id,
                        kind="framework_registration",
                        metadata={
                            "framework": metadata.route_decorator or "route",
                            "detector": metadata.route_decorator,
                            "detector_confidence": _route_detector_confidence(
                                metadata.route_decorator
                            ),
                        },
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
                                detail="configuration reference; detector=config_reference",
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
    if suffix in {".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".ipp"}:
        return "cpp"
    if suffix == ".rs":
        return "rust"
    if suffix in {".sv", ".svh"}:
        return "systemverilog"
    if suffix in {".v", ".vh"}:
        return "verilog"
    return "c"


def _is_config_metadata_path(path: Path) -> bool:
    suffix = path.suffix.lower()
    name = path.name.lower()
    return suffix in CONFIG_METADATA_EXTENSIONS or name in CONFIG_METADATA_PATTERNS


def _config_language_for_path(path: Path) -> str:
    suffix = path.suffix.lower()
    name = path.name.lower()
    if name == "dockerfile" or suffix == ".dockerfile":
        return "dockerfile"
    if suffix in {".tf", ".tfvars", ".hcl"}:
        return "terraform"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".json":
        return "json"
    return suffix.lstrip(".") or name


def _parser_language_for_path(path: Path, plugin_name: str) -> str:
    return runtime_language_for(plugin_name, path)


def _repository_supported_path_tokens(repository) -> list[str]:
    tokens = set(repository.get_all_supported_code_extensions())
    tokens.update(_repository_supported_path_patterns(repository))
    return sorted(tokens)


def _repository_supported_path_patterns(repository) -> list[str]:
    try:
        return [
            str(pattern).lower()
            for pattern, _plugin in repository._config.ext_pattern_plugin_map
        ]
    except Exception:
        return []


def _graph_capability_fingerprint(repository) -> str:
    payload = {
        "capability_version": GRAPH_CAPABILITY_VERSION,
        "source": GRAPH_METADATA_SOURCE,
        "text_metadata_extensions": sorted(TEXT_METADATA_EXTENSIONS),
        "server_script_text_extensions": sorted(SERVER_SCRIPT_TEXT_EXTENSIONS),
        "config_metadata_extensions": sorted(CONFIG_METADATA_EXTENSIONS),
        "config_metadata_patterns": sorted(CONFIG_METADATA_PATTERNS),
        "route_detector": {
            key: sorted(value) if isinstance(value, tuple) else value
            for key, value in ROUTE_DETECTOR_CAPABILITY.items()
        },
        "plugins": _plugin_capability_payload(repository),
        "rules": [
            {
                "family": rule.family,
                "cwe": rule.cwe,
                "source_markers": sorted(rule.source_markers),
                "sink_markers": sorted(rule.sink_markers),
                "sanitizer_markers": sorted(rule.sanitizer_markers),
                "guard_markers": sorted(rule.guard_markers),
                "languages": sorted(rule.languages),
                "aliases": sorted(rule.aliases),
            }
            for rule in VULNERABILITY_RULES
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode("utf-8")).hexdigest()


def _plugin_capability_payload(repository) -> list[dict[str, Any]]:
    plugins = _repository_plugins(repository)
    payload: list[dict[str, Any]] = []
    for plugin in sorted(plugins, key=lambda item: _safe_plugin_name(item)):
        analyzer_config = _plugin_analyzer_config(plugin)
        payload.append(
            {
                "name": _safe_plugin_name(plugin),
                "extensions": _safe_plugin_extensions(plugin),
                "analyzer_config": _ast_config_payload(analyzer_config),
            }
        )
    return payload


def _ast_config_payload(analyzer_config) -> dict[str, list[str]]:
    return {
        "function_node_types": sorted(analyzer_config.function_node_types),
        "call_node_types": sorted(analyzer_config.call_node_types),
        "name_fields": list(analyzer_config.name_fields),
        "call_name_fields": list(analyzer_config.call_name_fields),
        "definition_node_types": sorted(analyzer_config.definition_node_types),
        "reference_node_types": sorted(analyzer_config.reference_node_types),
        "parameter_node_types": sorted(analyzer_config.parameter_node_types),
        "import_node_types": sorted(analyzer_config.import_node_types),
        "return_node_types": sorted(analyzer_config.return_node_types),
        "check_node_types": sorted(analyzer_config.check_node_types),
        "condition_fields": list(analyzer_config.condition_fields),
        "identifier_node_types": sorted(analyzer_config.identifier_node_types),
    }


def _repository_plugins(repository) -> list[Any]:
    config = getattr(repository, "_config", None)
    if config is None:
        return []
    plugins = []
    seen: set[int] = set()
    for plugin in list(getattr(config, "ext_plugin_map", {}).values()):
        plugin_id = id(plugin)
        if plugin_id in seen:
            continue
        seen.add(plugin_id)
        plugins.append(plugin)
    for _pattern, plugin in getattr(config, "ext_pattern_plugin_map", []):
        plugin_id = id(plugin)
        if plugin_id in seen:
            continue
        seen.add(plugin_id)
        plugins.append(plugin)
    return plugins


def _safe_plugin_name(plugin) -> str:
    try:
        return str(plugin.get_name() or "").strip()
    except Exception:
        return ""


def _safe_plugin_extensions(plugin) -> list[str]:
    try:
        return sorted(str(ext).lower() for ext in plugin.get_supported_extensions())
    except Exception:
        return []


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
        for match in re.finditer(
            r"^\s*(?:use|require)\s+([A-Za-z_][\w:]*)", source, re.M
        ):
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
    route = _script_entrypoint_route(file_id, language) if script_markers else None
    line_count = len(script_source.splitlines()) or 1
    symbol = "__script__"
    script_metadata = _PythonFunctionMetadata(
        file_id=file_id,
        language=language,
        symbol=symbol,
        line=1,
        end_line=line_count,
        decorators=(),
        route=route,
        route_decorator="server_script" if route else None,
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


def _script_entrypoint_route(file_id: str, language: str) -> str | None:
    if language not in {"php", "perl"}:
        return None
    if Path(file_id).suffix.lower() in SCRIPT_ROUTE_EXCLUDED_SUFFIXES:
        return None
    path = "/" + file_id.strip().lstrip("./")
    return path.replace("\\", "/")


def _framework_route_for_function(
    *,
    file_id: str,
    language: str,
    source: str,
    body: str,
    signature: str,
    symbol: str,
    line: int,
) -> tuple[str | None, str | None]:
    language = str(language or "").lower()
    route = _route_from_file_path(file_id, language, source, symbol)
    if route:
        return route, "file_route"

    registered = _registered_route_for_symbol(source, symbol, language)
    if registered:
        return registered

    annotated = _annotation_route_before_line(source, line, language)
    if annotated:
        return annotated

    dsl = _dsl_route_for_symbol(source, body, signature, symbol, language)
    if dsl:
        return dsl

    return None, None


def _route_from_file_path(
    file_id: str,
    language: str,
    source: str,
    symbol: str,
) -> str | None:
    normalized = file_id.replace("\\", "/")
    if language not in {"javascript", "typescript", "tsx", "jsx"}:
        return None
    marker = "/pages/api/"
    if marker not in f"/{normalized}":
        return None
    if not _is_file_route_handler(symbol, source):
        return None
    route = "/" + f"/{normalized}".split(marker, 1)[1]
    route = re.sub(r"\.(?:jsx?|tsx?)$", "", route)
    route = re.sub(r"/index$", "", route)
    route = re.sub(r"\[([^\]]+)\]", r":\1", route)
    return route or "/"


def _is_file_route_handler(symbol: str, source: str) -> bool:
    if not symbol:
        return False
    escaped = re.escape(symbol)
    export_patterns = (
        rf"\bexport\s+default\s+(?:async\s+)?function\s+{escaped}\b",
        rf"\bexport\s+default\s+{escaped}\b",
        rf"\bmodule\.exports\s*=\s*{escaped}\b",
        rf"\bexports\.default\s*=\s*{escaped}\b",
    )
    return any(re.search(pattern, source) for pattern in export_patterns)


def _registered_route_for_symbol(
    source: str,
    symbol: str,
    language: str,
) -> tuple[str, str] | None:
    if not symbol:
        return None
    escaped = re.escape(symbol)
    quote_route = r"['\"]([^'\"]+)['\"]"
    if language in {"javascript", "typescript", "tsx", "jsx"}:
        patterns: tuple[str, ...] = (
            rf"\b(?:app|router|server|fastify)\s*\.\s*"
            rf"(get|post|put|patch|delete|all|use)\s*\(\s*{quote_route}"
            rf"\s*,[^)]*\b{escaped}\b",
            rf"\bfastify\s*\.\s*route\s*\(\s*\{{[^}}]*\burl\s*:\s*{quote_route}"
            rf"[^}}]*\bhandler\s*:\s*{escaped}\b",
            rf"\b(?:app|router)\s*\.\s*use\s*\(\s*{quote_route}"
            rf"\s*,[^)]*\b{escaped}\b",
        )
    elif language == "go":
        patterns = (
            rf"\b(?:http\.)?HandleFunc\s*\(\s*{quote_route}\s*,\s*{escaped}\b",
            rf"\.\s*(GET|POST|PUT|PATCH|DELETE|Any|Handle)\s*\(\s*{quote_route}"
            rf"\s*,\s*{escaped}\b",
        )
    elif language == "csharp":
        patterns = (
            rf"\bMap(?:Get|Post|Put|Patch|Delete|Methods)\s*\(\s*{quote_route}"
            rf"\s*,[^)]*\b{escaped}\b",
        )
    elif language == "rust":
        patterns = (
            rf"\.route\s*\(\s*{quote_route}\s*,\s*(?:get|post|put|patch|delete|any)"
            rf"\s*\(\s*{escaped}\s*\)",
        )
    elif language in {"php", "ruby"}:
        patterns = (
            rf"\b(?:get|post|put|patch|delete|match)\s*\(?\s*{quote_route}"
            rf"[^)\n]*\b{escaped}\b",
            rf"\b(?:get|post|put|patch|delete)\s+{quote_route}"
            rf"[^#\n]*#\s*{escaped}\b",
            rf"['\"](?:GET|POST|PUT|PATCH|DELETE)\s+([^'\"]+)['\"]\s*=>"
            rf"[^;\n]*['\"]{escaped}['\"]",
        )
    else:
        return None
    for pattern in patterns:
        match = re.search(pattern, source, re.I | re.S)
        if not match:
            continue
        route = next(
            (group for group in match.groups() if group and group.startswith("/")),
            None,
        )
        if route:
            detector = (
                "framework_minimal_api" if language == "csharp" else "framework_route"
            )
            return route, detector
    return None


def _annotation_route_before_line(
    source: str,
    line: int,
    language: str,
) -> tuple[str, str] | None:
    prefix = _adjacent_annotation_block(source, line)
    if language in {"javascript", "typescript", "tsx", "jsx"}:
        patterns: tuple[str, ...] = (
            r"@\s*(?:Get|Post|Put|Patch|Delete|All)\s*\(\s*['\"]([^'\"]+)['\"]",
        )
    elif language in {"java", "kotlin", "scala"}:
        patterns: tuple[str, ...] = (
            r"@\s*(?:GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping|Path)\s*\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"]",
            r"@\s*(?:GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping|Path)\s*\(\s*path\s*=\s*['\"]([^'\"]+)['\"]",
        )
    elif language == "csharp":
        patterns = (
            r"\[\s*(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\s*\(\s*['\"]([^'\"]+)['\"]",
        )
    elif language == "rust":
        patterns = (
            r"#\s*\[\s*(?:get|post|put|patch|delete|route)\s*\(\s*['\"]([^'\"]+)['\"]",
        )
    else:
        return None
    for pattern in patterns:
        matches = list(re.finditer(pattern, prefix, re.I | re.S))
        if not matches:
            continue
        route = matches[-1].group(1)
        return _normalize_route(route), "framework_annotation"
    return None


def _adjacent_annotation_block(source: str, line: int) -> str:
    lines = source.splitlines()
    if not lines:
        return ""
    idx = min(max(line - 1, 0), len(lines) - 1)
    start = idx
    while start > 0 and _is_annotation_context_line(lines[start - 1]):
        start -= 1
    end = idx
    if _is_annotation_context_line(lines[idx]):
        while end + 1 < len(lines) and _is_annotation_context_line(lines[end + 1]):
            end += 1
    return "\n".join(lines[start : end + 1])


def _is_annotation_context_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if stripped.startswith(("@", "[", "#[", "//", "/*", "*")):
        return True
    return False


def _dsl_route_for_symbol(
    source: str,
    body: str,
    signature: str,
    symbol: str,
    language: str,
) -> tuple[str, str] | None:
    if language == "ruby":
        match = re.search(
            r"\b(?:get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]", body
        )
        if match:
            return _normalize_route(match.group(1)), "framework_dsl"
        match = re.search(
            rf"\b(?:get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]"
            rf"\s*(?:\n\s*)+def\s+{re.escape(symbol)}\b",
            source,
        )
        if match:
            return _normalize_route(match.group(1)), "framework_dsl"
    if language == "go" and (
        "cobra.Command" in body
        or "cobra.Command" in signature
        or re.search(r"\bRunE?\s*:", body)
    ):
        return f"/{symbol}", "framework_command"
    if language in {"java", "kotlin", "scala"} and (
        symbol.lower() in {"doget", "dopost", "doput", "dodelete", "service"}
        or "HttpServletRequest" in signature
        or "HttpServletRequest" in body
    ):
        return f"/{symbol}", "framework_signature"
    if language == "rust" and re.search(r"\b(?:Json|Query|Path)\s*<", signature):
        return f"/{symbol}", "framework_signature"
    if language in {"bash", "lua", "perl"} and _matching_source_values(
        tuple(_generic_security_markers(body))
    ):
        return f"/{symbol}", "script_handler"
    return None


def _normalize_route(route: str) -> str:
    cleaned = str(route or "").strip()
    if not cleaned:
        return "/"
    if not cleaned.startswith("/"):
        return "/" + cleaned
    return cleaned


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
        script_has_sources = bool(_server_script_markers(body, language))
        route = (
            _script_entrypoint_route(file_id, language) if script_has_sources else None
        )
        functions.append(
            _PythonFunctionMetadata(
                file_id=qname.rsplit("::", 1)[0],
                language=language,
                symbol=qname.rsplit("::", 1)[-1].split("@", 1)[0],
                line=line,
                end_line=end_line,
                decorators=(),
                route=route,
                route_decorator="server_script" if route else None,
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
            r"(?m)^\s*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)\s*\("
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
        route, route_decorator = _framework_route_for_function(
            file_id=file_id,
            language=language,
            source=source,
            body=body,
            signature=signature,
            symbol=symbol,
            line=line,
        )
        qname = _dedup_text_qname(file_id, symbol, line, used_qnames)
        metadata = _PythonFunctionMetadata(
            file_id=qname.rsplit("::", 1)[0],
            language=language,
            symbol=qname.rsplit("::", 1)[-1].split("@", 1)[0],
            line=line,
            end_line=end_line,
            decorators=(),
            route=route,
            route_decorator=route_decorator,
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


def _config_nodes_for_file(
    *,
    file_id: str,
    source: str,
    language: str,
) -> list[_PythonFunctionMetadata]:
    if language == "terraform":
        nodes = _terraform_config_nodes(file_id, source, language)
        if nodes:
            return nodes
    if language == "dockerfile":
        nodes = _dockerfile_config_nodes(file_id, source, language)
        if nodes:
            return nodes
    symbol = Path(file_id).name or "config"
    return [
        _PythonFunctionMetadata(
            file_id=file_id,
            language=language,
            symbol=symbol,
            line=1,
            end_line=len(source.splitlines()) or 1,
            decorators=(),
            route=None,
            route_decorator=None,
            parameters=(),
            returns=(),
            call_names=tuple(sorted(_config_security_markers(source, language))),
            imports=(),
            config_refs=tuple(sorted(_text_config_refs(source))),
            node_type="config",
        )
    ]


def _terraform_config_nodes(
    file_id: str,
    source: str,
    language: str,
) -> list[_PythonFunctionMetadata]:
    nodes: list[_PythonFunctionMetadata] = []
    used_qnames: set[str] = set()
    block_pattern = re.compile(
        r'(?m)^\s*(resource|data|module)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{'
    )
    matches = list(block_pattern.finditer(source))
    for index, match in enumerate(matches):
        block_kind = match.group(1)
        block_type = match.group(2)
        block_name = match.group(3) or block_type
        symbol = (
            f"{block_type}.{block_name}"
            if block_kind in {"resource", "data"}
            else f"module.{block_name}"
        )
        line = _line_number_for_offset(source, match.start())
        end_line = _brace_end_line(source, match.end() - 1)
        if index + 1 < len(matches):
            next_line = _line_number_for_offset(source, matches[index + 1].start())
            end_line = min(end_line, max(line, next_line - 1))
        body = _slice_lines(source, line, end_line)
        qname = _dedup_text_qname(file_id, symbol, line, used_qnames)
        nodes.append(
            _PythonFunctionMetadata(
                file_id=qname.rsplit("::", 1)[0],
                language=language,
                symbol=qname.rsplit("::", 1)[-1].split("@", 1)[0],
                line=line,
                end_line=end_line,
                decorators=(),
                route=None,
                route_decorator=None,
                parameters=(block_kind, block_type),
                returns=(),
                call_names=tuple(sorted(_config_security_markers(body, language))),
                imports=(),
                config_refs=tuple(sorted(_text_config_refs(body))),
                node_type="resource"
                if block_kind in {"resource", "data"}
                else "config",
            )
        )
    return nodes


def _dockerfile_config_nodes(
    file_id: str,
    source: str,
    language: str,
) -> list[_PythonFunctionMetadata]:
    nodes: list[_PythonFunctionMetadata] = []
    used_qnames: set[str] = set()
    for line_no, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        instruction = line.split(None, 1)[0].upper()
        if instruction not in {"RUN", "CMD", "ENTRYPOINT", "ENV", "USER", "EXPOSE"}:
            continue
        symbol = f"{instruction.lower()}_{line_no}"
        qname = _dedup_text_qname(file_id, symbol, line_no, used_qnames)
        nodes.append(
            _PythonFunctionMetadata(
                file_id=qname.rsplit("::", 1)[0],
                language=language,
                symbol=qname.rsplit("::", 1)[-1].split("@", 1)[0],
                line=line_no,
                end_line=line_no,
                decorators=(),
                route=None,
                route_decorator=None,
                parameters=(instruction,),
                returns=(),
                call_names=tuple(sorted(_config_security_markers(line, language))),
                imports=(),
                config_refs=tuple(sorted(_text_config_refs(line))),
                node_type="config",
            )
        )
    return nodes


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
        for match in re.finditer(
            r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b", body, re.I
        ):
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
        for marker in SANITIZER_KEYWORDS:
            if _body_matches_marker(body.lower(), marker.lower(), source=False):
                names.add(marker)
        if re.search(
            r"\b(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\(", body, re.I
        ):
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
    for marker in SANITIZER_KEYWORDS:
        if _body_matches_marker(body.lower(), marker.lower(), source=False):
            names.add(marker)
    if re.search(r"`[^`]+`|\bqx\s*[/({]", body):
        names.add("exec")
    return names


def _generic_security_markers(body: str) -> set[str]:
    markers: set[str] = set()
    lowered = body.lower()
    for keyword in SOURCE_KEYWORDS + SINK_KEYWORDS + SANITIZER_KEYWORDS:
        if keyword.lower() == "function":
            continue
        if _body_matches_marker(lowered, keyword, source=False):
            markers.add(keyword)
    return markers


def _body_matches_marker(lowered_body: str, marker: str, *, source: bool) -> bool:
    marker_lower = str(marker or "").lower()
    if not marker_lower:
        return False
    for pattern in _marker_body_patterns(marker_lower, source=source):
        if re.search(pattern, lowered_body, re.I):
            return True
    return False


def _marker_body_patterns(marker: str, *, source: bool) -> tuple[str, ...]:
    escaped = re.escape(marker)
    special_patterns = {
        "child_process.exec": (r"\bchild_process\s*\.\s*exec\s*\(",),
        "child_process.execfile": (r"\bchild_process\s*\.\s*execfile\s*\(",),
        "child_process.spawn": (r"\bchild_process\s*\.\s*spawn\s*\(",),
        "runtime.exec": (
            r"\bruntime\s*\.\s*getruntime\s*\(\s*\)\s*\.\s*exec\s*\(",
            r"\bruntime\s*\.\s*exec\s*\(",
        ),
        "getruntime().exec": (r"\bgetruntime\s*\(\s*\)\s*\.\s*exec\s*\(",),
        "process.start": (r"\bprocess\s*\.\s*start\s*\(",),
        "system.diagnostics.process.start": (
            r"\bsystem\s*\.\s*diagnostics\s*\.\s*process\s*\.\s*start\s*\(",
        ),
        "exec.command": (r"\bexec\s*\.\s*command(?:context)?\s*\(",),
        "exec.commandcontext": (r"\bexec\s*\.\s*commandcontext\s*\(",),
        "command::new": (r"\bcommand\s*::\s*new\s*\(",),
        "std::process::command": (
            r"\bstd\s*::\s*process\s*::\s*command\s*::\s*new\s*\(",
        ),
        "vm.runin": (r"\bvm\s*\.\s*runin\w*\s*\(",),
        "method.invoke": (r"\bmethod\s*\.\s*invoke\s*\(",),
        "assembly.load": (r"\bassembly\s*\.\s*load\w*\s*\(",),
        "class.forname": (r"\bclass\s*\.\s*forname\s*\(",),
        "pdo::query": (r"\bpdo\s*::\s*query\s*\(",),
        "pdo.query": (r"\bpdo\s*->\s*query\s*\(", r"\bpdo\s*\.\s*query\s*\("),
        "pdo.exec": (r"\bpdo\s*->\s*exec\s*\(", r"\bpdo\s*\.\s*exec\s*\("),
        "db.query": (r"\bdb\s*(?:\.|->)\s*query\s*\(",),
        "db.exec": (r"\bdb\s*(?:\.|->)\s*exec\s*\(",),
        "db.raw": (r"\bdb\s*(?:\.|->)\s*raw\s*\(",),
        "dbh.do": (r"\bdbh\s*(?:\.|->)\s*do\s*\(",),
        "statement.execute": (r"\bstatement\s*\.\s*execute\w*\s*\(",),
        "statement.executequery": (r"\bstatement\s*\.\s*executequery\s*\(",),
        "statement.executeupdate": (r"\bstatement\s*\.\s*executeupdate\s*\(",),
        "parameters.add": (r"\bparameters\s*\.\s*add(?:withvalue)?\s*\(",),
        "parameters.addwithvalue": (r"\bparameters\s*\.\s*addwithvalue\s*\(",),
        "command.parameters": (r"\bcommand\s*\.\s*parameters\b",),
        "activerecord.sanitize_sql": (r"\bactive_?record\s*\.\s*sanitize_sql\w*\s*\(",),
    }
    if marker in special_patterns:
        return special_patterns[marker]
    if source and marker in {"$_get", "$_post", "$_request", "$_cookie"}:
        return (escaped,)
    if source and marker in {"@argv", "$argv"}:
        return (r"[@$]argv\b|\$argv\s*\[",)
    if any(not char.isalnum() and char != "_" for char in marker):
        return (escaped,)
    return (rf"(?<![a-z0-9_]){escaped}(?![a-z0-9_])",)


def _config_security_markers(body: str, language: str) -> set[str]:
    markers = _generic_security_markers(body)
    lowered = body.lower()
    if language == "terraform":
        markers.update({"config", "network", "resource"})
        if "ingress" in lowered:
            markers.add("ingress")
        if "cidr" in lowered:
            markers.add("cidr")
        if "principal" in lowered:
            markers.add("principal")
        if "policy" in lowered:
            markers.add("policy")
        if "0.0.0.0/0" in lowered or "::/0" in lowered:
            markers.update({"public", "network"})
        if "aws_security_group" in lowered or "ingress" in lowered:
            markers.add("security_group")
    elif language == "dockerfile":
        markers.add("config")
        if re.search(r"\b(curl|wget|bash|sh|apk|apt-get|pip|npm)\b", lowered):
            markers.update({"exec", "sh -c"})
        if re.search(r"\bexpose\b", lowered):
            markers.update({"network", "public", "exposed_port"})
        if re.search(r"\broot\b|user\s+0\b", lowered):
            markers.add("root")
        if re.search(r"\bsecret|token|password|key\b", lowered):
            markers.add("env")
    elif language in {"yaml", "json"}:
        markers.add("config")
        if re.search(r"\b(secret|token|password|api[_-]?key|private_key)\b", lowered):
            markers.add("env")
        if re.search(
            r"\b(public|0\.0\.0\.0/0|::/0|privileged|listen|port|ports|ingress)\b",
            lowered,
        ):
            markers.update({"network", "public"})
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
            "route_detector": metadata.route_decorator,
            "route_detector_confidence": _route_detector_confidence(
                metadata.route_decorator
            )
            if metadata.route
            else None,
            "guards": list(metadata.guards),
            "imports": list(metadata.imports),
            "config_refs": list(metadata.config_refs),
        }
    )
    return result


def _entrypoint_registration_detail(route_decorator: str | None) -> str:
    detector = _detector_detail_suffix(route_decorator)
    if route_decorator in {"server_script", "script_handler"}:
        return f"Script entrypoint registration{detector}"
    if route_decorator == "file_route":
        return f"File-based route registration{detector}"
    if route_decorator == "framework_annotation":
        return f"Annotated framework route registration{detector}"
    if route_decorator == "framework_command":
        return f"Framework command registration{detector}"
    if route_decorator == "framework_minimal_api":
        return f"Minimal API route registration{detector}"
    if route_decorator == "framework_signature":
        return f"Framework signature route registration{detector}"
    return f"Framework route registration{detector}"


def _entrypoint_handler_detail(route_decorator: str | None) -> str:
    detector = _detector_detail_suffix(route_decorator)
    if route_decorator in {"server_script", "script_handler"}:
        return f"Script entrypoint handler{detector}"
    if route_decorator == "file_route":
        return f"File-based route handler{detector}"
    if route_decorator == "framework_annotation":
        return f"Annotated framework route handler{detector}"
    if route_decorator == "framework_command":
        return f"Framework command handler{detector}"
    if route_decorator == "framework_minimal_api":
        return f"Minimal API route handler{detector}"
    if route_decorator == "framework_signature":
        return f"Framework signature route handler{detector}"
    return f"Framework route handler{detector}"


def _detector_detail_suffix(route_decorator: str | None) -> str:
    if not route_decorator:
        return ""
    confidence = _route_detector_confidence(route_decorator)
    return f"; detector={route_decorator}; confidence={confidence:.2f}"


def _route_detector_confidence(route_decorator: str | None) -> float:
    return {
        "file_route": 0.95,
        "framework_annotation": 0.9,
        "framework_minimal_api": 0.9,
        "framework_route": 0.9,
        "server_script": 0.85,
        "framework_command": 0.75,
        "framework_dsl": 0.75,
        "framework_signature": 0.75,
        "script_handler": 0.75,
    }.get(str(route_decorator or ""), 0.7)


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
                detail=_entrypoint_handler_detail(metadata.route_decorator),
                file=file,
                line=line,
                symbol=symbol,
                confidence=_route_detector_confidence(metadata.route_decorator),
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
                confidence=_route_detector_confidence(metadata.route_decorator),
            )
        )
    for value in _matching_source_values(behavior_items):
        tags.append(
            SecurityTag(
                kind="source",
                value=value,
                detail="heuristic source marker; detector=source_marker",
                file=file,
                line=line,
                symbol=symbol,
                confidence=0.7,
            )
        )
    for value in _matching_values(behavior_items, SINK_KEYWORDS):
        if _is_namespace_only_sink(value, metadata):
            continue
        tags.append(
            SecurityTag(
                kind="sink",
                value=value,
                detail="heuristic sink marker; detector=sink_marker",
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
                detail="heuristic guard marker; detector=guard_marker",
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
                detail="heuristic sanitizer marker; detector=sanitizer_marker",
                file=file,
                line=line,
                symbol=symbol,
                confidence=0.7,
            )
        )
    return _dedupe_tags(tags)


def _is_namespace_only_sink(
    value: str,
    metadata: _PythonFunctionMetadata | None,
) -> bool:
    if metadata is None:
        return False
    return metadata.language == "csharp" and value == "System"


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
    for keyword in keywords:
        if _value_matches_marker(lowered, keyword):
            return True
    return False


def _matches_source_keyword(value: str | None) -> bool:
    lowered = str(value or "").lower()
    for keyword in SOURCE_KEYWORDS:
        if _value_matches_marker(lowered, keyword):
            return True
    return False


def _value_matches_marker(value: str, marker: str) -> bool:
    marker_lower = str(marker or "").lower()
    if not marker_lower:
        return False
    if value == marker_lower or value.endswith(f".{marker_lower}"):
        return True
    if _is_prefix_marker(marker_lower) and value.startswith(marker_lower):
        return True
    if re.search(rf"(?:^|[._-]){re.escape(marker_lower)}(?:$|[._-])", value):
        return True
    if _normalized_name(value) == marker_lower:
        return True
    if any(not char.isalnum() and char not in "._" for char in marker_lower):
        return marker_lower in value
    return bool(
        re.search(
            rf"(?<![a-z0-9_]){re.escape(marker_lower)}(?![a-z0-9_])",
            value,
        )
    )


def _is_prefix_marker(marker: str) -> bool:
    return marker in {
        "allowlist",
        "authorize",
        "canonical",
        "check_",
        "escape",
        "normalize",
        "parameterize",
        "prepare",
        "require_",
        "sanitize",
        "schema",
        "validate",
        "whitelist",
    }


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
        if _matches_supported_source_path(path, supported):
            result.append(path)
    return sorted(result)


def _matches_supported_source_path(path: Path, supported: set[str]) -> bool:
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in supported or name in supported:
        return True
    for token in supported:
        if "*" not in token:
            continue
        if token.count("*") != 1 or not token.endswith("*"):
            continue
        if token[:-1] in name:
            return True
    return False


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
