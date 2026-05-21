# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Any

from metis.engine.analysis.treesitter_ast import normalize_analyzer_config
from metis.engine.analysis.treesitter_runtime import TreeSitterRuntime


CONFIG_GRAPH_EXTENSIONS = {
    ".dockerfile",
    ".hcl",
    ".json",
    ".tf",
    ".tfvars",
    ".yaml",
    ".yml",
}
CONFIG_GRAPH_PATTERNS = {"dockerfile"}


def runtime_language_for(language: str, path: str | Path | None = None) -> str:
    """Return the tree-sitter runtime language used for a plugin/path pair."""
    normalized = str(language or "").strip().lower()
    path_text = str(path or "").strip().lower()
    suffix = Path(path_text).suffix.lower() if path is not None else ""
    if path_text.startswith(".") and "/" not in path_text and "\\" not in path_text:
        suffix = path_text
    name = Path(path_text).name.lower() if path is not None else ""
    if normalized == "systemverilog":
        return "verilog"
    if normalized in {"jsx", "tsx"} or suffix in {".jsx", ".tsx"}:
        return "tsx"
    if normalized in {"terraform", "hcl"}:
        if suffix == ".hcl":
            return "hcl"
        if suffix in {".tf", ".tfvars"}:
            return "terraform"
        return "terraform" if normalized == "terraform" else "hcl"
    if name == "dockerfile" or suffix == ".dockerfile":
        return "dockerfile"
    return normalized


def alias_source_for(language: str, runtime_language: str) -> str:
    normalized = str(language or "").strip().lower()
    if not normalized:
        return "unknown"
    if normalized == runtime_language:
        return "identity"
    return "runtime_alias"


def build_parser_inventory(plugins) -> dict[str, Any]:
    """Return parser/analyzer coverage for research language support."""
    languages: list[dict[str, Any]] = []
    parser_available_count = 0
    for plugin in sorted(plugins or (), key=lambda item: _plugin_name(item)):
        name = _plugin_name(plugin)
        extensions = _plugin_extensions(plugin)
        analyzer_config = _normalized_config(plugin)
        runtime_language = runtime_language_for(name)
        runtime_by_extension = {
            extension: runtime_language_for(name, extension) for extension in extensions
        }
        runtime_languages = tuple(
            dict.fromkeys([runtime_language, *runtime_by_extension.values()])
        )
        parser_available = any(
            _parser_available(language) for language in runtime_languages
        )
        if parser_available:
            parser_available_count += 1
        config_graph = bool(
            set(extensions) & CONFIG_GRAPH_EXTENSIONS
            or set(extensions) & CONFIG_GRAPH_PATTERNS
        )
        if analyzer_config.function_node_types and analyzer_config.call_node_types:
            graph_mode = "ast"
        elif config_graph:
            graph_mode = "config_resource"
        else:
            graph_mode = "text_or_splitter"
        languages.append(
            {
                "name": name,
                "extensions": extensions,
                "parser": {
                    "language": runtime_language,
                    "alias_source": alias_source_for(name, runtime_language),
                    "runtime_by_extension": runtime_by_extension,
                    "available": parser_available,
                },
                "analyzer": {
                    "function_node_types": sorted(analyzer_config.function_node_types),
                    "call_node_types": sorted(analyzer_config.call_node_types),
                    "import_node_types": sorted(analyzer_config.import_node_types),
                },
                "research_graph_mode": graph_mode,
            }
        )
    return {
        "language_count": len(languages),
        "parser_available_count": parser_available_count,
        "languages": languages,
    }


def _normalized_config(plugin):
    try:
        return normalize_analyzer_config(plugin.get_analyzer_config())
    except Exception:
        return normalize_analyzer_config({})


def _parser_available(name: str) -> bool:
    try:
        return TreeSitterRuntime(name).is_available
    except Exception:
        return False


def _plugin_name(plugin) -> str:
    try:
        return str(plugin.get_name() or "").strip()
    except Exception:
        return ""


def _plugin_extensions(plugin) -> list[str]:
    try:
        return sorted(str(ext).lower() for ext in plugin.get_supported_extensions())
    except Exception:
        return []
