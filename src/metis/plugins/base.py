# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from llama_index.core.node_parser import CodeSplitter


class BaseLanguagePlugin(ABC):
    @abstractmethod
    def get_name(self) -> str:
        """Return the name of the plugin."""
        pass

    @abstractmethod
    def can_handle(self, extension: str) -> bool:
        """Return True if this plugin can handle the file extension."""
        pass

    @abstractmethod
    def get_splitter(self):
        """Return a splitter instance for code."""
        pass

    @abstractmethod
    def get_prompts(self) -> dict:
        """Return a dictionary of language-specific prompts."""
        pass

    @abstractmethod
    def get_supported_extensions(self) -> list:
        """Return a list of file extensions supported by this language."""
        pass

    def get_test_path_patterns(self) -> list[str]:
        """Return language-specific test/fixture path patterns."""
        return []

    def get_function_node_types(self) -> dict[str, list[str]]:
        """Return Tree-sitter node declarations for function-level indexing.

        Plugins that return an empty mapping keep the existing line-based
        splitter behavior.
        """
        return {}

    def get_analyzer_config(self) -> dict[str, Any]:
        """Return config-driven declarations for generic Tree-sitter triage."""
        return _analyzer_config_from_function_declarations(
            self.get_function_node_types()
        )

    def get_triage_analyzer_factory(self):
        """Return optional factory(codebase_path) -> analyzer used by triage."""
        language = str(self.get_name() or "").strip().lower()
        if not language:
            return None
        from metis.engine.analysis.generic_treesitter_analyzer import (
            build_generic_treesitter_analyzer_factory,
        )

        supported_extensions = [
            str(ext).lower() for ext in self.get_supported_extensions()
        ]
        return build_generic_treesitter_analyzer_factory(
            language,
            supported_extensions=supported_extensions,
            analyzer_config=self.get_analyzer_config(),
        )


class ConfigBackedLanguagePlugin(BaseLanguagePlugin):
    NAME = ""
    DEFAULT_EXTENSIONS: list[str] = []
    DEFAULT_TEST_PATH_PATTERNS: list[str] = []
    DEFAULT_CHUNK_LINES = 40
    DEFAULT_CHUNK_LINES_OVERLAP = 15
    DEFAULT_MAX_CHARS = 1500

    def __init__(self, plugin_config):
        self.plugin_config = plugin_config

    def get_name(self) -> str:
        return self.NAME

    def _plugin_section(self) -> dict:
        return self.plugin_config.get("plugins", {}).get(self.get_name(), {})

    def can_handle(self, extension: str) -> bool:
        return str(extension or "").lower() in self.get_supported_extensions()

    def get_supported_extensions(self) -> list:
        configured = self._plugin_section().get(
            "supported_extensions", self.DEFAULT_EXTENSIONS
        )
        return [str(ext).lower() for ext in configured]

    def get_test_path_patterns(self) -> list[str]:
        configured = self._plugin_section().get("test_path_patterns", [])
        patterns = [*self.DEFAULT_TEST_PATH_PATTERNS]
        if isinstance(configured, str):
            patterns.append(configured)
        else:
            try:
                patterns.extend(str(item) for item in configured)
            except TypeError:
                patterns.append(str(configured))
        return _dedupe_nonempty(patterns)

    def get_splitter(self):
        splitting_cfg = self._plugin_section().get("splitting", {})
        return CodeSplitter(
            language=self.get_name(),
            chunk_lines=splitting_cfg.get("chunk_lines") or self.DEFAULT_CHUNK_LINES,
            chunk_lines_overlap=splitting_cfg.get("chunk_lines_overlap")
            or self.DEFAULT_CHUNK_LINES_OVERLAP,
            max_chars=splitting_cfg.get("max_chars") or self.DEFAULT_MAX_CHARS,
        )

    def get_prompts(self) -> dict:
        return self._plugin_section().get("prompts", {})

    def get_analyzer_config(self) -> dict[str, Any]:
        base = super().get_analyzer_config()
        configured = self._plugin_section().get("analyzer", {})
        if not isinstance(configured, Mapping):
            return base
        merged = dict(base)
        for key, value in configured.items():
            merged[str(key)] = value
        return merged


def _analyzer_config_from_function_declarations(
    declarations: dict[str, list[str]],
) -> dict[str, Any]:
    if not isinstance(declarations, Mapping):
        return {}
    function_types = _as_list(declarations.get("function"))
    call_types = _as_list(declarations.get("call"))
    name_fields = _as_list(declarations.get("name"))
    import_types = _as_list(declarations.get("import"))
    return {
        "function_node_types": function_types,
        "call_node_types": call_types,
        "name_fields": name_fields,
        "call_name_fields": ["function", "callee", *name_fields],
        "definition_node_types": function_types,
        "reference_node_types": [
            "identifier",
            "field_identifier",
            "property_identifier",
            "type_identifier",
            "constant",
        ],
        "import_node_types": import_types,
        "return_node_types": ["return_statement", "return_expression"],
    }


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = [value]
    else:
        try:
            raw_items = list(value)
        except TypeError:
            raw_items = [value]
    out: list[str] = []
    for raw in raw_items:
        text = str(raw or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _dedupe_nonempty(values) -> list[str]:
    out: list[str] = []
    for raw in values:
        text = str(raw or "").strip()
        if text and text not in out:
            out.append(text)
    return out
