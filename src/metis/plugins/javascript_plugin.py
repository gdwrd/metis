# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class JavaScriptPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing JavaScript-specific splitter and prompts."""

    NAME = "javascript"
    DEFAULT_EXTENSIONS = [".js", ".jsx"]
    DEFAULT_TEST_PATH_PATTERNS = [
        "*.spec.js",
        "*.spec.jsx",
        "*.test.js",
        "*.test.jsx",
        "**/__tests__/**",
    ]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": [
                "function_declaration",
                "method_definition",
                "arrow_function",
                "generator_function_declaration",
            ],
            "call": ["call_expression"],
            "name": ["name", "function", "property", "declarator"],
            "import": ["import_statement"],
        }
