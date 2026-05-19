# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class GoPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing Go-specific splitter and prompts."""

    NAME = "go"
    DEFAULT_EXTENSIONS = [".go"]
    DEFAULT_TEST_PATH_PATTERNS = ["*_test.go"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_declaration", "method_declaration"],
            "call": ["call_expression"],
            "name": ["name", "function"],
            "import": ["import_declaration"],
        }
