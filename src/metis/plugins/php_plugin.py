# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class PHPPlugin(ConfigBackedLanguagePlugin):
    """Language plugin providing PHP-specific splitter and prompts."""

    NAME = "php"
    DEFAULT_TEST_PATH_PATTERNS = ["*Test.php"]
    DEFAULT_EXTENSIONS = [
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
    ]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": [
                "function_definition",
                "method_declaration",
                "anonymous_function_creation_expression",
            ],
            "call": ["function_call_expression", "member_call_expression"],
            "name": ["name", "function", "member"],
            "import": ["namespace_use_declaration"],
        }
