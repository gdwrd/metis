# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class RustPlugin(ConfigBackedLanguagePlugin):
    NAME = "rust"
    DEFAULT_EXTENSIONS = [".rs"]
    DEFAULT_TEST_PATH_PATTERNS = ["*_test.rs"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_item", "closure_expression"],
            "call": ["call_expression"],
            "name": ["name", "function"],
            "import": ["use_declaration"],
        }
