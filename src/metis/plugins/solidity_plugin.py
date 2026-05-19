# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class SolidityPlugin(ConfigBackedLanguagePlugin):
    NAME = "solidity"
    DEFAULT_EXTENSIONS = [".sol"]
    DEFAULT_TEST_PATH_PATTERNS = ["*.t.sol"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_definition", "modifier_definition"],
            "call": ["call_expression"],
            "name": ["name", "function"],
            "import": ["import_directive"],
        }
