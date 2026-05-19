# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class PythonPlugin(ConfigBackedLanguagePlugin):
    NAME = "python"
    DEFAULT_EXTENSIONS = [".py"]
    DEFAULT_TEST_PATH_PATTERNS = ["test_*.py", "*_test.py"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_definition", "async_function_definition"],
            "call": ["call"],
            "name": ["name", "function"],
            "import": ["import_statement", "import_from_statement"],
        }
