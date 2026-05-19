# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class CppPlugin(ConfigBackedLanguagePlugin):
    NAME = "cpp"
    DEFAULT_EXTENSIONS = [".cpp", ".hpp"]
    DEFAULT_TEST_PATH_PATTERNS = ["**/testcases/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_definition"],
            "call": ["call_expression"],
            "name": ["declarator", "function"],
            "import": ["preproc_include"],
        }

    def get_triage_analyzer_factory(self):
        from metis.engine.analysis.c_family_analyzer import (
            build_c_family_analyzer_factory,
        )

        return build_c_family_analyzer_factory(
            "cpp",
            supported_extensions=self.get_supported_extensions(),
        )
