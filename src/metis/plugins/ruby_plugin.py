# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class RubyPlugin(ConfigBackedLanguagePlugin):
    NAME = "ruby"
    DEFAULT_EXTENSIONS = [".rb"]
    DEFAULT_TEST_PATH_PATTERNS = ["*_spec.rb"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["method", "singleton_method"],
            "call": ["call", "command"],
            "name": ["name", "method", "receiver"],
        }
