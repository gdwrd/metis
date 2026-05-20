# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class CPlugin(ConfigBackedLanguagePlugin):
    NAME = "c"
    DEFAULT_EXTENSIONS = [".c", ".h", ".cc"]
    DEFAULT_TEST_PATH_PATTERNS = ["**/testcases/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_definition"],
            "call": ["call_expression"],
            "name": ["declarator", "function"],
            "import": ["preproc_include"],
        }

    def get_analyzer_config(self):
        config = super().get_analyzer_config()
        config.update(
            {
                "lifetime_sink_names": [
                    "free",
                    "kfree",
                    "vfree",
                    "delete",
                    "drop",
                ],
                "lifetime_guard_names": [
                    "refcount_dec_and_test",
                    "mutex_lock",
                    "spin_lock",
                    "memset_s",
                    "zeroize",
                ],
                "hardware_sink_names": [
                    "write_reg",
                    "register_write",
                    "mmio_write",
                    "csr_write",
                    "set_privilege",
                    "enable_debug",
                ],
                "hardware_guard_names": [
                    "is_privileged",
                    "lifecycle_is_secure",
                    "check_permission",
                    "is_locked",
                    "allow_debug",
                ],
            }
        )
        return config

    def get_triage_analyzer_factory(self):
        from metis.engine.analysis.c_family_analyzer import (
            build_c_family_analyzer_factory,
        )

        return build_c_family_analyzer_factory(
            "c",
            supported_extensions=self.get_supported_extensions(),
        )
