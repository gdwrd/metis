# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.plugins.c_plugin import CPlugin
from metis.plugins.cpp_plugin import CppPlugin
from metis.plugins.go_plugin import GoPlugin
from metis.plugins.javascript_plugin import JavaScriptPlugin
from metis.plugins.php_plugin import PHPPlugin
from metis.plugins.python_plugin import PythonPlugin
from metis.plugins.rust_plugin import RustPlugin
from metis.plugins.solidity_plugin import SolidityPlugin
from metis.plugins.systemverilog_plugin import SystemVerilogPlugin
from metis.plugins.tb_plugin import TableGenPlugin
from metis.plugins.terraform_plugin import TerraformPlugin
from metis.plugins.typescript_plugin import TypeScriptPlugin
from metis.plugins.verilog_plugin import VerilogPlugin


@pytest.mark.parametrize(
    "plugin_cls",
    [
        CPlugin,
        CppPlugin,
        GoPlugin,
        JavaScriptPlugin,
        PHPPlugin,
        PythonPlugin,
        RustPlugin,
        SolidityPlugin,
        SystemVerilogPlugin,
        TableGenPlugin,
        TerraformPlugin,
        TypeScriptPlugin,
        VerilogPlugin,
    ],
)
def test_shipped_plugins_expose_test_path_patterns(plugin_cls):
    assert plugin_cls({}).get_test_path_patterns()


def test_config_backed_plugin_merges_configured_test_path_patterns():
    plugin = PythonPlugin(
        {
            "plugins": {
                "python": {
                    "test_path_patterns": ["custom_tests/**", "*_fixture.py"],
                }
            }
        }
    )

    assert plugin.get_test_path_patterns() == [
        "test_*.py",
        "*_test.py",
        "custom_tests/**",
        "*_fixture.py",
    ]
