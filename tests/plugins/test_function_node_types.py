# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import yaml

from metis.plugins.c_plugin import CPlugin
from metis.plugins.cpp_plugin import CppPlugin
from metis.plugins.go_plugin import GoPlugin
from metis.plugins.javascript_plugin import JavaScriptPlugin
from metis.plugins.python_plugin import PythonPlugin
from metis.plugins.ruby_plugin import RubyPlugin
from metis.plugins.rust_plugin import RustPlugin
from metis.plugins.solidity_plugin import SolidityPlugin
from metis.plugins.typescript_plugin import TypeScriptPlugin
from metis.plugin_loader import load_plugins


def test_roadmap_plugins_declare_function_node_types():
    plugins = [
        PythonPlugin({}),
        TypeScriptPlugin({}),
        GoPlugin({}),
        RustPlugin({}),
        SolidityPlugin({}),
        RubyPlugin({}),
        CPlugin({}),
        CppPlugin({}),
        JavaScriptPlugin({}),
    ]

    for plugin in plugins:
        declarations = plugin.get_function_node_types()

        assert declarations["function"], plugin.get_name()
        assert declarations["call"], plugin.get_name()
        assert declarations["name"], plugin.get_name()


def test_roadmap_plugins_expose_generic_analyzer_config():
    plugins = [
        PythonPlugin({}),
        TypeScriptPlugin({}),
        GoPlugin({}),
        RustPlugin({}),
        SolidityPlugin({}),
        RubyPlugin({}),
        JavaScriptPlugin({}),
    ]

    for plugin in plugins:
        config = plugin.get_analyzer_config()

        assert config["function_node_types"], plugin.get_name()
        assert config["call_node_types"], plugin.get_name()
        assert config["name_fields"], plugin.get_name()
        assert config["call_name_fields"], plugin.get_name()


def test_roadmap_plugins_load_yaml_analyzer_declarations():
    config = yaml.safe_load(
        Path("src/metis/plugins/plugins.yaml").read_text(encoding="utf-8")
    )

    plugin = PythonPlugin(config)
    analyzer_config = plugin.get_analyzer_config()

    assert analyzer_config["function_node_types"] == [
        "function_definition",
        "async_function_definition",
    ]
    assert analyzer_config["call_name_fields"] == ["function"]


def test_discovered_plugins_include_builtin_research_languages():
    config = yaml.safe_load(
        Path("src/metis/plugins/plugins.yaml").read_text(encoding="utf-8")
    )

    names = {plugin.get_name() for plugin in load_plugins(config)}

    assert {"ruby", "solidity"} <= names


def test_c_plugin_exposes_phase6_native_and_hardware_analyzer_markers():
    config = CPlugin({}).get_analyzer_config()

    assert "free" in config["lifetime_sink_names"]
    assert "refcount_dec_and_test" in config["lifetime_guard_names"]
    assert "mmio_write" in config["hardware_sink_names"]
    assert "is_privileged" in config["hardware_guard_names"]
