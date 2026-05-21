# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import yaml

from metis.plugins.c_plugin import CPlugin
from metis.plugins.cpp_plugin import CppPlugin
from metis.plugins.extra_plugins import (
    BashPlugin,
    CSharpPlugin,
    JavaPlugin,
    KotlinPlugin,
    LuaPlugin,
    PerlPlugin,
    ScalaPlugin,
    SwiftPlugin,
)
from metis.plugins.go_plugin import GoPlugin
from metis.plugins.javascript_plugin import JavaScriptPlugin
from metis.plugins.php_plugin import PHPPlugin
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
        JavaPlugin({}),
        CSharpPlugin({}),
        KotlinPlugin({}),
        SwiftPlugin({}),
        ScalaPlugin({}),
        BashPlugin({}),
        LuaPlugin({}),
        PerlPlugin({}),
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
        JavaPlugin({}),
        CSharpPlugin({}),
        KotlinPlugin({}),
        SwiftPlugin({}),
        ScalaPlugin({}),
        BashPlugin({}),
        LuaPlugin({}),
        PerlPlugin({}),
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

    assert {
        "bash",
        "csharp",
        "dockerfile",
        "java",
        "json",
        "kotlin",
        "lua",
        "perl",
        "ruby",
        "scala",
        "solidity",
        "swift",
        "yaml",
    } <= names


def test_c_plugin_exposes_phase6_native_and_hardware_analyzer_markers():
    config = CPlugin({}).get_analyzer_config()

    assert "free" in config["lifetime_sink_names"]
    assert "refcount_dec_and_test" in config["lifetime_guard_names"]
    assert "mmio_write" in config["hardware_sink_names"]
    assert "is_privileged" in config["hardware_guard_names"]


def test_parser_coverage_extensions_include_common_cpp_and_php_variants():
    config = yaml.safe_load(
        Path("src/metis/plugins/plugins.yaml").read_text(encoding="utf-8")
    )

    cpp_extensions = set(CppPlugin(config).get_supported_extensions())
    php_extensions = set(PHPPlugin(config).get_supported_extensions())

    assert {".cc", ".cxx", ".c++", ".hh", ".hxx", ".hhp", ".ipp"} <= cpp_extensions
    assert ".inc" in php_extensions
