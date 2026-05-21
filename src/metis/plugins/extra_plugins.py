# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.base import ConfigBackedLanguagePlugin


class JavaPlugin(ConfigBackedLanguagePlugin):
    NAME = "java"
    DEFAULT_EXTENSIONS = [".java"]
    DEFAULT_TEST_PATH_PATTERNS = ["*Test.java", "**/src/test/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["method_declaration", "constructor_declaration"],
            "call": ["method_invocation", "object_creation_expression"],
            "name": ["name"],
            "import": ["import_declaration"],
        }


class CSharpPlugin(ConfigBackedLanguagePlugin):
    NAME = "csharp"
    DEFAULT_EXTENSIONS = [".cs"]
    DEFAULT_TEST_PATH_PATTERNS = ["*Tests.cs", "**/Tests/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["method_declaration", "constructor_declaration"],
            "call": ["invocation_expression", "object_creation_expression"],
            "name": ["name"],
            "import": ["using_directive"],
        }


class KotlinPlugin(ConfigBackedLanguagePlugin):
    NAME = "kotlin"
    DEFAULT_EXTENSIONS = [".kt", ".kts"]
    DEFAULT_TEST_PATH_PATTERNS = ["*Test.kt", "*Tests.kt", "**/src/test/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_declaration"],
            "call": ["call_expression"],
            "name": ["name"],
            "import": ["import_header"],
        }


class SwiftPlugin(ConfigBackedLanguagePlugin):
    NAME = "swift"
    DEFAULT_EXTENSIONS = [".swift"]
    DEFAULT_TEST_PATH_PATTERNS = ["*Tests.swift", "**/Tests/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_declaration"],
            "call": ["call_expression"],
            "name": ["name", "simple_identifier"],
            "import": ["import_declaration"],
        }


class ScalaPlugin(ConfigBackedLanguagePlugin):
    NAME = "scala"
    DEFAULT_EXTENSIONS = [".scala", ".sc"]
    DEFAULT_TEST_PATH_PATTERNS = ["*Spec.scala", "*Test.scala", "**/src/test/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_definition"],
            "call": ["call_expression"],
            "name": ["name", "identifier"],
            "import": ["import_declaration"],
        }


class BashPlugin(ConfigBackedLanguagePlugin):
    NAME = "bash"
    DEFAULT_EXTENSIONS = [".sh", ".bash", ".bats"]
    DEFAULT_TEST_PATH_PATTERNS = ["*.bats", "**/test/**", "**/tests/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_definition"],
            "call": ["command"],
            "name": ["name", "word"],
        }


class LuaPlugin(ConfigBackedLanguagePlugin):
    NAME = "lua"
    DEFAULT_EXTENSIONS = [".lua"]
    DEFAULT_TEST_PATH_PATTERNS = ["*_spec.lua", "**/spec/**", "**/test/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["function_declaration"],
            "call": ["function_call"],
            "name": ["name", "identifier"],
        }


class PerlPlugin(ConfigBackedLanguagePlugin):
    NAME = "perl"
    DEFAULT_EXTENSIONS = [".pl", ".pm", ".cgi"]
    DEFAULT_TEST_PATH_PATTERNS = ["*.t", "**/t/**"]

    def get_function_node_types(self) -> dict[str, list[str]]:
        return {
            "function": ["subroutine_declaration_statement"],
            "call": ["subroutine_call_expression", "call_expression"],
            "name": ["name", "bareword"],
            "import": ["use_statement", "require_statement"],
        }


class DockerfilePlugin(ConfigBackedLanguagePlugin):
    NAME = "dockerfile"
    DEFAULT_EXTENSIONS = [".dockerfile", "dockerfile"]
    DEFAULT_TEST_PATH_PATTERNS = ["**/test/**", "**/tests/**"]


class YamlPlugin(ConfigBackedLanguagePlugin):
    NAME = "yaml"
    DEFAULT_EXTENSIONS = [".yaml", ".yml"]
    DEFAULT_TEST_PATH_PATTERNS = ["**/test/**", "**/tests/**"]


class JsonPlugin(ConfigBackedLanguagePlugin):
    NAME = "json"
    DEFAULT_EXTENSIONS = [".json"]
    DEFAULT_TEST_PATH_PATTERNS = ["**/test/**", "**/tests/**"]
