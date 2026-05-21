# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

from metis.engine.analysis.base import AnalyzerRequest
from metis.engine.analysis.generic_treesitter_analyzer import GenericTreeSitterAnalyzer
from metis.plugins.extra_plugins import BashPlugin, CSharpPlugin, JavaPlugin, LuaPlugin
from metis.plugins.go_plugin import GoPlugin
from metis.plugins.javascript_plugin import JavaScriptPlugin
from metis.plugins.python_plugin import PythonPlugin
from metis.plugins.rust_plugin import RustPlugin
from metis.plugins.solidity_plugin import SolidityPlugin
from metis.plugins.typescript_plugin import TypeScriptPlugin


def _write(root: Path, rel_path: str, source: str) -> None:
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _analyzer(root: Path, plugin) -> GenericTreeSitterAnalyzer:
    return GenericTreeSitterAnalyzer(
        codebase_path=str(root),
        language_name=plugin.get_name(),
        supported_extensions=plugin.get_supported_extensions(),
        analyzer_config=plugin.get_analyzer_config(),
    )


def _request(root: Path, rel_path: str, line: int) -> AnalyzerRequest:
    return AnalyzerRequest(
        codebase_path=str(root),
        file_path=rel_path,
        line=line,
        finding_message="possible wrapper chain",
        finding_snippet="",
        finding_rule_id="R1",
        max_citations=20,
    )


def test_python_generic_analyzer_follows_two_hop_wrapper_path(tmp_path):
    root = tmp_path / "repo"
    source = (
        "def sink(value):\n"
        "    return value\n"
        "\n"
        "def normalize(value):\n"
        "    return sink(value)\n"
        "\n"
        "def handler(value):\n"
        "    return normalize(value)\n"
    )
    _write(root, "src/app.py", source)

    out = _analyzer(root, PythonPlugin({})).collect_evidence(
        _request(root, "src/app.py", 8)
    )

    assert out.supported is True
    assert "functions=3" in out.summary
    assert any("handler calls 'normalize'" in step for step in out.flow_chain)
    assert any("normalize calls 'sink'" in step for step in out.flow_chain)
    assert any(
        "path.callees: handler -> normalize -> sink" in section
        for section in out.sections
    )
    assert "src/app.py:7" in out.citations
    assert "FLOW_SINK_NOT_FOUND" not in out.unresolved_hops


def test_python_generic_analyzer_resolves_unresolved_hop_across_codebase(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "src/app.py",
        "def handler(value):\n    return normalize(value)\n",
    )
    _write(
        root,
        "src/helpers.py",
        "def normalize(value):\n    return value\n",
    )

    out = _analyzer(root, PythonPlugin({})).collect_evidence(
        _request(root, "src/app.py", 2)
    )

    assert any("evidence.cross_file.normalize" in section for section in out.sections)
    assert "src/helpers.py:1" in out.citations
    assert "FLOW_EXTERNAL_CALLEE_UNRESOLVED:normalize" not in out.unresolved_hops


def test_javascript_generic_analyzer_builds_call_graph(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "src/app.js",
        "function sink(value) { return value; }\n"
        "function handler(value) { return sink(value); }\n",
    )

    out = _analyzer(root, JavaScriptPlugin({})).collect_evidence(
        _request(root, "src/app.js", 2)
    )

    assert out.supported is True
    assert any("handler calls 'sink'" in step for step in out.flow_chain)


def test_typescript_generic_analyzer_builds_call_graph(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "src/app.ts",
        "function sink(value: string): string { return value; }\n"
        "function handler(value: string): string { return sink(value); }\n",
    )

    out = _analyzer(root, TypeScriptPlugin({})).collect_evidence(
        _request(root, "src/app.ts", 2)
    )

    assert out.supported is True
    assert any("handler calls 'sink'" in step for step in out.flow_chain)


def test_go_generic_analyzer_builds_call_graph(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "main.go",
        "package main\n"
        "func sink(value string) string { return value }\n"
        "func handler(value string) string { return sink(value) }\n",
    )

    out = _analyzer(root, GoPlugin({})).collect_evidence(_request(root, "main.go", 3))

    assert out.supported is True
    assert any("handler calls 'sink'" in step for step in out.flow_chain)


def test_rust_generic_analyzer_builds_call_graph(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "src/main.rs",
        "fn sink(value: i32) -> i32 { value }\n"
        "fn handler(value: i32) -> i32 { sink(value) }\n",
    )

    out = _analyzer(root, RustPlugin({})).collect_evidence(
        _request(root, "src/main.rs", 2)
    )

    assert out.supported is True
    assert any("handler calls 'sink'" in step for step in out.flow_chain)


def test_solidity_generic_analyzer_builds_call_graph(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "contracts/App.sol",
        "contract App {\n"
        "  function sink(uint value) internal returns (uint) { return value; }\n"
        "  function handler(uint value) public returns (uint) { return sink(value); }\n"
        "}\n",
    )

    out = _analyzer(root, SolidityPlugin({})).collect_evidence(
        _request(root, "contracts/App.sol", 3)
    )

    assert out.supported is True
    assert any("handler calls 'sink'" in step for step in out.flow_chain)


def test_java_generic_analyzer_builds_call_graph(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "src/App.java",
        "class App {\n"
        "  static String sink(String value) { return value; }\n"
        "  static String handler(String value) { return sink(value); }\n"
        "}\n",
    )

    out = _analyzer(root, JavaPlugin({})).collect_evidence(
        _request(root, "src/App.java", 3)
    )

    assert out.supported is True
    assert any("handler calls 'sink'" in step for step in out.flow_chain)


def test_csharp_generic_analyzer_builds_call_graph(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "src/App.cs",
        "class App {\n"
        "  static string Sink(string value) { return value; }\n"
        "  static string Handler(string value) { return Sink(value); }\n"
        "}\n",
    )

    out = _analyzer(root, CSharpPlugin({})).collect_evidence(
        _request(root, "src/App.cs", 3)
    )

    assert out.supported is True
    assert any("Handler calls 'Sink'" in step for step in out.flow_chain)


def test_bash_generic_analyzer_builds_call_graph(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "scripts/app.sh",
        'sink() {\n  printf \'%s\' "$1"\n}\nhandler() {\n  sink "$1"\n}\n',
    )

    out = _analyzer(root, BashPlugin({})).collect_evidence(
        _request(root, "scripts/app.sh", 5)
    )

    assert out.supported is True
    assert any("handler calls 'sink'" in step for step in out.flow_chain)


def test_lua_generic_analyzer_builds_call_graph(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        "app.lua",
        "function sink(value)\n  return value\nend\n"
        "function handler(value)\n  return sink(value)\nend\n",
    )

    out = _analyzer(root, LuaPlugin({})).collect_evidence(_request(root, "app.lua", 5))

    assert out.supported is True
    assert any("handler calls 'sink'" in step for step in out.flow_chain)
