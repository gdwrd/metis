# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HypothesisStatus, ResearchOptions


def test_command_injection_hunter_reports_cwe_78(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import subprocess\n\n"
        "def validate_command(value):\n"
        "    return value\n\n"
        "def run_command(request):\n"
        "    cmd = request.args.get('cmd')\n"
        "    subprocess.run(cmd, shell=True)\n\n"
        "def run_safe_command(request):\n"
        "    cmd = validate_command(request.args.get('cmd'))\n"
        "    subprocess.run(cmd, shell=True)\n\n"
        "def run_default_command():\n"
        "    subprocess.run('id', shell=True)\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("command_injection",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["run_command"].status == HypothesisStatus.PROVEN
    assert by_symbol["run_command"].vulnerability_class == "CWE-78"
    assert by_symbol["run_command"].sarif_rule_id == "CWE-78"
    assert by_symbol["run_command"].missing_guard == "command sanitizer or allowlist"
    assert by_symbol["run_safe_command"].status == HypothesisStatus.KILLED
    assert by_symbol["run_safe_command"].observed_guard == "validate_command"
    assert by_symbol["run_default_command"].status == HypothesisStatus.UNRESOLVED


def test_command_injection_hunter_uses_javascript_graph_metadata(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        "const child_process = require('child_process');\n"
        "function run(req) {\n"
        "  child_process.exec(req.query.cmd);\n"
        "}\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("command_injection",), rebuild=True),
    )

    assert any(item.vulnerability_class == "CWE-78" for item in result.proven)


def test_command_injection_hunter_normalizes_csharp_process_start(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Worker.cs").write_text(
        "class Worker {\n"
        "  void Run(string input) {\n"
        "    System.Diagnostics.Process.Start(input);\n"
        "  }\n"
        "  void RunSafe(string input) {\n"
        "    var clean = ShellEscape(input);\n"
        "    System.Diagnostics.Process.Start(clean);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("command_injection",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["Run"].status == HypothesisStatus.PROVEN
    assert by_symbol["Run"].sink == "process.start"
    assert by_symbol["RunSafe"].status == HypothesisStatus.KILLED
    assert by_symbol["RunSafe"].observed_guard.lower() == "shellescape"
