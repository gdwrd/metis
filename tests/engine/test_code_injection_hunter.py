# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HypothesisStatus, ResearchOptions


def test_code_injection_hunter_reports_cwe_94(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def validate_expr(value):\n"
        "    return value\n\n"
        "def eval_expr(request):\n"
        "    expr = request.args.get('expr')\n"
        "    return eval(expr)\n\n"
        "def eval_safe_expr(request):\n"
        "    expr = validate_expr(request.args.get('expr'))\n"
        "    return eval(expr)\n\n"
        "def eval_default_expr():\n"
        "    return eval('1 + 1')\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("code_injection",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["eval_expr"].status == HypothesisStatus.PROVEN
    assert by_symbol["eval_expr"].vulnerability_class == "CWE-94"
    assert by_symbol["eval_expr"].sarif_rule_id == "CWE-94"
    assert by_symbol["eval_expr"].missing_guard == "code input validation or allowlist"
    assert by_symbol["eval_safe_expr"].status == HypothesisStatus.KILLED
    assert by_symbol["eval_safe_expr"].observed_guard == "validate_expr"
    assert by_symbol["eval_default_expr"].status == HypothesisStatus.UNRESOLVED


def test_code_injection_hunter_normalizes_javascript_vm_execution(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        "function run(req, vm) {\n"
        "  const expr = req.query.expr;\n"
        "  return vm.runInNewContext(expr);\n"
        "}\n"
        "function runSafe(req) {\n"
        "  const expr = validate(req.query.expr);\n"
        "  return eval(expr);\n"
        "}\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("code_injection",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["run"].status == HypothesisStatus.PROVEN
    assert by_symbol["run"].sink == "vm.runin"
    assert by_symbol["runSafe"].status == HypothesisStatus.KILLED
    assert by_symbol["runSafe"].observed_guard == "validate"
