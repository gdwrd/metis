# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HypothesisStatus, ResearchOptions


def test_template_injection_hunter_reports_cwe_1336(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def escape(value):\n"
        "    return value\n\n"
        "def render_template_string(value):\n"
        "    return value\n\n"
        "def render_user_template(request):\n"
        "    template = request.args.get('template')\n"
        "    return render_template_string(template)\n\n"
        "def render_safe_template(request):\n"
        "    template = escape(request.args.get('template'))\n"
        "    return render_template_string(template)\n\n"
        "def render_default_template():\n"
        "    return render_template_string('hello')\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("template_injection",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["render_user_template"].status == HypothesisStatus.PROVEN
    assert by_symbol["render_user_template"].vulnerability_class == "CWE-1336"
    assert by_symbol["render_user_template"].sarif_rule_id == "CWE-1336"
    assert (
        by_symbol["render_user_template"].missing_guard
        == "template escaping or input allowlist"
    )
    assert by_symbol["render_safe_template"].status == HypothesisStatus.KILLED
    assert by_symbol["render_safe_template"].observed_guard == "escape"
    assert by_symbol["render_default_template"].status == HypothesisStatus.UNRESOLVED
