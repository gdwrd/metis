# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HunterRegistry, HypothesisStatus, ResearchOptions


def test_xss_hunter_reports_html_sink_paths(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def sanitize(value):\n"
        "    return value\n\n"
        "def innerHTML(value):\n"
        "    return value\n\n"
        "def render_user_html(request):\n"
        "    html = request.args.get('html')\n"
        "    return innerHTML(html)\n\n"
        "def render_safe_html(request):\n"
        "    html = sanitize(request.args.get('html'))\n"
        "    return innerHTML(html)\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("xss",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["render_user_html"].status == HypothesisStatus.PROVEN
    assert by_symbol["render_user_html"].vulnerability_class == "CWE-79"
    assert by_symbol["render_safe_html"].status == HypothesisStatus.KILLED


def test_xss_hunter_is_promoted():
    metadata = HunterRegistry.default().metadata_for("xss")

    assert metadata.default_enabled is True
    assert metadata.experimental is False
    assert metadata.promotion_status == "promoted"
