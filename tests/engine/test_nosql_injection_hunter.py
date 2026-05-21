# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HunterRegistry, HypothesisStatus, ResearchOptions


def test_nosql_injection_hunter_is_opt_in_and_rule_backed(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def schema(value):\n"
        "    return value\n\n"
        "def find(criteria):\n"
        "    return criteria\n\n"
        "def search(request):\n"
        "    criteria = request.args.get('q')\n"
        "    return find(criteria)\n\n"
        "def search_safe(request):\n"
        "    criteria = schema(request.args.get('q'))\n"
        "    return find(criteria)\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("nosql_injection",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["search"].status == HypothesisStatus.PROVEN
    assert by_symbol["search"].vulnerability_class == "CWE-943"
    assert by_symbol["search_safe"].status == HypothesisStatus.KILLED
    assert result.metric_summary["selected_hunters"] == ("nosql_injection",)


def test_nosql_injection_hunter_is_promoted():
    metadata = HunterRegistry.default().metadata_for("nosql_injection")

    assert metadata.default_enabled is True
    assert metadata.experimental is False
    assert metadata.promotion_status == "promoted"
