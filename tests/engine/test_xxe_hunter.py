# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HunterRegistry, HypothesisStatus, ResearchOptions


def test_xxe_hunter_reports_xml_parser_paths(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def defusedxml(value):\n"
        "    return value\n\n"
        "def parsexml(value):\n"
        "    return value\n\n"
        "def parse_user_xml(request):\n"
        "    xml = request.args.get('xml')\n"
        "    return parsexml(xml)\n\n"
        "def parse_safe_xml(request):\n"
        "    xml = defusedxml(request.args.get('xml'))\n"
        "    return parsexml(xml)\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("xxe",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["parse_user_xml"].status == HypothesisStatus.PROVEN
    assert by_symbol["parse_user_xml"].vulnerability_class == "CWE-611"
    assert by_symbol["parse_safe_xml"].status == HypothesisStatus.KILLED


def test_xxe_hunter_is_promoted():
    metadata = HunterRegistry.default().metadata_for("xxe")

    assert metadata.default_enabled is True
    assert metadata.experimental is False
    assert metadata.promotion_status == "promoted"
