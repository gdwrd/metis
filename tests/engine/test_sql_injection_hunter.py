# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HypothesisStatus, ResearchOptions


def test_sql_injection_hunter_proves_php_and_perl_server_script_paths(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "search.php").write_text(
        "<?php\n"
        "$id = $_GET['id'];\n"
        "$sql = \"SELECT * FROM users WHERE id='$id'\";\n"
        "$db->query($sql);\n",
        encoding="utf-8",
    )
    (repo / "update_mix.pl").write_text(
        "#!/usr/bin/perl\n"
        "$uniqueid=$ARGV[0];\n"
        "$query=\"INSERT INTO recordings VALUES('$uniqueid')\";\n"
        "$dbh->do($query);\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(repo, options=ResearchOptions(hunters=("sql_injection",)))

    assert result.metric_summary["selected_hunters"] == ("sql_injection",)
    assert result.metric_summary["sql_injection"]["proven"] == 2
    assert {item.status for item in result.generated} == {HypothesisStatus.PROVEN}
    by_file = {item.locations[0].file: item for item in result.generated}
    assert by_file["search.php"].vulnerability_class == "CWE-89"
    assert by_file["search.php"].source == "$_GET"
    assert by_file["search.php"].sink == "db.query"
    assert by_file["update_mix.pl"].source in {"$ARGV[", "$ARGV"}
    assert by_file["update_mix.pl"].sink == "dbh.do"
    for hypothesis in result.generated:
        assert hypothesis.missing_guard == "SQL parameterization or escaping"
        assert {entry.obligation for entry in hypothesis.evidence} == {
            "source",
            "reachability",
            "sql_sink",
            "missing_parameterization",
            "impact",
        }
