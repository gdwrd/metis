# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil

from metis.engine.research import HypothesisStatus, ResearchOptions

FIXTURE = "tests/fixtures/research/memory_lifetime_app"


def test_memory_lifetime_hunter_proves_kills_and_leaves_unresolved(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("memory_lifetime",)),
    )

    assert result.metric_summary["selected_hunters"] == ("memory_lifetime",)
    assert "memory_lifetime" in result.metric_summary["available_hunters"]
    assert result.metric_summary["memory_lifetime"]["generated"] == 3
    assert result.metric_summary["memory_lifetime"]["proven"] == 1
    assert result.metric_summary["memory_lifetime"]["killed"] == 1
    assert result.metric_summary["memory_lifetime"]["unresolved"] == 1

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    proven = by_symbol["finish_request_callback"]
    assert proven.status == HypothesisStatus.PROVEN
    assert proven.vulnerability_class == "CWE-416"
    assert proven.missing_guard == "ownership transfer or post-free guard"
    assert {entry.obligation for entry in proven.evidence} == {
        "source",
        "lifetime_transition",
        "post_lifetime_use",
        "missing_lifetime_guard",
        "impact",
    }

    killed = by_symbol["finish_request_safe"]
    assert killed.status == HypothesisStatus.KILLED
    assert killed.observed_guard == "null_after_free"
    assert "null_after_free" in str(killed.kill_reason)

    unresolved = by_symbol["cleanup_cache"]
    assert unresolved.status == HypothesisStatus.UNRESOLVED
    assert unresolved.unresolved_reason == (
        "No lifecycle or attacker-controlled trigger evidence"
    )


def test_memory_lifetime_hunter_does_not_emit_for_web_fixture(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree("tests/fixtures/research/authz_outlier_app", repo)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("memory_lifetime",)),
    )

    assert result.generated == []
