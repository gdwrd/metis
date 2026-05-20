# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil

import pytest

from metis.engine.research import HypothesisStatus, ResearchOptions
from metis.engine.research.hunters.authz_outlier import AuthzOutlierHunter


FIXTURE = "tests/fixtures/research/authz_outlier_app"


def test_authz_outlier_proves_kills_and_leaves_ambiguous_unresolved():
    result = AuthzOutlierHunter().hunt(FIXTURE)

    assert len(result.generated) == 3
    assert [item.status for item in result.proven] == [HypothesisStatus.PROVEN]
    assert [item.status for item in result.killed] == [HypothesisStatus.KILLED]
    assert [item.status for item in result.unresolved] == [
        HypothesisStatus.UNRESOLVED
    ]

    proven = result.proven[0]
    assert proven.hunter == "authz_outlier"
    assert proven.vulnerability_class == "CWE-862"
    assert proven.expected_guard == "require_project_member"
    assert proven.missing_guard == "require_project_member"
    assert proven.locations[0].symbol == "update_project_settings"
    assert {entry.obligation for entry in proven.evidence} == {
        "source",
        "reachability",
        "asset",
        "missing_guard",
        "impact",
    }

    killed = result.killed[0]
    assert killed.locations[0].symbol == "get_project"
    assert killed.kill_reason == "Equivalent guard require_project_member is present"
    assert killed.observed_guard == "require_project_member"
    assert {entry.obligation for entry in killed.evidence} == {
        item.name for item in killed.evidence_obligations
    }

    unresolved = result.unresolved[0]
    assert unresolved.locations[0].symbol == "status"
    assert unresolved.unresolved_reason == (
        "No dominant comparable authorization guard pattern"
    )
    assert {entry.obligation for entry in unresolved.evidence} == {
        item.name for item in unresolved.evidence_obligations
    }


def test_research_service_runs_authz_outlier_and_can_persist(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    result = engine.research.run(repo, options=ResearchOptions(persist=True))

    assert len(result.generated) == 3
    assert result.hypotheses_path.endswith(".metis/research/hypotheses.jsonl")
    assert result.evidence_ledger_path.endswith(".metis/research/evidence.jsonl")
    assert (tmp_path / ".metis" / "security_model.json").exists()
    assert (tmp_path / ".metis" / "security_graph.json").exists()


def test_research_service_uses_shared_security_model_for_authz(
    engine,
    monkeypatch,
    tmp_path,
):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    def _private_scan_should_not_run(*_args, **_kwargs):
        raise AssertionError("authz_outlier should use shared model context")

    monkeypatch.setattr(
        AuthzOutlierHunter,
        "_discover_handlers",
        _private_scan_should_not_run,
    )

    result = engine.research.run(repo)

    assert [item.status for item in result.proven] == [HypothesisStatus.PROVEN]
    assert [item.status for item in result.killed] == [HypothesisStatus.KILLED]
    assert [item.status for item in result.unresolved] == [
        HypothesisStatus.UNRESOLVED
    ]


def test_research_service_rejects_persistent_roots_outside_codebase(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    shutil.copytree(FIXTURE, outside)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    with pytest.raises(ValueError, match="inside the configured codebase path"):
        engine.research.run(outside, options=ResearchOptions(persist=True))

    with pytest.raises(ValueError, match="inside the configured codebase path"):
        engine.research.run(outside, options=ResearchOptions(persist=False))
