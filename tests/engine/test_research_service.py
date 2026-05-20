# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil

import pytest

from metis.engine.research import (
    EvidenceKind,
    EvidenceQuery,
    EvidenceStatus,
    HypothesisQuery,
    HypothesisStatus,
    ResearchRunMode,
    ResearchRunRequest,
    ResearchRunState,
    ResearchRunStatus,
)
from pydantic import ValidationError


AUTHZ_FIXTURE = "tests/fixtures/research/authz_outlier_app"
VARIANT_FIXTURE = "tests/fixtures/research/variant_authz_app"


def test_research_run_request_converts_to_options():
    request = ResearchRunRequest(
        hunters="authz_outlier,injection_path",
        persist=True,
        rebuild=True,
        research_budget="quick",
        emit_killed=True,
        emit_unresolved=True,
        proof_artifacts=True,
        evidence_policy="triage_evidence",
        hypotheses_path="hypotheses.jsonl",
        evidence_ledger_path="evidence.jsonl",
        sarif_path="results.sarif",
        research_report_path="report.json",
    )

    options = request.to_options()

    assert options.hunters == ("authz_outlier", "injection_path")
    assert options.persist is True
    assert options.rebuild is True
    assert options.research_budget == "quick"
    assert options.emit_killed is True
    assert options.emit_unresolved is True
    assert options.proof_artifacts is True
    assert options.evidence_policy == "triage_evidence"
    assert options.hypotheses_path == "hypotheses.jsonl"
    assert options.evidence_ledger_path == "evidence.jsonl"
    assert options.sarif_path == "results.sarif"
    assert options.research_report_path == "report.json"


def test_variant_request_requires_source():
    with pytest.raises(ValueError, match="variant research requests require"):
        ResearchRunRequest(mode=ResearchRunMode.VARIANTS)


def test_api_models_are_frozen():
    request = ResearchRunRequest()
    status = ResearchRunStatus(request=request)

    with pytest.raises(ValidationError, match="frozen"):
        request.root = "other"
    with pytest.raises(ValidationError, match="frozen"):
        status.error = "changed"
    with pytest.raises(ValidationError, match="frozen"):
        HypothesisQuery().symbol = "changed"
    with pytest.raises(ValidationError, match="frozen"):
        EvidenceQuery().obligation = "changed"


def test_research_service_runs_api_request_and_builds_status(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(AUTHZ_FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    request = ResearchRunRequest(
        root=str(repo),
        hunters=("authz_outlier",),
        persist=True,
        emit_killed=True,
        emit_unresolved=True,
    )

    result = engine.research.run_request(request)
    status = ResearchRunStatus.from_result(
        result,
        job_id="research-test",
        request=request,
        started_at="2026-05-20T00:00:00Z",
        completed_at="2026-05-20T00:00:01Z",
    )

    assert [item.status for item in result.proven] == [HypothesisStatus.PROVEN]
    assert status.job_id == "research-test"
    assert status.state == ResearchRunState.SUCCEEDED
    assert status.generated_count == 3
    assert status.proven_count == 1
    assert status.killed_count == 1
    assert status.unresolved_count == 1
    assert status.hypotheses_path.endswith(".metis/research/hypotheses.jsonl")
    assert status.evidence_ledger_path.endswith(".metis/research/evidence.jsonl")
    assert status.sarif_path.endswith(".metis/research/results.sarif")
    assert status.research_report_path.endswith(".metis/research/report.json")
    assert result.metric_summary["evidence_policy"] == "triage_evidence"


def test_research_service_tracks_async_request_status(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(AUTHZ_FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    request = ResearchRunRequest(root=str(repo), hunters=("authz_outlier",))
    queued = engine.research.start_request(request)

    assert queued.state == ResearchRunState.QUEUED
    engine.research._job_futures[queued.job_id].result(timeout=10)

    completed = engine.research.get_run_status(queued.job_id)
    result = engine.research.get_run_result(queued.job_id)

    assert completed.state == ResearchRunState.SUCCEEDED
    assert completed.generated_count == 3
    assert result is not None
    assert len(result.generated) == 3


def test_research_service_returns_defensive_queued_status(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(AUTHZ_FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    queued = engine.research.start_request(
        ResearchRunRequest(root=str(repo), hunters=("authz_outlier",))
    )
    queued.metric_summary["caller"] = "controlled"
    with pytest.raises(AttributeError):
        queued.proof_artifact_paths.append("caller-controlled")
    engine.research._job_futures[queued.job_id].result(timeout=10)

    stored_status = engine.research.get_run_status(queued.job_id)

    assert "caller" not in stored_status.metric_summary
    assert "caller-controlled" not in stored_status.proof_artifact_paths


def test_research_service_returns_defensive_status_and_result_copies(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(AUTHZ_FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    queued = engine.research.start_request(
        ResearchRunRequest(root=str(repo), hunters=("authz_outlier",))
    )
    engine.research._job_futures[queued.job_id].result(timeout=10)

    status = engine.research.get_run_status(queued.job_id)
    result = engine.research.get_run_result(queued.job_id)

    assert result is not None
    result.generated.clear()

    stored_result = engine.research.get_run_result(queued.job_id)
    stored_status = engine.research.get_run_status(queued.job_id)

    assert stored_result is not None
    assert len(stored_result.generated) == 3
    assert stored_status.generated_count == status.generated_count == 3


def test_research_service_tracks_async_request_failures(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    shutil.copytree(AUTHZ_FIXTURE, outside)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    queued = engine.research.start_request(ResearchRunRequest(root=str(outside)))

    with pytest.raises(ValueError, match="inside the configured codebase path"):
        engine.research._job_futures[queued.job_id].result(timeout=10)

    failed = engine.research.get_run_status(queued.job_id)

    assert failed.state == ResearchRunState.FAILED
    assert failed.error is not None
    assert "inside the configured codebase path" in failed.error
    assert engine.research.get_run_result(queued.job_id) is None


def test_research_service_query_helpers_filter_hypotheses_and_evidence(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    shutil.copytree(AUTHZ_FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)
    result = engine.research.run_request(
        ResearchRunRequest(root=str(repo), hunters=("authz_outlier",))
    )

    hypotheses = engine.research.query_hypotheses(
        result,
        HypothesisQuery(
            statuses=(HypothesisStatus.PROVEN,),
            symbol="update_project_settings",
        ),
    )
    missing_guard_evidence = engine.research.query_evidence(
        result,
        EvidenceQuery(
            hypothesis_id=hypotheses[0].id,
            statuses=(EvidenceStatus.SATISFIED,),
            kinds=(EvidenceKind.NEGATIVE_EVIDENCE,),
            obligation="missing_guard",
        ),
    )

    assert [item.status for item in hypotheses] == [HypothesisStatus.PROVEN]
    assert [entry.obligation for entry in missing_guard_evidence] == [
        "missing_guard"
    ]


def test_research_service_job_scoped_queries_and_cleanup(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(AUTHZ_FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    queued = engine.research.start_request(
        ResearchRunRequest(root=str(repo), hunters=("authz_outlier",))
    )
    assert engine.research.query_run_hypotheses(queued.job_id) is None
    engine.research._job_futures[queued.job_id].result(timeout=10)

    hypotheses = engine.research.query_run_hypotheses(
        queued.job_id,
        HypothesisQuery(statuses=(HypothesisStatus.PROVEN,)),
    )
    evidence = engine.research.query_run_evidence(
        queued.job_id,
        EvidenceQuery(
            hypothesis_id=hypotheses[0].id,
            obligation="missing_guard",
        ),
    )

    assert hypotheses is not None
    assert [item.status for item in hypotheses] == [HypothesisStatus.PROVEN]
    assert evidence is not None
    assert [entry.obligation for entry in evidence] == ["missing_guard"]
    assert engine.research.forget_request(queued.job_id) is True
    assert engine.research.forget_request(queued.job_id) is False
    with pytest.raises(KeyError, match="Unknown research job_id"):
        engine.research.get_run_status(queued.job_id)


def test_research_service_runs_variant_api_request(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(VARIANT_FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    result = engine.research.run_request(
        ResearchRunRequest(
            root=str(repo),
            mode=ResearchRunMode.VARIANTS,
            from_fix=str(repo / "fix_get_project.patch"),
            persist=True,
            emit_killed=True,
        )
    )

    assert [item.status for item in result.proven] == [HypothesisStatus.PROVEN]
    assert [item.status for item in result.killed] == [HypothesisStatus.KILLED]
    assert result.metric_summary["evidence_policy"] == "triage_evidence"
    assert result.hypotheses_path.endswith(".metis/research/hypotheses.jsonl")
