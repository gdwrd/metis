# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
from pydantic import ValidationError

from metis.engine.research import (
    EvidenceKind,
    EvidenceLedgerEntry,
    EvidenceObligation,
    EvidenceStatus,
    FlowStep,
    Hypothesis,
    HypothesisStatus,
    ResearchJsonlStore,
    ResearchRunResult,
)


def test_hypothesis_model_round_trips_with_evidence():
    hypothesis = _proven_hypothesis()

    payload = hypothesis.model_dump(mode="json")
    restored = Hypothesis.model_validate(payload)

    assert restored.status == HypothesisStatus.PROVEN
    assert restored.expected_guard == "require_project_member"
    assert restored.evidence[0].status == EvidenceStatus.SATISFIED


def test_proven_hypothesis_requires_all_required_evidence():
    with pytest.raises(ValidationError, match="missing required evidence"):
        _proven_hypothesis(evidence_names=("source",))


def test_killed_and_unresolved_require_reasons():
    with pytest.raises(ValidationError, match="kill_reason"):
        Hypothesis(
            id="hyp-killed",
            hunter="authz_outlier",
            vulnerability_class="CWE-862",
            title="Killed",
            source="/projects/<id>",
            path=[FlowStep(file="app.py", line=1, symbol="handler", role="entrypoint")],
            asset="projects",
            impact="No impact",
            status=HypothesisStatus.KILLED,
        )

    with pytest.raises(ValidationError, match="unresolved_reason"):
        Hypothesis(
            id="hyp-unresolved",
            hunter="authz_outlier",
            vulnerability_class="CWE-862",
            title="Unresolved",
            source="/status",
            path=[FlowStep(file="app.py", line=1, symbol="status", role="entrypoint")],
            asset="status",
            impact="Unknown",
            status=HypothesisStatus.UNRESOLVED,
        )


def test_research_jsonl_store_round_trips_hypotheses_and_evidence(tmp_path):
    hypothesis = _proven_hypothesis()
    store = ResearchJsonlStore(
        hypotheses_path=tmp_path / "hypotheses.jsonl",
        evidence_path=tmp_path / "evidence.jsonl",
    )

    store.append_hypothesis(hypothesis)
    store.append_evidence_entries(hypothesis.evidence)

    assert store.read_hypotheses() == [hypothesis]
    assert store.read_evidence() == hypothesis.evidence


def test_research_run_result_splits_status_buckets():
    proven = _proven_hypothesis()
    killed = Hypothesis(
        id="hyp-killed",
        hunter="authz_outlier",
        vulnerability_class="CWE-862",
        title="Killed",
        source="/projects/<id>",
        path=[FlowStep(file="app.py", line=1, symbol="handler", role="entrypoint")],
        asset="projects",
        impact="No impact",
        status=HypothesisStatus.KILLED,
        kill_reason="Guard present",
    )
    unresolved = Hypothesis(
        id="hyp-unresolved",
        hunter="authz_outlier",
        vulnerability_class="CWE-862",
        title="Unresolved",
        source="/status",
        path=[FlowStep(file="app.py", line=1, symbol="status", role="entrypoint")],
        asset="status",
        impact="Unknown",
        status=HypothesisStatus.UNRESOLVED,
        unresolved_reason="No comparable guard",
    )

    result = ResearchRunResult.from_hypotheses([proven, killed, unresolved])

    assert len(result.generated) == 3
    assert result.proven == [proven]
    assert result.killed == [killed]
    assert result.unresolved == [unresolved]


def _proven_hypothesis(evidence_names=("source", "missing_guard")):
    obligations = [
        EvidenceObligation(name="source"),
        EvidenceObligation(name="missing_guard"),
    ]
    evidence = [
        EvidenceLedgerEntry(
            hypothesis_id="hyp-proven",
            obligation=name,
            status=EvidenceStatus.SATISFIED,
            kind=EvidenceKind.DEFINITION,
            claim=f"{name} satisfied",
            evidence=["app.py:10"],
            file="app.py",
            line=10,
            symbol="update_project_settings",
        )
        for name in evidence_names
    ]
    return Hypothesis(
        id="hyp-proven",
        hunter="authz_outlier",
        vulnerability_class="CWE-862",
        title="Missing guard",
        source="/projects/<project_id>/settings",
        path=[
            FlowStep(
                file="app.py",
                line=10,
                symbol="update_project_settings",
                role="entrypoint",
            )
        ],
        asset="projects",
        expected_guard="require_project_member",
        missing_guard="require_project_member",
        impact="Project settings can be changed without authorization.",
        evidence_obligations=obligations,
        evidence=evidence,
        status=HypothesisStatus.PROVEN,
    )
