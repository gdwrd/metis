# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import (
    EvidenceKind,
    EvidenceLedgerEntry,
    EvidenceObligation,
    EvidenceStatus,
    FlowStep,
    Hypothesis,
    HypothesisStatus,
    HypothesisVerifier,
    ResearchLesson,
    ResearchLessonSource,
    ResearchLessonType,
    ResearchPriority,
    evidence_completeness,
    generate_research_sarif,
)


def test_verifier_proves_only_when_required_obligations_are_satisfied():
    hypothesis = _hypothesis(
        evidence=[
            _entry("source", EvidenceStatus.SATISFIED),
            _entry("reachability", EvidenceStatus.SATISFIED),
            _entry("sink", EvidenceStatus.SATISFIED),
        ],
    )

    verified = HypothesisVerifier().verify(hypothesis)

    assert verified.status == HypothesisStatus.PROVEN
    assert verified.kill_reason is None
    assert verified.unresolved_reason is None


def test_verifier_kills_when_required_guard_evidence_fails():
    hypothesis = _hypothesis(
        evidence=[
            _entry("source", EvidenceStatus.SATISFIED),
            _entry("reachability", EvidenceStatus.SATISFIED),
            _entry("sink", EvidenceStatus.SATISFIED),
            _entry(
                "missing_guard",
                EvidenceStatus.FAILED,
                kind=EvidenceKind.GUARD_CHECK,
                claim="Guard require_admin is present.",
            ),
        ],
        obligations=("source", "reachability", "sink", "missing_guard"),
    )

    verified = HypothesisVerifier().verify(hypothesis)

    assert verified.status == HypothesisStatus.KILLED
    assert verified.kill_reason == (
        "Candidate invalidated by evidence: Guard require_admin is present."
    )
    assert verified.unresolved_reason is None


def test_verifier_leaves_missing_required_evidence_unresolved():
    hypothesis = _hypothesis(
        evidence=[
            _entry("source", EvidenceStatus.SATISFIED),
            _entry("reachability", EvidenceStatus.MISSING),
        ],
    )

    verified = HypothesisVerifier().verify(hypothesis)

    assert verified.status == HypothesisStatus.UNRESOLVED
    assert verified.unresolved_reason == "Missing required evidence: reachability, sink"
    assert verified.kill_reason is None
    assert {
        (entry.obligation, entry.status)
        for entry in verified.evidence
        if entry.tool == "hypothesis_verifier"
    } == {
        ("sink", EvidenceStatus.MISSING),
    }
    verifier_entries = [
        entry for entry in verified.evidence if entry.tool == "hypothesis_verifier"
    ]
    assert verifier_entries[0].evidence == [
        "bounded_evidence_policy=triage_evidence",
        "available_tools=",
    ]


def test_verifier_records_bounded_evidence_tools_for_missing_entries(tmp_path):
    hypothesis = _hypothesis(evidence=[])

    verified = HypothesisVerifier().verify_all(
        [hypothesis],
        codebase_path=str(tmp_path),
    )[0]

    verifier_entries = [
        entry for entry in verified.evidence if entry.tool == "hypothesis_verifier"
    ]
    assert verifier_entries
    assert verifier_entries[0].evidence == [
        "bounded_evidence_policy=triage_evidence",
        "available_tools=cat,find_name,grep,sed",
    ]


def test_verifier_ignores_evidence_for_other_hypotheses():
    hypothesis = _hypothesis(
        evidence=[
            _entry("source", EvidenceStatus.SATISFIED, hypothesis_id="hyp-other"),
            _entry("reachability", EvidenceStatus.SATISFIED, hypothesis_id="hyp-other"),
            _entry("sink", EvidenceStatus.SATISFIED, hypothesis_id="hyp-other"),
        ],
    )

    verified = HypothesisVerifier().verify(hypothesis)

    assert verified.status == HypothesisStatus.UNRESOLVED
    assert verified.unresolved_reason == (
        "Missing required evidence: reachability, sink, source"
    )
    synthetic_missing = [
        entry
        for entry in verified.evidence
        if entry.hypothesis_id == "hyp-test" and entry.status == EvidenceStatus.MISSING
    ]
    assert {entry.obligation for entry in synthetic_missing} == {
        "source",
        "reachability",
        "sink",
    }


def test_verifier_does_not_apply_file_scoped_suppression_to_locationless_hypothesis():
    scoped_lesson = ResearchLesson(
        id="lesson-scoped",
        type=ResearchLessonType.FALSE_POSITIVE_SUPPRESSION,
        source=ResearchLessonSource.KILLED_HYPOTHESIS,
        summary="Suppress only the original scoped handler.",
        pattern="test_hunter|request|handler",
        hunter="test_hunter",
        vulnerability_class="CWE-862",
        file="app.py",
        symbol="handler",
        metadata={"source": "request", "observed_guards": ["expected_guard"]},
    )
    locationless = _hypothesis(
        evidence=[
            _entry("source", EvidenceStatus.SATISFIED),
            _entry("reachability", EvidenceStatus.SATISFIED),
            _entry("sink", EvidenceStatus.SATISFIED),
        ],
    ).model_copy(
        update={
            "path": [],
            "locations": [],
            "observed_guard": "expected_guard",
        }
    )

    verified = HypothesisVerifier().verify(locationless, lessons=(scoped_lesson,))

    assert verified.status == HypothesisStatus.PROVEN
    assert verified.kill_reason is None
    assert all(entry.obligation != "lesson_suppression" for entry in verified.evidence)


def test_research_sarif_promotes_only_proven_hypotheses_with_properties():
    proven = HypothesisVerifier().verify(
        _hypothesis(
            hypothesis_id="hyp-proven",
            evidence=[
                _entry("source", EvidenceStatus.SATISFIED, hypothesis_id="hyp-proven"),
                _entry(
                    "reachability",
                    EvidenceStatus.SATISFIED,
                    hypothesis_id="hyp-proven",
                ),
                _entry("sink", EvidenceStatus.SATISFIED, hypothesis_id="hyp-proven"),
            ],
        )
    )
    killed = HypothesisVerifier().verify(
        _hypothesis(
            hypothesis_id="hyp-killed",
            evidence=[
                _entry("source", EvidenceStatus.SATISFIED, hypothesis_id="hyp-killed"),
                _entry(
                    "missing_guard",
                    EvidenceStatus.FAILED,
                    hypothesis_id="hyp-killed",
                ),
            ],
            obligations=("source", "missing_guard"),
        )
    )

    sarif = generate_research_sarif(
        [proven, killed],
        evidence_ledger_path=".metis/research/evidence.jsonl",
    )

    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "CWE-862"
    assert sarif["runs"][0]["tool"]["driver"]["rules"][-1]["id"] == "CWE-862"
    props = results[0]["properties"]
    assert props["metisHypothesisId"] == "hyp-proven"
    assert props["metisHypothesisStatus"] == "proven"
    assert props["metisHunter"] == "test_hunter"
    assert props["metisSarifRuleId"] == "CWE-862"
    assert props["metisSarifRuleTitle"] == "Test hypothesis"
    assert props["metisEvidenceLedger"] == ".metis/research/evidence.jsonl"
    assert props["metisEvidenceObligations"] == [
        "source",
        "reachability",
        "sink",
    ]
    assert props["metisEvidenceCompleteness"]["ratio"] == 1.0
    assert props["metisExpectedGuard"] == "expected_guard"
    assert props["metisMissingGuard"] == "expected_guard"
    assert props["metisEvidenceReferences"] == [
        "source:app.py:10",
        "reachability:app.py:10",
        "sink:app.py:10",
    ]
    assert evidence_completeness(proven)["missing"] == []


def test_research_sarif_ignores_foreign_evidence_metadata():
    proven = HypothesisVerifier().verify(
        _hypothesis(
            hypothesis_id="hyp-proven",
            evidence=[
                _entry("source", EvidenceStatus.SATISFIED, hypothesis_id="hyp-proven"),
                _entry(
                    "reachability",
                    EvidenceStatus.SATISFIED,
                    hypothesis_id="hyp-proven",
                ),
                _entry("sink", EvidenceStatus.SATISFIED, hypothesis_id="hyp-proven"),
                _entry("impact", EvidenceStatus.SATISFIED, hypothesis_id="hyp-other"),
            ],
        )
    )

    sarif = generate_research_sarif([proven])

    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["metisEvidenceCompleteness"] == {
        "required": ["source", "reachability", "sink"],
        "satisfied": ["reachability", "sink", "source"],
        "missing": [],
        "ratio": 1.0,
    }
    assert props["metisEvidenceReferences"] == [
        "source:app.py:10",
        "reachability:app.py:10",
        "sink:app.py:10",
    ]


def test_research_sarif_skips_proven_status_with_incomplete_owned_evidence():
    proven = HypothesisVerifier().verify(
        _hypothesis(
            hypothesis_id="hyp-proven",
            evidence=[
                _entry("source", EvidenceStatus.SATISFIED, hypothesis_id="hyp-proven"),
                _entry(
                    "reachability",
                    EvidenceStatus.SATISFIED,
                    hypothesis_id="hyp-proven",
                ),
                _entry("sink", EvidenceStatus.SATISFIED, hypothesis_id="hyp-proven"),
            ],
        )
    )
    stale_import = proven.model_copy(
        update={
            "evidence": [
                _entry("source", EvidenceStatus.SATISFIED, hypothesis_id="hyp-other"),
                _entry(
                    "reachability",
                    EvidenceStatus.SATISFIED,
                    hypothesis_id="hyp-other",
                ),
                _entry("sink", EvidenceStatus.SATISFIED, hypothesis_id="hyp-other"),
            ]
        }
    )

    sarif = generate_research_sarif([stale_import])

    assert sarif["runs"][0]["results"] == []


def _hypothesis(
    *,
    hypothesis_id: str = "hyp-test",
    evidence: list[EvidenceLedgerEntry],
    obligations: tuple[str, ...] = ("source", "reachability", "sink"),
) -> Hypothesis:
    step = FlowStep(file="app.py", line=10, symbol="handler", role="entrypoint")
    return Hypothesis(
        id=hypothesis_id,
        hunter="test_hunter",
        vulnerability_class="CWE-862",
        title="Test hypothesis",
        source="request",
        path=[step],
        sink="dangerous_call",
        expected_guard="expected_guard",
        missing_guard="expected_guard",
        impact="A protected operation is reachable without the expected guard.",
        evidence_obligations=[
            EvidenceObligation(name=obligation) for obligation in obligations
        ],
        evidence=evidence,
        status=HypothesisStatus.CANDIDATE,
        confidence=0.1,
        locations=[step],
        sarif_rule_id="CWE-862",
        priority=ResearchPriority.HIGH,
    )


def _entry(
    obligation: str,
    status: EvidenceStatus,
    *,
    hypothesis_id: str = "hyp-test",
    kind: EvidenceKind = EvidenceKind.STATIC_TRACE,
    claim: str | None = None,
) -> EvidenceLedgerEntry:
    return EvidenceLedgerEntry(
        hypothesis_id=hypothesis_id,
        obligation=obligation,
        status=status,
        kind=kind,
        claim=claim or f"{obligation} evidence",
        evidence=["app.py:10"],
        file="app.py",
        line=10,
        symbol="handler",
    )
