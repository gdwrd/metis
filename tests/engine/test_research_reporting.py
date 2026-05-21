# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import shutil

from metis.engine.research import (
    EvidenceStatus,
    HypothesisStatus,
    ResearchOptions,
    evidence_completeness,
)


def test_research_sarif_uses_class_specific_rules_and_no_proof_decisions(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    shutil.copytree("tests/benchmarks/cases/research/xss", repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    result = engine.research.run(
        repo,
        options=ResearchOptions(
            hunters=("xss",),
            persist=True,
            proof_artifacts=True,
            emit_killed=True,
        ),
    )

    assert result.proof_artifact_paths == []
    assert result.metric_summary["proof_artifacts"]["refused"] == 2
    for hypothesis in result.proven:
        proof_entries = [
            entry
            for entry in hypothesis.evidence
            if entry.obligation == "proof_artifact"
        ]
        assert [entry.status for entry in proof_entries] == [
            EvidenceStatus.NOT_APPLICABLE
        ]

    sarif = json.loads(
        (tmp_path / ".metis" / "research" / "results.sarif").read_text(
            encoding="utf-8"
        )
    )
    run = sarif["runs"][0]
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} >= {"CWE-79"}
    assert {item["ruleId"] for item in run["results"]} == {"CWE-79"}
    for item in run["results"]:
        props = item["properties"]
        assert props["metisHunter"] == "xss"
        assert props["metisResearchClass"] == "CWE-79"
        assert props["metisSarifRuleId"] == "CWE-79"
        assert props["metisProofArtifacts"] == []
        assert props["metisProofDecision"]["status"] == "no_proof"
        if props["metisHypothesisStatus"] == HypothesisStatus.PROVEN.value:
            assert "only Python, native, and hardware" in props[
                "metisProofDecision"
            ]["reason"]


def test_promoted_hunter_evidence_is_complete_by_hunter_and_class(engine, tmp_path):
    cases = {
        "nosql_injection": (
            "CWE-943",
            "tests/benchmarks/cases/research/nosql_injection",
        ),
        "xxe": ("CWE-611", "tests/benchmarks/cases/research/xxe"),
        "xss": ("CWE-79", "tests/benchmarks/cases/research/xss"),
        "crypto_misuse": (
            "CWE-327",
            "tests/benchmarks/cases/research/crypto_misuse",
        ),
    }

    for hunter, (vulnerability_class, fixture) in cases.items():
        repo = tmp_path / hunter
        shutil.copytree(fixture, repo)
        engine.codebase_path = str(tmp_path)
        engine._config.codebase_path = str(tmp_path)

        result = engine.research.run(
            repo,
            options=ResearchOptions(
                hunters=(hunter,),
                rebuild=True,
                persist=False,
                emit_killed=True,
            ),
        )

        assert result.proven
        assert {item.hunter for item in result.proven} == {hunter}
        assert {item.vulnerability_class for item in result.proven} == {
            vulnerability_class
        }
        for hypothesis in result.proven:
            obligations = {item.name for item in hypothesis.evidence_obligations}
            assert {"source", "reachability", "impact"} <= obligations
            assert any("sink" in obligation for obligation in obligations)
            assert any(
                obligation.startswith("missing_")
                or "mitigation" in obligation
                or "guard" in obligation
                for obligation in obligations
            )
            assert hypothesis.sarif_rule_id == vulnerability_class
            assert evidence_completeness(hypothesis)["missing"] == []
            assert hypothesis.status == HypothesisStatus.PROVEN
