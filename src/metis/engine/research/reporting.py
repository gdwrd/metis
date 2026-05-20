# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from metis.engine.research.models import (
    EvidenceKind,
    EvidenceLedgerEntry,
    EvidenceStatus,
    FlowStep,
    Hypothesis,
    HypothesisStatus,
)
from metis.sarif.writer import generate_sarif


def generate_research_sarif(
    hypotheses: Iterable[Hypothesis],
    *,
    evidence_ledger_path: str | None = None,
    include_statuses: tuple[HypothesisStatus, ...] = (HypothesisStatus.PROVEN,),
    tool_name: str = "Metis Research",
    automation_id: str = "metis-research-run-1",
) -> dict[str, Any]:
    return generate_sarif(
        hypotheses_to_review_results(
            hypotheses,
            evidence_ledger_path=evidence_ledger_path,
            include_statuses=include_statuses,
        ),
        tool_name=tool_name,
        automation_id=automation_id,
    )


def write_research_sarif(
    hypotheses: Iterable[Hypothesis],
    path: str | os.PathLike[str],
    *,
    evidence_ledger_path: str | None = None,
    include_statuses: tuple[HypothesisStatus, ...] = (HypothesisStatus.PROVEN,),
) -> str:
    sarif = generate_research_sarif(
        hypotheses,
        evidence_ledger_path=evidence_ledger_path,
        include_statuses=include_statuses,
    )
    sarif_path = Path(path)
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = sarif_path.with_suffix(sarif_path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(sarif, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_path, sarif_path)
    return str(sarif_path)


def hypotheses_to_review_results(
    hypotheses: Iterable[Hypothesis],
    *,
    evidence_ledger_path: str | None = None,
    include_statuses: tuple[HypothesisStatus, ...] = (HypothesisStatus.PROVEN,),
) -> dict[str, Any]:
    reviews_by_file: dict[str, list[dict[str, Any]]] = {}
    include = set(include_statuses)
    for hypothesis in hypotheses:
        if hypothesis.status not in include:
            continue
        completeness = evidence_completeness(hypothesis)
        if hypothesis.status == HypothesisStatus.PROVEN and completeness["missing"]:
            continue
        location = _primary_location(hypothesis)
        file_path = location.file if location is not None else "<unknown>"
        line_number = location.line if location is not None else 1
        reviews_by_file.setdefault(file_path, []).append(
            {
                "issue": hypothesis.title,
                "line_number": line_number or 1,
                "severity": _priority_to_severity(str(hypothesis.priority.value)),
                "cwe": hypothesis.vulnerability_class,
                "confidence": hypothesis.confidence,
                "reasoning": hypothesis.impact,
                "mitigation": _mitigation_for(hypothesis),
                "properties": _hypothesis_properties(
                    hypothesis,
                    evidence_ledger_path=evidence_ledger_path,
                ),
            }
        )
    return {
        "reviews": [
            {
                "file_path": file_path,
                "file": file_path,
                "reviews": reviews,
            }
            for file_path, reviews in sorted(reviews_by_file.items())
        ]
    }


def evidence_completeness(hypothesis: Hypothesis) -> dict[str, Any]:
    required = [
        obligation.name
        for obligation in hypothesis.evidence_obligations
        if obligation.required
    ]
    owned_evidence = _owned_evidence(hypothesis)
    satisfied = sorted(
        {
            entry.obligation
            for entry in owned_evidence
            if entry.status == EvidenceStatus.SATISFIED
            and entry.obligation in set(required)
        }
    )
    missing = sorted(set(required) - set(satisfied))
    total = len(required)
    return {
        "required": required,
        "satisfied": satisfied,
        "missing": missing,
        "ratio": 1.0 if total == 0 else len(satisfied) / total,
    }


def _hypothesis_properties(
    hypothesis: Hypothesis,
    *,
    evidence_ledger_path: str | None,
) -> dict[str, Any]:
    completeness = evidence_completeness(hypothesis)
    return {
        "metisHypothesisId": hypothesis.id,
        "metisHypothesisStatus": hypothesis.status.value,
        "metisHunter": hypothesis.hunter,
        "metisResearchClass": hypothesis.vulnerability_class,
        "metisEvidenceLedger": evidence_ledger_path,
        "metisEvidenceObligations": [
            obligation.name for obligation in hypothesis.evidence_obligations
        ],
        "metisEvidenceCompleteness": completeness,
        "metisExpectedGuard": hypothesis.expected_guard,
        "metisObservedGuard": hypothesis.observed_guard,
        "metisMissingGuard": hypothesis.missing_guard,
        "metisProofArtifacts": _proof_artifacts(hypothesis),
        "metisLessonsUsed": list(hypothesis.lesson_refs),
        "metisEvidenceReferences": [
            _evidence_reference(entry) for entry in _owned_evidence(hypothesis)
        ],
    }


def _primary_location(hypothesis: Hypothesis) -> FlowStep | None:
    if hypothesis.locations:
        return hypothesis.locations[0]
    if hypothesis.path:
        return hypothesis.path[0]
    return None


def _priority_to_severity(priority: str) -> str:
    return {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }.get(priority.lower(), "Medium")


def _mitigation_for(hypothesis: Hypothesis) -> str:
    if hypothesis.expected_guard:
        return f"Add or restore the expected guard: {hypothesis.expected_guard}."
    return "Add the missing guard, sanitizer, or policy check proven by the ledger."


def _evidence_reference(entry) -> str:
    if entry.file and entry.line:
        return f"{entry.obligation}:{entry.file}:{entry.line}"
    if entry.file:
        return f"{entry.obligation}:{entry.file}"
    return entry.obligation


def _proof_artifacts(hypothesis: Hypothesis) -> list[str]:
    artifacts: list[str] = []
    for entry in _owned_evidence(hypothesis):
        if (
            entry.kind == EvidenceKind.PROOF_ARTIFACT
            and entry.status == EvidenceStatus.SATISFIED
            and entry.file
        ):
            artifacts.append(entry.file)
    return sorted(dict.fromkeys(artifacts))


def _owned_evidence(hypothesis: Hypothesis) -> list[EvidenceLedgerEntry]:
    return [
        entry for entry in hypothesis.evidence if entry.hypothesis_id == hypothesis.id
    ]
