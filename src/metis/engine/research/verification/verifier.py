# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable

from metis.engine.tools import build_toolbox
from metis.engine.research.learning import (
    false_positive_suppression_matches,
    observed_guards_for_hypothesis,
)
from metis.engine.research.models import (
    EvidenceKind,
    EvidenceLedgerEntry,
    EvidenceStatus,
    Hypothesis,
    HypothesisStatus,
    ResearchLesson,
    SourceTrust,
    utc_now,
)


class HypothesisVerifier:
    """Deterministically adjudicate hypotheses from ledger entries."""

    def verify_all(
        self,
        hypotheses: Iterable[Hypothesis],
        *,
        lessons: tuple[ResearchLesson, ...] = (),
        evidence_policy: str = "triage_evidence",
        codebase_path: str | None = None,
    ) -> list[Hypothesis]:
        evidence_tool_names = _bounded_evidence_tool_names(
            evidence_policy=evidence_policy,
            codebase_path=codebase_path,
        )
        return [
            self.verify(
                hypothesis,
                lessons=lessons,
                evidence_policy=evidence_policy,
                evidence_tool_names=evidence_tool_names,
            )
            for hypothesis in hypotheses
        ]

    def verify(
        self,
        hypothesis: Hypothesis,
        *,
        lessons: tuple[ResearchLesson, ...] = (),
        evidence_policy: str = "triage_evidence",
        evidence_tool_names: tuple[str, ...] = (),
    ) -> Hypothesis:
        suppression = _suppression_lesson_for(hypothesis, lessons)
        if suppression is not None:
            evidence = [
                *hypothesis.evidence,
                _lesson_suppression_entry(hypothesis, suppression),
            ]
            return hypothesis.model_copy(
                update={
                    "status": HypothesisStatus.KILLED,
                    "kill_reason": f"Candidate suppressed by lesson {suppression.id}",
                    "unresolved_reason": None,
                    "evidence": evidence,
                    "lesson_refs": sorted({*hypothesis.lesson_refs, suppression.id}),
                    "updated_at": utc_now(),
                }
            )
        required = {
            obligation.name
            for obligation in hypothesis.evidence_obligations
            if obligation.required
        }
        if not required:
            return hypothesis.model_copy(update={"updated_at": utc_now()})

        evidence_by_obligation: dict[str, list[EvidenceLedgerEntry]] = {
            obligation: [] for obligation in required
        }
        for entry in hypothesis.evidence:
            if entry.hypothesis_id == hypothesis.id and entry.obligation in required:
                evidence_by_obligation.setdefault(entry.obligation, []).append(entry)

        failed = [
            entry
            for entries in evidence_by_obligation.values()
            for entry in entries
            if entry.status == EvidenceStatus.FAILED
        ]
        if failed:
            kill_reason = hypothesis.kill_reason or _kill_reason(failed[0])
            return hypothesis.model_copy(
                update={
                    "status": HypothesisStatus.KILLED,
                    "kill_reason": kill_reason,
                    "unresolved_reason": None,
                    "updated_at": utc_now(),
                }
            )

        satisfied = {
            obligation
            for obligation, entries in evidence_by_obligation.items()
            if any(entry.status == EvidenceStatus.SATISFIED for entry in entries)
        }
        missing = sorted(required - satisfied)
        evidence = list(hypothesis.evidence)
        for obligation in missing:
            if not evidence_by_obligation.get(obligation):
                missing_entry = _missing_evidence_entry(
                    hypothesis,
                    obligation,
                    evidence_policy=evidence_policy,
                    evidence_tool_names=evidence_tool_names,
                )
                evidence.append(missing_entry)
                evidence_by_obligation.setdefault(obligation, []).append(missing_entry)
        explicit_missing = [
            entry
            for entries in evidence_by_obligation.values()
            for entry in entries
            if entry.status == EvidenceStatus.MISSING
        ]
        if missing or explicit_missing:
            unresolved_reason = hypothesis.unresolved_reason or _unresolved_reason(
                missing,
                explicit_missing,
            )
            return hypothesis.model_copy(
                update={
                    "status": HypothesisStatus.UNRESOLVED,
                    "kill_reason": None,
                    "unresolved_reason": unresolved_reason,
                    "evidence": evidence,
                    "updated_at": utc_now(),
                }
            )

        return hypothesis.model_copy(
            update={
                "status": HypothesisStatus.PROVEN,
                "kill_reason": None,
                "unresolved_reason": None,
                "updated_at": utc_now(),
            }
        )


def _kill_reason(entry: EvidenceLedgerEntry) -> str:
    label = "Candidate killed by evidence"
    if entry.kind in {
        EvidenceKind.GUARD_CHECK,
        EvidenceKind.SANITIZER_CHECK,
        EvidenceKind.CONFIG_CHECK,
        EvidenceKind.NEGATIVE_EVIDENCE,
    }:
        label = "Candidate invalidated by evidence"
    return f"{label}: {entry.claim}"


def _unresolved_reason(
    missing: list[str],
    explicit_missing: list[EvidenceLedgerEntry],
) -> str:
    if missing:
        return "Missing required evidence: " + ", ".join(missing)
    obligations = sorted({entry.obligation for entry in explicit_missing})
    if obligations:
        return "Missing required evidence: " + ", ".join(obligations)
    return "Required evidence could not be collected within bounds"


def _missing_evidence_entry(
    hypothesis: Hypothesis,
    obligation: str,
    *,
    evidence_policy: str,
    evidence_tool_names: tuple[str, ...],
) -> EvidenceLedgerEntry:
    location = None
    if hypothesis.locations:
        location = hypothesis.locations[0]
    elif hypothesis.path:
        location = hypothesis.path[0]
    return EvidenceLedgerEntry(
        hypothesis_id=hypothesis.id,
        obligation=obligation,
        status=EvidenceStatus.MISSING,
        kind=EvidenceKind.NEGATIVE_EVIDENCE,
        claim=f"No valid evidence entry satisfied required obligation {obligation}.",
        evidence=[
            f"bounded_evidence_policy={evidence_policy}",
            f"available_tools={','.join(evidence_tool_names)}",
        ],
        file=location.file if location is not None else None,
        line=location.line if location is not None else None,
        symbol=location.symbol if location is not None else None,
        tool="hypothesis_verifier",
        tool_input=evidence_policy,
        source_trust=SourceTrust.TOOL_OUTPUT,
    )


def _bounded_evidence_tool_names(
    *,
    evidence_policy: str,
    codebase_path: str | None,
) -> tuple[str, ...]:
    if not codebase_path:
        return ()
    policy = str(evidence_policy or "").strip() or "triage_evidence"
    toolbox = build_toolbox(policy=policy, codebase_path=codebase_path)
    return toolbox.list_tools()


def _suppression_lesson_for(
    hypothesis: Hypothesis,
    lessons: tuple[ResearchLesson, ...],
) -> ResearchLesson | None:
    location = None
    if hypothesis.locations:
        location = hypothesis.locations[0]
    elif hypothesis.path:
        location = hypothesis.path[0]
    for lesson in lessons:
        if false_positive_suppression_matches(
            lesson,
            hunter=hypothesis.hunter,
            source=hypothesis.source,
            file=location.file if location is not None else None,
            symbol=location.symbol if location is not None else None,
            observed_guards=observed_guards_for_hypothesis(hypothesis),
        ):
            return lesson
    return None


def _lesson_suppression_entry(
    hypothesis: Hypothesis,
    lesson: ResearchLesson,
) -> EvidenceLedgerEntry:
    location = None
    if hypothesis.locations:
        location = hypothesis.locations[0]
    elif hypothesis.path:
        location = hypothesis.path[0]
    return EvidenceLedgerEntry(
        hypothesis_id=hypothesis.id,
        obligation="lesson_suppression",
        status=EvidenceStatus.FAILED,
        kind=EvidenceKind.NEGATIVE_EVIDENCE,
        claim=f"Project lesson {lesson.id} suppresses this repeat candidate.",
        evidence=[lesson.summary],
        file=location.file if location is not None else lesson.file,
        line=location.line if location is not None else lesson.line,
        symbol=location.symbol if location is not None else lesson.symbol,
        tool="research_learning_store",
        source_trust=SourceTrust.TOOL_OUTPUT,
    )
