# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from metis.engine.research.hunters.base import HunterMetadata
from metis.engine.research.models import (
    EvidenceKind,
    EvidenceLedgerEntry,
    EvidenceObligation,
    EvidenceStatus,
    FlowStep,
    Hypothesis,
    HypothesisStatus,
    ProjectSecurityModel,
    ResearchLesson,
    ResearchPriority,
    ResearchRunResult,
    SecurityGraph,
    SecurityGraphNode,
    SourceTrust,
    build_hypothesis_id,
)

MEMORY_LIFETIME_OBLIGATIONS = (
    "source",
    "lifetime_transition",
    "post_lifetime_use",
    "missing_lifetime_guard",
    "impact",
)
_NATIVE_LANGUAGES = {"c", "cpp", "rust"}
_NATIVE_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".hpp", ".rs"}
_SOURCE_MARKERS = (
    "callback",
    "handler",
    "request",
    "work",
    "thread",
    "irq",
    "interrupt",
    "teardown",
    "release",
    "destroy",
)
_MITIGATION_MARKERS = (
    "null",
    "nullptr",
    "zeroize",
    "memset_s",
    "clear",
    "refcount",
    "lock",
    "ownership",
)


@dataclass(frozen=True)
class _FreeEvent:
    variable: str
    line: int
    operation: str


@dataclass(frozen=True)
class _MemoryCandidate:
    node: SecurityGraphNode
    source: str | None
    free_event: _FreeEvent
    violation: str | None
    violation_line: int | None
    mitigation: str | None


class MemoryLifetimeHunter:
    name = "memory_lifetime"
    vulnerability_class = "CWE-416"
    metadata = HunterMetadata(
        name=name,
        vulnerability_class=vulnerability_class,
        supported_languages=("c", "cpp", "rust"),
        supported_model_tags=("source", "sink", "guard", "sanitizer"),
        required_graph_fields=("nodes", "tags", "metadata"),
        evidence_obligations=MEMORY_LIFETIME_OBLIGATIONS,
        benchmark_classes=(vulnerability_class,),
    )

    def hunt(
        self,
        root: str | Path,
        *,
        security_model: ProjectSecurityModel | None = None,
        security_graph: SecurityGraph | None = None,
        lessons: tuple[ResearchLesson, ...] = (),
    ) -> ResearchRunResult:
        if security_graph is None:
            return ResearchRunResult.from_hypotheses([])
        root_path = Path(root).resolve()
        hypotheses: list[Hypothesis] = []
        for node in sorted(security_graph.nodes, key=lambda item: item.id):
            if not _is_native_node(node):
                continue
            body = _body_for_node(root_path, node)
            if not body:
                continue
            candidate = _memory_candidate(node, body)
            if candidate is None:
                continue
            hypotheses.append(_hypothesis_for_candidate(root_path, candidate))
        return ResearchRunResult.from_hypotheses(
            hypotheses,
            metric_summary=_summary_for(hypotheses),
        )


def _memory_candidate(
    node: SecurityGraphNode,
    body: str,
) -> _MemoryCandidate | None:
    events = _free_events(body, start_line=node.line or 1)
    if not events:
        return None
    event = events[0]
    violation, violation_line = _post_free_violation(body, event, node.line or 1)
    mitigation = _lifetime_mitigation(body, event, start_line=node.line or 1)
    source = _source_marker(node, body)
    return _MemoryCandidate(
        node=node,
        source=source,
        free_event=event,
        violation=violation,
        violation_line=violation_line,
        mitigation=mitigation,
    )


def _hypothesis_for_candidate(
    root_path: Path,
    candidate: _MemoryCandidate,
) -> Hypothesis:
    hypothesis_id = build_hypothesis_id(
        str(root_path),
        "memory_lifetime",
        candidate.node.file,
        candidate.node.symbol,
        candidate.free_event.variable,
        candidate.source or "unknown",
    )
    status: HypothesisStatus
    title: str
    evidence: list[EvidenceLedgerEntry]
    kill_reason = None
    unresolved_reason = None
    missing_guard = None
    observed_guard = None
    confidence = 0.45

    if candidate.source is None:
        status = HypothesisStatus.UNRESOLVED
        title = f"Unresolved memory lifetime candidate in {candidate.node.symbol}"
        unresolved_reason = "No lifecycle or attacker-controlled trigger evidence"
        evidence = _unresolved_evidence(hypothesis_id, candidate, missing="source")
    elif candidate.violation is not None and candidate.mitigation is None:
        status = HypothesisStatus.PROVEN
        title = f"Memory lifetime violation in {candidate.node.symbol}"
        missing_guard = "ownership transfer or post-free guard"
        confidence = 0.78
        evidence = _proven_evidence(hypothesis_id, candidate)
    elif candidate.mitigation is not None:
        status = HypothesisStatus.KILLED
        title = f"Memory lifetime candidate killed in {candidate.node.symbol}"
        observed_guard = candidate.mitigation
        kill_reason = f"Lifetime mitigation {candidate.mitigation} is present"
        confidence = 0.82
        evidence = _killed_evidence(hypothesis_id, candidate)
    else:
        status = HypothesisStatus.UNRESOLVED
        title = f"Unresolved memory lifetime candidate in {candidate.node.symbol}"
        unresolved_reason = "No post-free use or ownership mitigation evidence"
        evidence = _unresolved_evidence(
            hypothesis_id,
            candidate,
            missing="post_lifetime_use",
        )

    path = [_location_for_node(candidate.node, role="lifetime_path")]
    return Hypothesis(
        id=hypothesis_id,
        hunter="memory_lifetime",
        vulnerability_class="CWE-416",
        title=title,
        source=candidate.source or "unknown",
        path=path,
        sink=candidate.free_event.operation,
        asset=candidate.free_event.variable,
        expected_guard="ownership transfer or post-free guard",
        observed_guard=observed_guard,
        missing_guard=missing_guard,
        impact=(
            "A stale native pointer or resource handle can be used after its "
            "lifetime ended, enabling memory corruption or denial of service."
        ),
        evidence_obligations=[
            EvidenceObligation(name=name) for name in MEMORY_LIFETIME_OBLIGATIONS
        ],
        evidence=evidence,
        status=status,
        kill_reason=kill_reason,
        unresolved_reason=unresolved_reason,
        confidence=confidence,
        locations=path,
        sarif_rule_id="CWE-416",
        priority=ResearchPriority.HIGH,
    )


def _proven_evidence(
    hypothesis_id: str,
    candidate: _MemoryCandidate,
) -> list[EvidenceLedgerEntry]:
    return [
        _evidence(
            hypothesis_id,
            candidate,
            "source",
            EvidenceStatus.SATISFIED,
            EvidenceKind.DEFINITION,
            f"Lifecycle trigger marker {candidate.source} is present.",
            line=candidate.node.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "lifetime_transition",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            (
                f"{candidate.free_event.operation} releases "
                f"{candidate.free_event.variable}."
            ),
            line=candidate.free_event.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "post_lifetime_use",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            candidate.violation or "Released object is used after lifetime end.",
            line=candidate.violation_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "missing_lifetime_guard",
            EvidenceStatus.SATISFIED,
            EvidenceKind.NEGATIVE_EVIDENCE,
            "No ownership transfer, nulling, or lifetime guard protects the later use.",
            line=candidate.free_event.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "impact",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            "Use after free can corrupt native memory or crash the process.",
            line=candidate.violation_line,
        ),
    ]


def _killed_evidence(
    hypothesis_id: str,
    candidate: _MemoryCandidate,
) -> list[EvidenceLedgerEntry]:
    return [
        _evidence(
            hypothesis_id,
            candidate,
            "source",
            EvidenceStatus.SATISFIED,
            EvidenceKind.DEFINITION,
            f"Lifecycle trigger marker {candidate.source} is present.",
            line=candidate.node.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "lifetime_transition",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            (
                f"{candidate.free_event.operation} releases "
                f"{candidate.free_event.variable}."
            ),
            line=candidate.free_event.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "post_lifetime_use",
            EvidenceStatus.NOT_APPLICABLE,
            EvidenceKind.NEGATIVE_EVIDENCE,
            "No post-free use remains after the lifetime mitigation.",
            line=candidate.free_event.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "missing_lifetime_guard",
            EvidenceStatus.FAILED,
            EvidenceKind.GUARD_CHECK,
            f"Lifetime mitigation {candidate.mitigation} is present.",
            line=candidate.free_event.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "impact",
            EvidenceStatus.NOT_APPLICABLE,
            EvidenceKind.NEGATIVE_EVIDENCE,
            "The candidate is killed before impact analysis.",
            line=candidate.free_event.line,
        ),
    ]


def _unresolved_evidence(
    hypothesis_id: str,
    candidate: _MemoryCandidate,
    *,
    missing: str,
) -> list[EvidenceLedgerEntry]:
    source_status = (
        EvidenceStatus.MISSING if missing == "source" else EvidenceStatus.SATISFIED
    )
    use_status = (
        EvidenceStatus.MISSING
        if missing == "post_lifetime_use"
        else EvidenceStatus.SATISFIED
    )
    return [
        _evidence(
            hypothesis_id,
            candidate,
            "source",
            source_status,
            EvidenceKind.DEFINITION,
            (
                f"Lifecycle trigger marker {candidate.source} is present."
                if candidate.source
                else "No lifecycle or attacker-controlled trigger marker was observed."
            ),
            line=candidate.node.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "lifetime_transition",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            (
                f"{candidate.free_event.operation} releases "
                f"{candidate.free_event.variable}."
            ),
            line=candidate.free_event.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "post_lifetime_use",
            use_status,
            EvidenceKind.STATIC_TRACE,
            candidate.violation or "Post-free use evidence is unresolved.",
            line=candidate.violation_line or candidate.free_event.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "missing_lifetime_guard",
            EvidenceStatus.MISSING,
            EvidenceKind.GUARD_CHECK,
            "Lifetime guard equivalence is unresolved.",
            line=candidate.free_event.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "impact",
            EvidenceStatus.MISSING,
            EvidenceKind.STATIC_TRACE,
            "Impact is unresolved until lifetime reachability is proven.",
            line=candidate.free_event.line,
        ),
    ]


def _free_events(body: str, *, start_line: int) -> list[_FreeEvent]:
    events: list[_FreeEvent] = []
    for offset, line in enumerate(body.splitlines(), start=start_line):
        for match in re.finditer(
            r"\b(?P<op>free|kfree|vfree|drop)\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*\)",
            line,
        ):
            events.append(_FreeEvent(match.group("var"), offset, match.group("op")))
        delete_match = re.search(r"\bdelete\s+(?P<var>[A-Za-z_]\w*)\b", line)
        if delete_match:
            events.append(_FreeEvent(delete_match.group("var"), offset, "delete"))
    return events


def _post_free_violation(
    body: str,
    event: _FreeEvent,
    start_line: int,
) -> tuple[str | None, int | None]:
    for offset, line in enumerate(body.splitlines(), start=start_line):
        if offset <= event.line:
            continue
        if _nulls_variable(line, event.variable) or _zeroizes_variable(
            line,
            event.variable,
        ):
            return None, None
        if re.search(
            rf"\b(?:free|kfree|vfree|drop)\s*\(\s*{event.variable}\s*\)", line
        ):
            return f"{event.variable} is released a second time.", offset
        if _uses_released_variable(line, event.variable):
            return f"{event.variable} is used after {event.operation}.", offset
    return None, None


def _lifetime_mitigation(
    body: str,
    event: _FreeEvent,
    *,
    start_line: int,
) -> str | None:
    for absolute, line in enumerate(body.splitlines(), start=start_line):
        if absolute <= event.line:
            continue
        if _nulls_variable(line, event.variable):
            return "null_after_free"
        if _zeroizes_variable(line, event.variable):
            return "zeroize_after_release"
        if any(marker in line.lower() for marker in ("refcount", "lock", "owner")):
            return "ownership_guard"
    if any(marker in body.lower() for marker in _MITIGATION_MARKERS):
        return "lifetime_guard"
    return None


def _uses_released_variable(line: str, variable: str) -> bool:
    patterns = (
        rf"\b{variable}\s*->",
        rf"\*\s*{variable}\b",
        rf"\b[A-Za-z_]\w*\s*\([^)]*\b{variable}\b",
    )
    return any(re.search(pattern, line) for pattern in patterns)


def _nulls_variable(line: str, variable: str) -> bool:
    return bool(re.search(rf"\b{variable}\s*=\s*(?:NULL|nullptr|None|0)\b", line))


def _zeroizes_variable(line: str, variable: str) -> bool:
    return bool(
        re.search(rf"\b(?:zeroize|memset_s|memset)\s*\([^;]*\b{variable}\b", line)
    )


def _source_marker(node: SecurityGraphNode, body: str) -> str | None:
    haystack = " ".join(
        [
            node.symbol or "",
            node.signature or "",
            " ".join(node.parameters),
            " ".join(str(tag.value) for tag in node.tags if tag.kind == "source"),
            body,
        ]
    ).lower()
    return next((marker for marker in _SOURCE_MARKERS if marker in haystack), None)


def _is_native_node(node: SecurityGraphNode) -> bool:
    if str(node.language or "").lower() in _NATIVE_LANGUAGES:
        return True
    return Path(node.file or "").suffix.lower() in _NATIVE_EXTENSIONS


def _body_for_node(root_path: Path, node: SecurityGraphNode) -> str:
    if not node.file:
        return ""
    path = _resolve_node_file(root_path, node.file)
    if path is None:
        return ""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return ""
    start = max(1, node.line or 1)
    end = max(start, node.end_line or start)
    return "\n".join(lines[start - 1 : end])


def _resolve_node_file(root_path: Path, file_name: str) -> Path | None:
    path = Path(file_name)
    candidates = (
        [path] if path.is_absolute() else [root_path.parent / path, root_path / path]
    )
    if not path.is_absolute():
        parts = path.parts
        for index, part in enumerate(parts):
            if part != root_path.name:
                continue
            if index:
                candidates.append(root_path.parent / Path(*parts[index:]))
            if index + 1 < len(parts):
                candidates.append(root_path / Path(*parts[index + 1 :]))
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.exists():
            return resolved
    return None


def _location_for_node(node: SecurityGraphNode, *, role: str) -> FlowStep:
    return FlowStep(
        file=node.file or "",
        line=node.line,
        symbol=node.symbol,
        role=role,
    )


def _evidence(
    hypothesis_id: str,
    candidate: _MemoryCandidate,
    obligation: str,
    status: EvidenceStatus,
    kind: EvidenceKind,
    claim: str,
    *,
    line: int | None,
) -> EvidenceLedgerEntry:
    file = candidate.node.file
    return EvidenceLedgerEntry(
        hypothesis_id=hypothesis_id,
        obligation=obligation,
        status=status,
        kind=kind,
        claim=claim,
        evidence=[f"{file}:{line}" if line else str(file or "")],
        file=file,
        line=line,
        symbol=candidate.node.symbol,
        source_trust=SourceTrust.CODE,
    )


def _summary_for(hypotheses: list[Hypothesis]) -> dict[str, int]:
    return {
        "generated": len(hypotheses),
        "proven": sum(
            1 for item in hypotheses if item.status == HypothesisStatus.PROVEN
        ),
        "killed": sum(
            1 for item in hypotheses if item.status == HypothesisStatus.KILLED
        ),
        "unresolved": sum(
            1 for item in hypotheses if item.status == HypothesisStatus.UNRESOLVED
        ),
    }
