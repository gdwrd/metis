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

HARDWARE_SECURITY_OBLIGATIONS = (
    "source",
    "security_sensitive_write",
    "protected_state",
    "missing_hardware_guard",
    "impact",
)
_HARDWARE_LANGUAGES = {"systemverilog", "verilog", "c", "cpp"}
_HARDWARE_EXTENSIONS = {".sv", ".svh", ".v", ".vh", ".c", ".h", ".cc", ".cpp"}
_SOURCE_MARKERS = (
    "bus_write",
    "bus_we",
    "mmio",
    "csr_write",
    "host_wdata",
    "debug_req",
    "jtag",
    "strap",
    "write_en",
)
_SENSITIVE_MARKERS = (
    "boot_key",
    "seed",
    "debug_enable",
    "debug_unlock",
    "privilege",
    "secure_lock",
    "secret",
    "otp",
    "fuse",
)
_SENSITIVE_CALLS = (
    "write_reg",
    "register_write",
    "mmio_write",
    "csr_write",
    "set_privilege",
    "enable_debug",
)
_GUARD_MARKERS = (
    "privileged",
    "secure_state",
    "lifecycle",
    "locked",
    "authorized",
    "allow_debug",
    "check_",
    "validate",
    "permission",
)


@dataclass(frozen=True)
class _HardwareCandidate:
    node: SecurityGraphNode
    source: str | None
    sink: str
    sink_line: int
    guard: str | None


class HardwareSecurityHunter:
    name = "hardware_security"
    vulnerability_class = "CWE-1262"
    metadata = HunterMetadata(
        name=name,
        vulnerability_class=vulnerability_class,
        supported_languages=("systemverilog", "verilog", "c", "cpp"),
        supported_model_tags=("source", "sink", "guard", "config"),
        required_graph_fields=("nodes", "tags", "metadata"),
        evidence_obligations=HARDWARE_SECURITY_OBLIGATIONS,
        benchmark_classes=(vulnerability_class,),
        rule_families=("hardware_security",),
        default_enabled=True,
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
            if not _is_hardware_node(node):
                continue
            body = _body_for_node(root_path, node)
            if not body:
                continue
            candidate = _hardware_candidate(node, body)
            if candidate is None:
                continue
            hypotheses.append(_hypothesis_for_candidate(root_path, candidate))
        return ResearchRunResult.from_hypotheses(
            hypotheses,
            metric_summary=_summary_for(hypotheses),
        )


def _hardware_candidate(
    node: SecurityGraphNode,
    body: str,
) -> _HardwareCandidate | None:
    sink, sink_line = _sensitive_write(body, start_line=node.line or 1)
    if sink is None or sink_line is None:
        return None
    source = _source_marker(node, body)
    guard = _guard_marker(body, sink_line=sink_line, start_line=node.line or 1)
    return _HardwareCandidate(
        node=node,
        source=source,
        sink=sink,
        sink_line=sink_line,
        guard=guard,
    )


def _hypothesis_for_candidate(
    root_path: Path,
    candidate: _HardwareCandidate,
) -> Hypothesis:
    hypothesis_id = build_hypothesis_id(
        str(root_path),
        "hardware_security",
        candidate.node.file,
        candidate.node.symbol,
        candidate.sink,
        candidate.source or "unknown",
    )
    status: HypothesisStatus
    kill_reason = None
    unresolved_reason = None
    missing_guard = None
    observed_guard = None
    confidence = 0.45

    if candidate.source is None:
        status = HypothesisStatus.UNRESOLVED
        title = f"Unresolved hardware security candidate in {candidate.node.symbol}"
        unresolved_reason = (
            "No externally controlled hardware or firmware source evidence"
        )
        evidence = _unresolved_evidence(hypothesis_id, candidate, missing="source")
    elif candidate.guard is not None:
        status = HypothesisStatus.KILLED
        title = f"Hardware security candidate killed in {candidate.node.symbol}"
        observed_guard = candidate.guard
        kill_reason = f"Hardware guard {candidate.guard} is present"
        confidence = 0.84
        evidence = _killed_evidence(hypothesis_id, candidate)
    else:
        status = HypothesisStatus.PROVEN
        title = (
            f"Unguarded security-sensitive hardware write in {candidate.node.symbol}"
        )
        missing_guard = "privilege, lifecycle, or lock guard"
        confidence = 0.76
        evidence = _proven_evidence(hypothesis_id, candidate)

    path = [_location_for_node(candidate.node, role="hardware_path")]
    return Hypothesis(
        id=hypothesis_id,
        hunter="hardware_security",
        vulnerability_class="CWE-1262",
        title=title,
        source=candidate.source or "unknown",
        path=path,
        sink=candidate.sink,
        asset=candidate.sink,
        expected_guard="privilege, lifecycle, or lock guard",
        observed_guard=observed_guard,
        missing_guard=missing_guard,
        impact=(
            "An externally controlled write can alter protected hardware state "
            "without the expected privilege, lifecycle, or lock invariant."
        ),
        evidence_obligations=[
            EvidenceObligation(name=name) for name in HARDWARE_SECURITY_OBLIGATIONS
        ],
        evidence=evidence,
        status=status,
        kill_reason=kill_reason,
        unresolved_reason=unresolved_reason,
        confidence=confidence,
        locations=path,
        sarif_rule_id="CWE-1262",
        priority=ResearchPriority.HIGH,
    )


def _proven_evidence(
    hypothesis_id: str,
    candidate: _HardwareCandidate,
) -> list[EvidenceLedgerEntry]:
    return [
        _evidence(
            hypothesis_id,
            candidate,
            "source",
            EvidenceStatus.SATISFIED,
            EvidenceKind.DEFINITION,
            f"Hardware source marker {candidate.source} is present.",
            line=candidate.node.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "security_sensitive_write",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            f"Security-sensitive write to {candidate.sink} is present.",
            line=candidate.sink_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "protected_state",
            EvidenceStatus.SATISFIED,
            EvidenceKind.TYPE_CONSTRAINT,
            f"{candidate.sink} is treated as protected hardware state.",
            line=candidate.sink_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "missing_hardware_guard",
            EvidenceStatus.SATISFIED,
            EvidenceKind.NEGATIVE_EVIDENCE,
            "No privilege, lifecycle, lock, or authorization guard protects the write.",
            line=candidate.sink_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "impact",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            "Protected hardware state can be modified by an untrusted writer.",
            line=candidate.sink_line,
        ),
    ]


def _killed_evidence(
    hypothesis_id: str,
    candidate: _HardwareCandidate,
) -> list[EvidenceLedgerEntry]:
    return [
        _evidence(
            hypothesis_id,
            candidate,
            "source",
            EvidenceStatus.SATISFIED,
            EvidenceKind.DEFINITION,
            f"Hardware source marker {candidate.source} is present.",
            line=candidate.node.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "security_sensitive_write",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            f"Security-sensitive write to {candidate.sink} is present.",
            line=candidate.sink_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "protected_state",
            EvidenceStatus.SATISFIED,
            EvidenceKind.TYPE_CONSTRAINT,
            f"{candidate.sink} is treated as protected hardware state.",
            line=candidate.sink_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "missing_hardware_guard",
            EvidenceStatus.FAILED,
            EvidenceKind.GUARD_CHECK,
            f"Hardware guard {candidate.guard} protects the write.",
            line=candidate.sink_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "impact",
            EvidenceStatus.NOT_APPLICABLE,
            EvidenceKind.NEGATIVE_EVIDENCE,
            "The candidate is killed before impact analysis.",
            line=candidate.sink_line,
        ),
    ]


def _unresolved_evidence(
    hypothesis_id: str,
    candidate: _HardwareCandidate,
    *,
    missing: str,
) -> list[EvidenceLedgerEntry]:
    source_status = (
        EvidenceStatus.MISSING if missing == "source" else EvidenceStatus.SATISFIED
    )
    return [
        _evidence(
            hypothesis_id,
            candidate,
            "source",
            source_status,
            EvidenceKind.DEFINITION,
            (
                f"Hardware source marker {candidate.source} is present."
                if candidate.source
                else "No externally controlled hardware or firmware source marker was observed."
            ),
            line=candidate.node.line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "security_sensitive_write",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            f"Security-sensitive write to {candidate.sink} is present.",
            line=candidate.sink_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "protected_state",
            EvidenceStatus.SATISFIED,
            EvidenceKind.TYPE_CONSTRAINT,
            f"{candidate.sink} is treated as protected hardware state.",
            line=candidate.sink_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "missing_hardware_guard",
            EvidenceStatus.MISSING,
            EvidenceKind.GUARD_CHECK,
            "Guard equivalence cannot be evaluated without source evidence.",
            line=candidate.sink_line,
        ),
        _evidence(
            hypothesis_id,
            candidate,
            "impact",
            EvidenceStatus.MISSING,
            EvidenceKind.STATIC_TRACE,
            "Impact is unresolved until write reachability is proven.",
            line=candidate.sink_line,
        ),
    ]


def _sensitive_write(body: str, *, start_line: int) -> tuple[str | None, int | None]:
    for line_number, line in enumerate(body.splitlines(), start=start_line):
        for marker in _SENSITIVE_MARKERS:
            if re.search(rf"\b{marker}\w*\b\s*(?:<=|=)", line):
                return marker, line_number
        for call in _SENSITIVE_CALLS:
            if re.search(rf"\b{call}\s*\(", line):
                return call, line_number
    return None, None


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


def _guard_marker(
    body: str,
    *,
    sink_line: int,
    start_line: int,
) -> str | None:
    for line_number, line in enumerate(body.splitlines(), start=start_line):
        if line_number > sink_line:
            break
        lowered = line.lower()
        if not _guard_context(lowered):
            continue
        for marker in _GUARD_MARKERS:
            if marker in lowered:
                return marker
    return None


def _guard_context(lowered_line: str) -> bool:
    if re.search(r"\bif\b|\bcase\b|\bassert\b", lowered_line):
        return True
    return any(
        marker in lowered_line
        for marker in ("check", "validate", "authorize", "allow", "&&", "||", "?")
    )


def _is_hardware_node(node: SecurityGraphNode) -> bool:
    language = str(node.language or "").lower()
    if language in _HARDWARE_LANGUAGES:
        return True
    return Path(node.file or "").suffix.lower() in _HARDWARE_EXTENSIONS


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
    candidate: _HardwareCandidate,
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
