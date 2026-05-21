# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterable

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
    SecurityTag,
    SourceTrust,
    build_hypothesis_id,
)


@dataclass(frozen=True)
class GraphPatternSpec:
    name: str
    vulnerability_class: str
    title: str
    sink_obligation: str
    missing_mitigation_obligation: str
    mitigation_label: str
    sink_markers: tuple[str, ...]
    mitigation_markers: tuple[str, ...]
    impact: str
    supported_languages: tuple[str, ...] = ("python",)
    priority: ResearchPriority = ResearchPriority.HIGH
    rule_families: tuple[str, ...] = ()
    default_enabled: bool = False
    experimental: bool = False
    promotion_criteria: tuple[str, ...] = ()
    promotion_status: str = "unassessed"
    promotion_skip_reason: str | None = None

    @property
    def obligations(self) -> tuple[str, ...]:
        return (
            "source",
            "reachability",
            self.sink_obligation,
            self.missing_mitigation_obligation,
            "impact",
        )

    @property
    def metadata(self) -> HunterMetadata:
        return HunterMetadata(
            name=self.name,
            vulnerability_class=self.vulnerability_class,
            supported_languages=self.supported_languages,
            supported_model_tags=("source", "sink", "sanitizer", "guard"),
            required_graph_fields=("nodes", "tags", "metadata"),
            evidence_obligations=self.obligations,
            benchmark_classes=(self.vulnerability_class,),
            rule_families=self.rule_families,
            default_enabled=self.default_enabled,
            experimental=self.experimental,
            promotion_criteria=self.promotion_criteria,
            promotion_status=self.promotion_status,
            promotion_skip_reason=self.promotion_skip_reason,
        )


class GraphPatternHunter:
    def __init__(self, spec: GraphPatternSpec) -> None:
        self.spec = spec
        self.name = spec.name
        self.vulnerability_class = spec.vulnerability_class
        self.metadata = spec.metadata

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
        candidates = self._candidates(root_path, security_graph)
        hypotheses = [
            self._hypothesis_for_candidate(root_path, candidate)
            for candidate in candidates
        ]
        return ResearchRunResult.from_hypotheses(
            hypotheses,
            metric_summary=_summary_for(hypotheses),
        )

    def _candidates(
        self,
        root_path: Path,
        security_graph: SecurityGraph,
    ) -> list["_Candidate"]:
        function_nodes = {
            node.id: node
            for node in security_graph.nodes
            if node.type in {"function", "resource", "config"}
        }
        source_callers_by_sink: dict[
            str, list[tuple[SecurityGraphNode, SecurityTag, SecurityTag | None]]
        ] = {}
        for edge in security_graph.edges:
            if edge.kind != "call":
                continue
            source_node = function_nodes.get(edge.source)
            sink_node = function_nodes.get(edge.target)
            if source_node is None or sink_node is None:
                continue
            source_tags = self._class_tags(source_node)
            if not source_tags.sources:
                continue
            if self._class_tags(sink_node).sink is None:
                continue
            for source_tag in source_tags.sources:
                if not _source_flows_to_direct_call(
                    root_path,
                    source_node=source_node,
                    sink_node=sink_node,
                    source=source_tag,
                ):
                    continue
                effective = self._effective_direct_mitigation(
                    root_path,
                    source_node=source_node,
                    sink_node=sink_node,
                    source_tag=source_tag,
                    source_tags=source_tags,
                    sink_tags=self._class_tags(sink_node),
                )
                source_callers_by_sink.setdefault(sink_node.id, []).append(
                    (source_node, source_tag, effective)
                )

        candidates: list[_Candidate] = []
        for node in sorted(function_nodes.values(), key=lambda item: item.id):
            tags = self._class_tags(node)
            if tags.sink is None:
                continue
            if tags.sources:
                for source_tag in tags.sources:
                    if not _source_flows_to_function_call(
                        root_path,
                        node,
                        source=source_tag,
                        function_name=tags.sink.value,
                    ):
                        continue
                    effective = self._effective_mitigation(
                        root_path,
                        node,
                        tags,
                        source_tag=source_tag,
                    )
                    candidates.append(
                        _Candidate(
                            source_node=node,
                            sink_node=node,
                            source=source_tag,
                            sink=tags.sink,
                            mitigation=effective,
                            same_function=True,
                        )
                    )
                continue
            for source_node, source_tag, mitigation_tag in source_callers_by_sink.get(
                node.id,
                [],
            ):
                candidates.append(
                    _Candidate(
                        source_node=source_node,
                        sink_node=node,
                        source=source_tag,
                        sink=tags.sink,
                        mitigation=mitigation_tag,
                        same_function=False,
                    )
                )
            if node.id not in source_callers_by_sink:
                candidates.append(
                    _Candidate(
                        source_node=node,
                        sink_node=node,
                        source=None,
                        sink=tags.sink,
                        mitigation=None,
                        same_function=True,
                    )
                )
        return candidates

    def _class_tags(self, node: SecurityGraphNode) -> "_ClassTags":
        sink = _first_matching_tag(
            node.tags,
            kind="sink",
            markers=self.spec.sink_markers,
        )
        sources = _source_tags(
            node.tags,
            sink_markers=self.spec.sink_markers,
            mitigation_markers=self.spec.mitigation_markers,
        )
        mitigations = _matching_tags(
            node.tags,
            kind=("sanitizer", "guard"),
            markers=self.spec.mitigation_markers,
            node_symbol=node.symbol,
        )
        return _ClassTags(sources=sources, sink=sink, mitigations=mitigations)

    def _effective_mitigation(
        self,
        root_path: Path,
        node: SecurityGraphNode,
        tags: "_ClassTags",
        *,
        source_tag: SecurityTag,
    ) -> SecurityTag | None:
        if tags.sink is None:
            return None
        for mitigation in tags.mitigations:
            if _mitigation_flows_to_sink(
                root_path,
                node,
                source=source_tag,
                sink=tags.sink,
                mitigation=mitigation,
            ):
                return mitigation
        return None

    def _effective_direct_mitigation(
        self,
        root_path: Path,
        *,
        source_node: SecurityGraphNode,
        sink_node: SecurityGraphNode,
        source_tag: SecurityTag,
        source_tags: "_ClassTags",
        sink_tags: "_ClassTags",
    ) -> SecurityTag | None:
        if not sink_node.symbol:
            return None
        for mitigation in source_tags.mitigations:
            if _mitigation_flows_to_function_call(
                root_path,
                source_node,
                source=source_tag,
                function_name=sink_node.symbol,
                mitigation=mitigation,
            ):
                return mitigation
        for mitigation in sink_tags.mitigations:
            if sink_tags.sink is not None and _callee_mitigation_flows_to_sink(
                root_path,
                sink_node,
                sink=sink_tags.sink,
                mitigation=mitigation,
            ):
                return mitigation
        return None

    def _hypothesis_for_candidate(
        self,
        root_path: Path,
        candidate: "_Candidate",
    ) -> Hypothesis:
        source_value = (
            candidate.source.value if candidate.source is not None else "unknown"
        )
        mitigation_value = (
            candidate.mitigation.value if candidate.mitigation is not None else None
        )
        hypothesis_id = build_hypothesis_id(
            str(root_path),
            self.name,
            candidate.source_node.file,
            candidate.source_node.symbol,
            candidate.sink_node.file,
            candidate.sink_node.symbol,
            source_value,
            candidate.sink.value,
            mitigation_value,
        )
        path = _path_for_candidate(candidate)
        if candidate.source is None:
            evidence = self._unresolved_evidence(
                hypothesis_id=hypothesis_id,
                candidate=candidate,
            )
            return self._new_hypothesis(
                hypothesis_id=hypothesis_id,
                candidate=candidate,
                source="unknown",
                sink=candidate.sink.value,
                title=(
                    f"Unresolved {self.spec.title} candidate in "
                    f"{candidate.sink_node.symbol}"
                ),
                evidence=evidence,
                status=HypothesisStatus.UNRESOLVED,
                unresolved_reason="No attacker-controlled source evidence",
                confidence=0.35,
                path=path,
            )
        if candidate.mitigation is not None:
            evidence = self._killed_evidence(
                hypothesis_id=hypothesis_id,
                candidate=candidate,
            )
            return self._new_hypothesis(
                hypothesis_id=hypothesis_id,
                candidate=candidate,
                source=candidate.source.value,
                sink=candidate.sink.value,
                title=(
                    f"{self.spec.title} candidate killed in "
                    f"{candidate.sink_node.symbol}"
                ),
                observed_guard=candidate.mitigation.value,
                evidence=evidence,
                status=HypothesisStatus.KILLED,
                kill_reason=(
                    f"Equivalent {self.spec.mitigation_label} "
                    f"{candidate.mitigation.value} is present"
                ),
                confidence=0.85,
                path=path,
            )
        evidence = self._proven_evidence(
            hypothesis_id=hypothesis_id,
            candidate=candidate,
        )
        return self._new_hypothesis(
            hypothesis_id=hypothesis_id,
            candidate=candidate,
            source=candidate.source.value,
            sink=candidate.sink.value,
            title=f"{self.spec.title} in {candidate.sink_node.symbol}",
            missing_guard=self.spec.mitigation_label,
            evidence=evidence,
            status=HypothesisStatus.PROVEN,
            confidence=0.75,
            path=path,
        )

    def _new_hypothesis(
        self,
        *,
        hypothesis_id: str,
        candidate: "_Candidate",
        source: str,
        sink: str,
        title: str,
        evidence: list[EvidenceLedgerEntry],
        status: HypothesisStatus,
        confidence: float,
        path: list[FlowStep],
        observed_guard: str | None = None,
        missing_guard: str | None = None,
        kill_reason: str | None = None,
        unresolved_reason: str | None = None,
    ) -> Hypothesis:
        return Hypothesis(
            id=hypothesis_id,
            hunter=self.name,
            vulnerability_class=self.vulnerability_class,
            title=title,
            source=source,
            path=path,
            sink=sink,
            expected_guard=self.spec.mitigation_label,
            observed_guard=observed_guard,
            missing_guard=missing_guard,
            impact=self.spec.impact,
            evidence_obligations=[
                EvidenceObligation(name=name) for name in self.spec.obligations
            ],
            evidence=evidence,
            status=status,
            kill_reason=kill_reason,
            unresolved_reason=unresolved_reason,
            confidence=confidence,
            locations=path,
            sarif_rule_id=self.vulnerability_class,
            priority=self.spec.priority,
        )

    def _proven_evidence(
        self,
        *,
        hypothesis_id: str,
        candidate: "_Candidate",
    ) -> list[EvidenceLedgerEntry]:
        source = candidate.source
        if source is None:
            raise ValueError("proven graph-pattern evidence requires a source")
        return [
            _evidence(
                hypothesis_id,
                "source",
                EvidenceStatus.SATISFIED,
                EvidenceKind.DEFINITION,
                f"Source marker {source.value} is present in {candidate.source_node.symbol}.",
                candidate.source_node,
                source,
            ),
            _evidence(
                hypothesis_id,
                "reachability",
                EvidenceStatus.SATISFIED,
                EvidenceKind.CALL_PATH,
                _reachability_claim(candidate),
                candidate.sink_node,
                candidate.sink,
            ),
            _evidence(
                hypothesis_id,
                self.spec.sink_obligation,
                EvidenceStatus.SATISFIED,
                EvidenceKind.STATIC_TRACE,
                f"Sink marker {candidate.sink.value} is present in {candidate.sink_node.symbol}.",
                candidate.sink_node,
                candidate.sink,
            ),
            _evidence(
                hypothesis_id,
                self.spec.missing_mitigation_obligation,
                EvidenceStatus.SATISFIED,
                EvidenceKind.NEGATIVE_EVIDENCE,
                f"No equivalent {self.spec.mitigation_label} protects the sink.",
                candidate.sink_node,
                candidate.sink,
                evidence=[
                    (
                        "observed mitigations: "
                        f"{_observed_mitigations(candidate.sink_node) or 'none'}"
                    )
                ],
            ),
            _evidence(
                hypothesis_id,
                "impact",
                EvidenceStatus.SATISFIED,
                EvidenceKind.STATIC_TRACE,
                self.spec.impact,
                candidate.sink_node,
                candidate.sink,
            ),
        ]

    def _killed_evidence(
        self,
        *,
        hypothesis_id: str,
        candidate: "_Candidate",
    ) -> list[EvidenceLedgerEntry]:
        source = candidate.source
        mitigation = candidate.mitigation
        if source is None or mitigation is None:
            raise ValueError(
                "killed graph-pattern evidence requires source and mitigation"
            )
        return [
            _evidence(
                hypothesis_id,
                "source",
                EvidenceStatus.SATISFIED,
                EvidenceKind.DEFINITION,
                f"Source marker {source.value} is present in {candidate.source_node.symbol}.",
                candidate.source_node,
                source,
            ),
            _evidence(
                hypothesis_id,
                "reachability",
                EvidenceStatus.SATISFIED,
                EvidenceKind.CALL_PATH,
                _reachability_claim(candidate),
                candidate.sink_node,
                candidate.sink,
            ),
            _evidence(
                hypothesis_id,
                self.spec.sink_obligation,
                EvidenceStatus.SATISFIED,
                EvidenceKind.STATIC_TRACE,
                f"Sink marker {candidate.sink.value} is present in {candidate.sink_node.symbol}.",
                candidate.sink_node,
                candidate.sink,
            ),
            _evidence(
                hypothesis_id,
                self.spec.missing_mitigation_obligation,
                EvidenceStatus.FAILED,
                EvidenceKind.SANITIZER_CHECK,
                (
                    f"{self.spec.mitigation_label.capitalize()} marker "
                    f"{mitigation.value} is present."
                ),
                candidate.sink_node,
                mitigation,
            ),
            _evidence(
                hypothesis_id,
                "impact",
                EvidenceStatus.NOT_APPLICABLE,
                EvidenceKind.NEGATIVE_EVIDENCE,
                "Equivalent mitigation kills the candidate before impact analysis.",
                candidate.sink_node,
                mitigation,
            ),
        ]

    def _unresolved_evidence(
        self,
        *,
        hypothesis_id: str,
        candidate: "_Candidate",
    ) -> list[EvidenceLedgerEntry]:
        return [
            _evidence(
                hypothesis_id,
                self.spec.sink_obligation,
                EvidenceStatus.SATISFIED,
                EvidenceKind.STATIC_TRACE,
                f"Sink marker {candidate.sink.value} is present in {candidate.sink_node.symbol}.",
                candidate.sink_node,
                candidate.sink,
            ),
            _evidence(
                hypothesis_id,
                "source",
                EvidenceStatus.MISSING,
                EvidenceKind.NEGATIVE_EVIDENCE,
                "No attacker-controlled source marker was observed.",
                candidate.sink_node,
                candidate.sink,
            ),
            _evidence(
                hypothesis_id,
                "reachability",
                EvidenceStatus.MISSING,
                EvidenceKind.CALL_PATH,
                "Reachability from attacker input to the sink is unresolved.",
                candidate.sink_node,
                candidate.sink,
            ),
            _evidence(
                hypothesis_id,
                self.spec.missing_mitigation_obligation,
                EvidenceStatus.MISSING,
                EvidenceKind.SANITIZER_CHECK,
                "Mitigation equivalence cannot be evaluated without source reachability.",
                candidate.sink_node,
                candidate.sink,
            ),
            _evidence(
                hypothesis_id,
                "impact",
                EvidenceStatus.MISSING,
                EvidenceKind.STATIC_TRACE,
                "Impact is unresolved until source reachability is established.",
                candidate.sink_node,
                candidate.sink,
            ),
        ]


@dataclass(frozen=True)
class _Candidate:
    source_node: SecurityGraphNode
    sink_node: SecurityGraphNode
    source: SecurityTag | None
    sink: SecurityTag
    mitigation: SecurityTag | None
    same_function: bool


@dataclass(frozen=True)
class _ClassTags:
    sources: tuple[SecurityTag, ...]
    sink: SecurityTag | None
    mitigations: tuple[SecurityTag, ...]


def _path_for_candidate(candidate: _Candidate) -> list[FlowStep]:
    source_step = _location_for_node(candidate.source_node, role="source")
    sink_step = _location_for_node(candidate.sink_node, role="sink")
    if candidate.source_node.id == candidate.sink_node.id:
        return [_location_for_node(candidate.sink_node, role="source_sink")]
    return [source_step, sink_step]


def _reachability_claim(candidate: _Candidate) -> str:
    if candidate.same_function:
        return (
            "Source-derived data reaches sink arguments in the same function "
            f"{candidate.sink_node.symbol}."
        )
    return (
        f"Source-derived data in {candidate.source_node.symbol} flows into a "
        f"direct call to sink function {candidate.sink_node.symbol}."
    )


def _mitigation_flows_to_sink(
    root_path: Path,
    node: SecurityGraphNode,
    *,
    source: SecurityTag,
    sink: SecurityTag,
    mitigation: SecurityTag,
) -> bool:
    function = _function_ast_for_node(root_path, node)
    if function is None:
        return _text_mitigation_flows_to_function_call(
            root_path,
            node,
            source=source,
            function_name=sink.value,
            mitigation=mitigation,
        )
    summary = _flow_summary_for_statements(
        function.body,
        source_name=source.value,
        sink_name=sink.value,
        mitigation_name=mitigation.value,
        tainted=set(),
        mitigated=set(),
    )
    return summary.has_mitigated_flow and not summary.has_unmitigated_flow


def _mitigation_flows_to_function_call(
    root_path: Path,
    node: SecurityGraphNode,
    *,
    source: SecurityTag,
    function_name: str,
    mitigation: SecurityTag,
) -> bool:
    function = _function_ast_for_node(root_path, node)
    if function is None:
        return _text_mitigation_flows_to_function_call(
            root_path,
            node,
            source=source,
            function_name=function_name,
            mitigation=mitigation,
        )
    summary = _flow_summary_for_statements(
        function.body,
        source_name=source.value,
        sink_name=function_name,
        mitigation_name=mitigation.value,
        tainted=set(),
        mitigated=set(),
    )
    return summary.has_mitigated_flow and not summary.has_unmitigated_flow


def _callee_mitigation_flows_to_sink(
    root_path: Path,
    node: SecurityGraphNode,
    *,
    sink: SecurityTag,
    mitigation: SecurityTag,
) -> bool:
    function = _function_ast_for_node(root_path, node)
    if function is None:
        return False
    parameters = {
        arg.arg
        for arg in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    }
    if function.args.vararg is not None:
        parameters.add(function.args.vararg.arg)
    if function.args.kwarg is not None:
        parameters.add(function.args.kwarg.arg)
    if not parameters:
        return False
    summary = _flow_summary_for_statements(
        function.body,
        source_name="",
        sink_name=sink.value,
        mitigation_name=mitigation.value,
        tainted=parameters,
        mitigated=set(),
    )
    return summary.has_mitigated_flow and not summary.has_unmitigated_flow


def _source_flows_to_function_call(
    root_path: Path,
    node: SecurityGraphNode,
    *,
    source: SecurityTag,
    function_name: str,
) -> bool:
    function = _function_ast_for_node(root_path, node)
    if function is None:
        return _text_source_flows_to_function_call(
            root_path,
            node,
            source=source,
            function_name=function_name,
        )
    summary = _flow_summary_for_statements(
        function.body,
        source_name=source.value,
        sink_name=function_name,
        mitigation_name=None,
        tainted=set(),
        mitigated=set(),
    )
    return summary.has_source_flow


def _text_source_flows_to_function_call(
    root_path: Path,
    node: SecurityGraphNode,
    *,
    source: SecurityTag,
    function_name: str,
) -> bool:
    body = _text_body_for_node(root_path, node)
    if body is None:
        return False
    source_offsets = _marker_offsets(body, source.value, source=True)
    sink_offsets = _marker_offsets(body, function_name, source=False)
    return bool(
        source_offsets and sink_offsets and min(source_offsets) <= max(sink_offsets)
    )


def _text_mitigation_flows_to_function_call(
    root_path: Path,
    node: SecurityGraphNode,
    *,
    source: SecurityTag,
    function_name: str,
    mitigation: SecurityTag,
) -> bool:
    body = _text_body_for_node(root_path, node)
    if body is None:
        return False
    source_offsets = _marker_offsets(body, source.value, source=True)
    mitigation_offsets = _marker_offsets(body, mitigation.value, source=False)
    sink_offsets = _marker_offsets(body, function_name, source=False)
    if not source_offsets or not mitigation_offsets or not sink_offsets:
        return False
    earliest_source = min(source_offsets)
    last_sink = max(sink_offsets)
    return any(
        earliest_source <= offset <= last_sink
        or (
            offset <= earliest_source <= last_sink
            and _text_mitigation_wraps_source(body, offset, earliest_source)
        )
        for offset in mitigation_offsets
    )


def _text_mitigation_wraps_source(
    body: str,
    mitigation_offset: int,
    source_offset: int,
) -> bool:
    segment = body[mitigation_offset:source_offset]
    return "(" in segment and "\n" not in segment and ";" not in segment


def _text_body_for_node(root_path: Path, node: SecurityGraphNode) -> str | None:
    if not node.file:
        return None
    path = _resolve_node_file(root_path, node.file)
    if path is None:
        return None
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if node.line is None:
        return source
    return "\n".join(
        source.splitlines()[
            max(0, node.line - 1) : node.end_line if node.end_line is not None else None
        ]
    )


def _marker_offsets(body: str, marker: str, *, source: bool) -> list[int]:
    lowered = marker.lower()
    patterns: list[str]
    if lowered == "sql_query":
        patterns = [
            r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b",
            r"\b(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\(",
            r"->\s*(?:query|do|execute|exec)\s*\(",
            r"\.(?:query|queryrow|exec|execute)\s*\(",
        ]
    elif source and lowered in {"$_get", "$_post", "$_request", "$_cookie"}:
        patterns = [re.escape(marker)]
    elif source and lowered in {"@argv", "$argv"}:
        patterns = [r"[@$]ARGV\b|\$ARGV\s*\["]
    elif source and lowered in {
        "req",
        "request",
        "param",
        "params",
        "query",
        "args",
        "argv",
        "body",
        "headers",
        "cookie",
        "cookies",
        "input",
        "stdin",
        "env",
        "url",
        "uri",
        "msg.sender",
        "msg.value",
        "tx.origin",
    }:
        patterns = [rf"\b{re.escape(marker)}\b"]
    elif lowered == "runtime.exec":
        patterns = [
            r"\bruntime\s*\.\s*getruntime\s*\(\s*\)\s*\.\s*exec\s*\(",
            r"\bruntime\s*\.\s*exec\s*\(",
        ]
    elif lowered == "getruntime().exec":
        patterns = [r"\bgetruntime\s*\(\s*\)\s*\.\s*exec\s*\("]
    elif lowered == "process.start":
        patterns = [r"\bprocess\s*\.\s*start\s*\("]
    elif lowered == "system.diagnostics.process.start":
        patterns = [r"\bsystem\s*\.\s*diagnostics\s*\.\s*process\s*\.\s*start\s*\("]
    elif lowered == "exec.command":
        patterns = [r"\bexec\s*\.\s*command(?:context)?\s*\("]
    elif lowered == "command::new":
        patterns = [r"\bcommand\s*::\s*new\s*\("]
    elif lowered == "std::process::command":
        patterns = [r"\bstd\s*::\s*process\s*::\s*command\s*::\s*new\s*\("]
    elif lowered == "vm.runin":
        patterns = [r"\bvm\s*\.\s*runin\w*\s*\("]
    elif lowered == "pdo::query":
        patterns = [r"\bpdo\s*::\s*query\s*\("]
    elif "." in lowered and _looks_like_dotted_call_marker(lowered):
        receiver, method = lowered.rsplit(".", 1)
        patterns = [
            rf"\${re.escape(receiver)}\s*->\s*{re.escape(method)}\s*\(",
            rf"\b{re.escape(receiver)}\s*\.\s*{re.escape(method)}\s*\(",
            rf"\b{re.escape(receiver)}\s*->\s*{re.escape(method)}\s*\(",
        ]
    elif lowered in {
        "exec",
        "execsync",
        "system",
        "shell_exec",
        "passthru",
        "proc_open",
        "popen",
        "spawn",
        "spawn_sync",
        "eval",
        "function",
        "call",
        "delegatecall",
    }:
        patterns = [rf"\b{re.escape(marker)}\s*\(", r"`[^`]+`|\bqx\s*[/({]"]
    elif lowered in {"query", "queryrow", "execute"}:
        patterns = [
            rf"\b{re.escape(marker)}\s*\(",
            rf"\.\s*{re.escape(marker)}\s*\(",
            r"->\s*(?:query|do|execute|exec)\s*\(",
        ]
    else:
        patterns = [re.escape(marker)]
    offsets: list[int] = []
    for pattern in patterns:
        offsets.extend(match.start() for match in re.finditer(pattern, body, re.I))
    return sorted(offsets)


def _looks_like_dotted_call_marker(marker: str) -> bool:
    return bool(re.match(r"^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+$", marker))


def _source_flows_to_direct_call(
    root_path: Path,
    *,
    source_node: SecurityGraphNode,
    sink_node: SecurityGraphNode,
    source: SecurityTag,
) -> bool:
    if not sink_node.symbol:
        return False
    return _source_flows_to_function_call(
        root_path,
        source_node,
        source=source,
        function_name=sink_node.symbol,
    )


@dataclass(frozen=True)
class _FlowSummary:
    has_source_flow: bool = False
    has_mitigated_flow: bool = False
    has_unmitigated_flow: bool = False

    def merge(self, other: "_FlowSummary") -> "_FlowSummary":
        return _FlowSummary(
            has_source_flow=self.has_source_flow or other.has_source_flow,
            has_mitigated_flow=self.has_mitigated_flow or other.has_mitigated_flow,
            has_unmitigated_flow=(
                self.has_unmitigated_flow or other.has_unmitigated_flow
            ),
        )


def _flow_summary_for_statements(
    statements: list[ast.stmt],
    *,
    source_name: str,
    sink_name: str,
    mitigation_name: str | None,
    tainted: set[str],
    mitigated: set[str],
) -> _FlowSummary:
    summary = _FlowSummary()
    for statement in statements:
        if isinstance(statement, ast.Assign | ast.AnnAssign):
            value = statement.value
            if value is not None:
                summary = summary.merge(
                    _flow_summary_for_node(
                        value,
                        source_name=source_name,
                        sink_name=sink_name,
                        mitigation_name=mitigation_name,
                        tainted=tainted,
                        mitigated=mitigated,
                    )
                )
                _update_flow_assignment(
                    statement,
                    source_name=source_name,
                    mitigation_name=mitigation_name,
                    tainted=tainted,
                    mitigated=mitigated,
                )
            continue
        if isinstance(statement, ast.If):
            summary = summary.merge(
                _flow_summary_for_node(
                    statement.test,
                    source_name=source_name,
                    sink_name=sink_name,
                    mitigation_name=mitigation_name,
                    tainted=tainted,
                    mitigated=mitigated,
                )
            )
            body_tainted = set(tainted)
            body_mitigated = set(mitigated)
            orelse_tainted = set(tainted)
            orelse_mitigated = set(mitigated)
            summary = summary.merge(
                _flow_summary_for_statements(
                    statement.body,
                    source_name=source_name,
                    sink_name=sink_name,
                    mitigation_name=mitigation_name,
                    tainted=body_tainted,
                    mitigated=body_mitigated,
                )
            )
            summary = summary.merge(
                _flow_summary_for_statements(
                    statement.orelse,
                    source_name=source_name,
                    sink_name=sink_name,
                    mitigation_name=mitigation_name,
                    tainted=orelse_tainted,
                    mitigated=orelse_mitigated,
                )
            )
            tainted.clear()
            tainted.update(body_tainted | orelse_tainted)
            mitigated.clear()
            mitigated.update(body_mitigated & orelse_mitigated)
            continue
        summary = summary.merge(
            _flow_summary_for_node(
                statement,
                source_name=source_name,
                sink_name=sink_name,
                mitigation_name=mitigation_name,
                tainted=tainted,
                mitigated=mitigated,
            )
        )
    return summary


def _flow_summary_for_node(
    node: ast.AST,
    *,
    source_name: str,
    sink_name: str,
    mitigation_name: str | None,
    tainted: set[str],
    mitigated: set[str],
) -> _FlowSummary:
    summary = _FlowSummary()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or not _call_matches(child, sink_name):
            continue
        summary = summary.merge(
            _flow_summary_for_call(
                child,
                source_name=source_name,
                mitigation_name=mitigation_name,
                tainted=tainted,
                mitigated=mitigated,
            )
        )
    return summary


def _flow_summary_for_call(
    node: ast.Call,
    *,
    source_name: str,
    mitigation_name: str | None,
    tainted: set[str],
    mitigated: set[str],
) -> _FlowSummary:
    summary = _FlowSummary()
    arguments = list(node.args)
    arguments.extend(
        keyword.value for keyword in node.keywords if keyword.value is not None
    )
    for argument in arguments:
        if not _argument_has_source_flow(argument, source_name, tainted, mitigated):
            continue
        argument_mitigated = _argument_is_mitigated(
            argument,
            source_name=source_name,
            mitigation_name=mitigation_name,
            tainted=tainted,
            mitigated=mitigated,
        )
        summary = summary.merge(
            _FlowSummary(
                has_source_flow=True,
                has_mitigated_flow=argument_mitigated,
                has_unmitigated_flow=not argument_mitigated,
            )
        )
    return summary


def _argument_has_source_flow(
    node: ast.AST,
    source_name: str,
    tainted: set[str],
    mitigated: set[str],
) -> bool:
    return (
        _contains_call(node, source_name)
        or _uses_names(node, tainted)
        or _uses_names(node, mitigated)
    )


def _argument_is_mitigated(
    node: ast.AST,
    *,
    source_name: str,
    mitigation_name: str | None,
    tainted: set[str],
    mitigated: set[str],
) -> bool:
    if mitigation_name is not None and _is_direct_mitigation_call(
        node,
        mitigation_name=mitigation_name,
        source_name=source_name,
        tainted=tainted,
        mitigated=mitigated,
    ):
        return True
    if _contains_call(node, source_name) or _uses_names(node, tainted - mitigated):
        return False
    return _uses_names(node, mitigated)


def _is_direct_mitigation_call(
    node: ast.AST,
    *,
    mitigation_name: str,
    source_name: str,
    tainted: set[str],
    mitigated: set[str],
) -> bool:
    if not isinstance(node, ast.Call) or not _call_matches(node, mitigation_name):
        return False
    arguments = list(node.args)
    arguments.extend(
        keyword.value for keyword in node.keywords if keyword.value is not None
    )
    return any(
        _argument_has_source_flow(argument, source_name, tainted, mitigated)
        for argument in arguments
    )


def _update_flow_assignment(
    node: ast.Assign | ast.AnnAssign,
    *,
    source_name: str,
    mitigation_name: str | None,
    tainted: set[str],
    mitigated: set[str],
) -> None:
    value = node.value
    if value is None:
        return
    targets = _assigned_names(node)
    value_is_tainted = _argument_uses_source(value, source_name, tainted)
    value_is_mitigated = _argument_is_mitigated(
        value,
        source_name=source_name,
        mitigation_name=mitigation_name,
        tainted=tainted,
        mitigated=mitigated,
    )
    tainted.difference_update(targets)
    mitigated.difference_update(targets)
    if value_is_tainted or value_is_mitigated:
        tainted.update(targets)
    if value_is_mitigated:
        mitigated.update(targets)


def _argument_uses_source(
    node: ast.AST,
    source_name: str,
    tainted: set[str],
) -> bool:
    return _contains_call(node, source_name) or _uses_names(node, tainted)


def _function_ast_for_node(
    root_path: Path,
    node: SecurityGraphNode,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    if not node.file or not node.symbol:
        return None
    path = _resolve_node_file(root_path, node.file)
    if path is None:
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return None
    for child in ast.walk(tree):
        if (
            isinstance(child, ast.AsyncFunctionDef | ast.FunctionDef)
            and child.name == node.symbol
        ):
            return child
    return None


def _resolve_node_file(root_path: Path, file_name: str) -> Path | None:
    path = Path(file_name)
    candidates = []
    if path.is_absolute():
        candidates.append(path)
    else:
        candidates.extend((root_path.parent / path, root_path / path))
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


def _assigned_names(node: ast.Assign | ast.AnnAssign) -> set[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    names: set[str] = set()
    for target in targets:
        for child in ast.walk(target):
            if isinstance(child, ast.Name):
                names.add(child.id)
    return names


def _uses_names(node: ast.AST, names: set[str]) -> bool:
    if not names:
        return False
    return any(
        isinstance(child, ast.Name) and child.id in names for child in ast.walk(node)
    )


def _contains_call(node: ast.AST, name: str) -> bool:
    return any(
        isinstance(child, ast.Call) and _call_matches(child, name)
        for child in ast.walk(node)
    )


def _mitigation_call_uses_source(
    node: ast.AST,
    *,
    mitigation_name: str,
    source_name: str,
    tainted: set[str],
) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or not _call_matches(child, mitigation_name):
            continue
        if any(_argument_uses_source(arg, source_name, tainted) for arg in child.args):
            return True
        if any(
            keyword.value is not None
            and _argument_uses_source(keyword.value, source_name, tainted)
            for keyword in child.keywords
        ):
            return True
    return False


def _call_matches(node: ast.Call, name: str) -> bool:
    call_name = _call_name(node.func)
    return call_name == name or _normalized_name(call_name or "") == name


def _normalized_name(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _first_source_tag(
    tags: Iterable[SecurityTag],
    *,
    sink_markers: tuple[str, ...],
) -> SecurityTag | None:
    return next(iter(_source_tags(tags, sink_markers=sink_markers)), None)


def _source_tags(
    tags: Iterable[SecurityTag],
    *,
    sink_markers: tuple[str, ...],
    mitigation_markers: tuple[str, ...],
) -> tuple[SecurityTag, ...]:
    sources: list[SecurityTag] = []
    for tag in tags:
        if (
            tag.kind == "source"
            and not _matches_any(tag.value, sink_markers)
            and not _matches_any(tag.value, mitigation_markers)
        ):
            sources.append(tag)
    return tuple(sources)


def _first_matching_tag(
    tags: Iterable[SecurityTag],
    *,
    kind: str | tuple[str, ...],
    markers: tuple[str, ...],
    node_symbol: str | None = None,
) -> SecurityTag | None:
    return next(
        iter(
            _matching_tags(
                tags,
                kind=kind,
                markers=markers,
                node_symbol=node_symbol,
            )
        ),
        None,
    )


def _matching_tags(
    tags: Iterable[SecurityTag],
    *,
    kind: str | tuple[str, ...],
    markers: tuple[str, ...],
    node_symbol: str | None = None,
) -> tuple[SecurityTag, ...]:
    kinds = (kind,) if isinstance(kind, str) else kind
    matches: list[SecurityTag] = []
    for tag in tags:
        if (
            tag.kind in kinds
            and _matches_any(tag.value, markers)
            and (node_symbol is None or tag.value != node_symbol)
        ):
            matches.append(tag)
    return tuple(matches)


def _matches_any(value: str, markers: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return any(_tag_value_matches_marker(lowered, marker) for marker in markers)


def _tag_value_matches_marker(value: str, marker: str) -> bool:
    lowered_marker = marker.lower()
    if value == lowered_marker or value.endswith(f".{lowered_marker}"):
        return True
    if _is_prefix_marker(lowered_marker) and value.startswith(lowered_marker):
        return True
    if re.search(rf"(?:^|[._-]){re.escape(lowered_marker)}(?:$|[._-])", value):
        return True
    if _normalized_name(value) == lowered_marker:
        return True
    if any(not char.isalnum() and char not in "._" for char in lowered_marker):
        return lowered_marker in value
    return bool(
        re.search(
            rf"(?<![a-z0-9_]){re.escape(lowered_marker)}(?![a-z0-9_])",
            value,
        )
    )


def _is_prefix_marker(marker: str) -> bool:
    return marker in {
        "allowlist",
        "authorize",
        "canonical",
        "check_",
        "escape",
        "normalize",
        "parameterize",
        "prepare",
        "require_",
        "sanitize",
        "schema",
        "validate",
        "whitelist",
    }


def _location_for_node(node: SecurityGraphNode, *, role: str) -> FlowStep:
    return FlowStep(
        file=node.file or "",
        line=node.line,
        symbol=node.symbol,
        role=role,
        detail=node.metadata.get("route_path") if node.metadata else None,
    )


def _evidence(
    hypothesis_id: str,
    obligation: str,
    status: EvidenceStatus,
    kind: EvidenceKind,
    claim: str,
    node: SecurityGraphNode,
    tag: SecurityTag,
    *,
    evidence: list[str] | None = None,
) -> EvidenceLedgerEntry:
    file = tag.file or node.file
    line = tag.line or node.line
    symbol = tag.symbol or node.symbol
    return EvidenceLedgerEntry(
        hypothesis_id=hypothesis_id,
        obligation=obligation,
        status=status,
        kind=kind,
        claim=claim,
        evidence=evidence or [f"{file}:{line}" if line else str(file or "")],
        file=file,
        line=line,
        symbol=symbol,
        source_trust=SourceTrust.CODE,
    )


def _observed_mitigations(node: SecurityGraphNode) -> str:
    values = sorted(
        tag.value for tag in node.tags if tag.kind in {"sanitizer", "guard"}
    )
    return ", ".join(values)


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
