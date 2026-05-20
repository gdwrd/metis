# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ast
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from metis.engine.research.hunters.base import HunterMetadata
from metis.engine.research.learning import AuthzLessonIndex
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
    SourceTrust,
    build_hypothesis_id,
)


AUTHZ_OBLIGATIONS = (
    EvidenceObligation(
        name="source",
        description="The route or handler is reachable from an untrusted caller.",
    ),
    EvidenceObligation(
        name="reachability",
        description="The entrypoint dispatches to the handler being analyzed.",
    ),
    EvidenceObligation(
        name="asset",
        description="The handler operates on a protected resource or route group.",
    ),
    EvidenceObligation(
        name="missing_guard",
        description="The comparable handler pattern expects an authorization guard.",
    ),
    EvidenceObligation(
        name="impact",
        description="Missing authorization can expose or mutate protected resources.",
    ),
)

AUTHZ_OBLIGATION_NAMES = tuple(obligation.name for obligation in AUTHZ_OBLIGATIONS)


@dataclass(frozen=True)
class Handler:
    file: Path
    rel_file: str
    symbol: str
    line: int
    route: str
    group: str
    guards: tuple[str, ...]


class AuthzOutlierHunter:
    name = "authz_outlier"
    vulnerability_class = "CWE-862"
    metadata = HunterMetadata(
        name=name,
        vulnerability_class=vulnerability_class,
        supported_languages=("python",),
        supported_model_tags=("entrypoint", "guard", "framework"),
        required_graph_fields=("nodes", "tags", "metadata"),
        evidence_obligations=AUTHZ_OBLIGATION_NAMES,
        benchmark_classes=(vulnerability_class,),
    )

    def __init__(
        self,
        *,
        guard_keywords: Iterable[str] | None = None,
    ) -> None:
        self.guard_keywords = tuple(
            guard_keywords
            or (
                "require_",
                "check_",
                "authorize",
                "permission",
                "owner",
                "tenant",
                "admin",
                "authenticated",
                "login_required",
                "jwt_required",
                "policy",
                "acl",
            )
        )

    def hunt(
        self,
        root: str | Path,
        *,
        security_model: ProjectSecurityModel | None = None,
        security_graph: SecurityGraph | None = None,
        lessons: tuple[ResearchLesson, ...] = (),
    ) -> ResearchRunResult:
        root_path = Path(root).resolve()
        handlers = self._handlers_from_model(security_model)
        if not handlers and security_graph is not None:
            handlers = self._handlers_from_graph(security_graph)
        if not handlers:
            handlers = self._discover_handlers(root_path)
        by_group: dict[str, list[Handler]] = defaultdict(list)
        for handler in handlers:
            by_group[handler.group].append(handler)

        hypotheses: list[Hypothesis] = []
        lesson_refs: set[str] = set()
        suppressed = 0
        lesson_index = AuthzLessonIndex(lessons, hunter=self.name)
        for group_handlers in by_group.values():
            expected_guard = self._expected_guard(group_handlers)
            expected_guard = expected_guard or lesson_index.expected_guard_for(
                group_handlers[0].group
            )
            for handler in group_handlers:
                suppression = lesson_index.suppression_for(
                    source=handler.route,
                    file=handler.rel_file,
                    symbol=handler.symbol,
                    observed_guards=handler.guards,
                )
                if suppression is not None:
                    lesson_refs.add(suppression.id)
                    suppressed += 1
                    continue
                handler_lesson_refs = lesson_index.refs_for(
                    source=handler.route,
                    asset=handler.group,
                    expected_guard=expected_guard,
                )
                lesson_refs.update(handler_lesson_refs)
                hypothesis = self._hypothesis_for_handler(
                    root_path=root_path,
                    handler=handler,
                    expected_guard=expected_guard,
                )
                if handler_lesson_refs:
                    hypothesis = hypothesis.model_copy(
                        update={"lesson_refs": handler_lesson_refs}
                    )
                hypotheses.append(hypothesis)
        return ResearchRunResult.from_hypotheses(
            hypotheses,
            metric_summary={
                "lessons_reused": len(lesson_refs),
                "lesson_refs": sorted(lesson_refs),
                "suppressed_by_lesson": suppressed,
            },
        )

    def _handlers_from_model(
        self,
        security_model: ProjectSecurityModel | None,
    ) -> list[Handler]:
        if security_model is None:
            return []
        handlers: list[Handler] = []
        for entrypoint in security_model.entrypoints:
            route = str(entrypoint.metadata.get("route_path") or entrypoint.name or "")
            if not route:
                continue
            guards = entrypoint.metadata.get("guards", [])
            if not isinstance(guards, list):
                guards = []
            group = str(entrypoint.metadata.get("route_group") or _route_group(route, entrypoint.file or ""))
            handlers.append(
                Handler(
                    file=Path(entrypoint.file or ""),
                    rel_file=str(entrypoint.file or ""),
                    symbol=str(entrypoint.symbol or entrypoint.name),
                    line=int(entrypoint.line or 1),
                    route=route,
                    group=group,
                    guards=tuple(sorted(str(guard) for guard in guards)),
                )
            )
        return handlers

    def _handlers_from_graph(self, security_graph: SecurityGraph) -> list[Handler]:
        handlers: list[Handler] = []
        for node in security_graph.nodes:
            if node.type != "function":
                continue
            route = str(node.metadata.get("route_path") or "")
            if not route:
                continue
            guards = tuple(
                sorted(tag.value for tag in node.tags if tag.kind == "guard")
            )
            group = str(node.metadata.get("route_group") or _route_group(route, node.file or ""))
            handlers.append(
                Handler(
                    file=Path(node.file or ""),
                    rel_file=str(node.file or ""),
                    symbol=str(node.symbol or route),
                    line=int(node.line or 1),
                    route=route,
                    group=group,
                    guards=guards,
                )
            )
        return handlers

    def _discover_handlers(self, root: Path) -> list[Handler]:
        handlers: list[Handler] = []
        for path in sorted(root.rglob("*.py")):
            if ".metis" in path.parts:
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue
            rel_file = path.relative_to(root).as_posix()
            for node in ast.walk(tree):
                if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
                    continue
                route = self._route_for(node)
                if route is None:
                    continue
                guards = tuple(sorted(self._guards_for(node)))
                handlers.append(
                    Handler(
                        file=path,
                        rel_file=rel_file,
                        symbol=node.name,
                        line=int(getattr(node, "lineno", 1) or 1),
                        route=route,
                        group=_route_group(route, rel_file),
                        guards=guards,
                    )
                )
        return handlers

    def _route_for(self, node: ast.AsyncFunctionDef | ast.FunctionDef) -> str | None:
        for decorator in node.decorator_list:
            name = _call_name(decorator)
            if not _is_route_decorator(name):
                continue
            route = _first_string_argument(decorator)
            if route:
                return route
        return None

    def _guards_for(self, node: ast.AsyncFunctionDef | ast.FunctionDef) -> set[str]:
        guards: set[str] = set()
        for decorator in node.decorator_list:
            name = _call_name(decorator)
            if name and not _is_route_decorator(name) and self._is_guard_name(name):
                guards.add(_normalized_name(name))
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = _call_name(child)
            if name and self._is_guard_name(name):
                guards.add(_normalized_name(name))
        return guards

    def _is_guard_name(self, name: str) -> bool:
        lowered = _normalized_name(name).lower()
        return any(keyword in lowered for keyword in self.guard_keywords)

    def _expected_guard(self, handlers: list[Handler]) -> str | None:
        counts: Counter[str] = Counter()
        for handler in handlers:
            counts.update(handler.guards)
        if not counts:
            return None
        top = counts.most_common()
        if len(top) > 1 and top[0][1] == top[1][1]:
            return None
        return top[0][0]

    def _hypothesis_for_handler(
        self,
        *,
        root_path: Path,
        handler: Handler,
        expected_guard: str | None,
    ) -> Hypothesis:
        hypothesis_id = build_hypothesis_id(
            str(root_path),
            self.name,
            handler.rel_file,
            handler.symbol,
            handler.route,
            expected_guard,
        )
        source_step = FlowStep(
            file=handler.rel_file,
            line=handler.line,
            symbol=handler.symbol,
            role="entrypoint",
            detail=f"Route {handler.route}",
        )
        if expected_guard is None:
            evidence = self._base_evidence(
                hypothesis_id=hypothesis_id,
                handler=handler,
                status=EvidenceStatus.MISSING,
                claim="No comparable guarded handler pattern was established.",
                obligation="missing_guard",
            )
            return self._new_hypothesis(
                hypothesis_id=hypothesis_id,
                handler=handler,
                source_step=source_step,
                title=f"Unresolved authorization pattern for {handler.symbol}",
                expected_guard=None,
                missing_guard=None,
                evidence=evidence,
                status=HypothesisStatus.UNRESOLVED,
                unresolved_reason="No dominant comparable authorization guard pattern",
                confidence=0.25,
            )

        if expected_guard in handler.guards:
            evidence = self._base_evidence(
                hypothesis_id=hypothesis_id,
                handler=handler,
                status=EvidenceStatus.FAILED,
                claim=f"Equivalent guard {expected_guard} is present.",
                obligation="missing_guard",
                kind=EvidenceKind.GUARD_CHECK,
            )
            return self._new_hypothesis(
                hypothesis_id=hypothesis_id,
                handler=handler,
                source_step=source_step,
                title=f"Authorization candidate killed for {handler.symbol}",
                expected_guard=expected_guard,
                missing_guard=None,
                evidence=evidence,
                status=HypothesisStatus.KILLED,
                kill_reason=f"Equivalent guard {expected_guard} is present",
                confidence=0.9,
            )

        evidence = self._proven_evidence(
            hypothesis_id=hypothesis_id,
            handler=handler,
            expected_guard=expected_guard,
        )
        return self._new_hypothesis(
            hypothesis_id=hypothesis_id,
            handler=handler,
            source_step=source_step,
            title=f"Missing authorization guard on {handler.symbol}",
            expected_guard=expected_guard,
            missing_guard=expected_guard,
            evidence=evidence,
            status=HypothesisStatus.PROVEN,
            confidence=0.85,
        )

    def _new_hypothesis(
        self,
        *,
        hypothesis_id: str,
        handler: Handler,
        source_step: FlowStep,
        title: str,
        expected_guard: str | None,
        missing_guard: str | None,
        evidence: list[EvidenceLedgerEntry],
        status: HypothesisStatus,
        confidence: float,
        kill_reason: str | None = None,
        unresolved_reason: str | None = None,
    ) -> Hypothesis:
        return Hypothesis(
            id=hypothesis_id,
            hunter=self.name,
            vulnerability_class=self.vulnerability_class,
            title=title,
            source=handler.route,
            path=[source_step],
            asset=handler.group,
            expected_guard=expected_guard,
            observed_guard=", ".join(handler.guards) if handler.guards else None,
            missing_guard=missing_guard,
            impact=(
                f"Unauthorized callers may access protected {handler.group} "
                f"behavior through {handler.symbol}."
            ),
            evidence_obligations=list(AUTHZ_OBLIGATIONS),
            evidence=evidence,
            status=status,
            kill_reason=kill_reason,
            unresolved_reason=unresolved_reason,
            confidence=confidence,
            locations=[source_step],
            sarif_rule_id=self.vulnerability_class,
            priority=ResearchPriority.HIGH,
        )

    def _base_evidence(
        self,
        *,
        hypothesis_id: str,
        handler: Handler,
        status: EvidenceStatus,
        claim: str,
        obligation: str,
        kind: EvidenceKind = EvidenceKind.NEGATIVE_EVIDENCE,
    ) -> list[EvidenceLedgerEntry]:
        return [
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation="source",
                status=EvidenceStatus.SATISFIED,
                kind=EvidenceKind.ROUTE_REGISTRATION,
                claim=f"{handler.route} is registered as a route.",
                evidence=[f"{handler.rel_file}:{handler.line}"],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
                source_trust=SourceTrust.CODE,
            ),
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation="reachability",
                status=EvidenceStatus.SATISFIED,
                kind=EvidenceKind.DEFINITION,
                claim=f"The route dispatches to handler {handler.symbol}.",
                evidence=[f"{handler.rel_file}:{handler.line}"],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
                source_trust=SourceTrust.CODE,
            ),
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation="asset",
                status=EvidenceStatus.SATISFIED,
                kind=EvidenceKind.DEFINITION,
                claim=f"The handler belongs to route group {handler.group}.",
                evidence=[handler.route],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
                source_trust=SourceTrust.CODE,
            ),
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation=obligation,
                status=status,
                kind=kind,
                claim=claim,
                evidence=[f"{handler.rel_file}:{handler.line}"],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
                source_trust=SourceTrust.CODE,
            ),
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation="impact",
                status=(
                    EvidenceStatus.NOT_APPLICABLE
                    if status == EvidenceStatus.FAILED
                    else EvidenceStatus.MISSING
                ),
                kind=EvidenceKind.STATIC_TRACE,
                claim=(
                    "Equivalent authorization guard kills the candidate before "
                    "impact analysis."
                    if status == EvidenceStatus.FAILED
                    else "Impact is unresolved without a dominant expected guard."
                ),
                evidence=[handler.route],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
                source_trust=SourceTrust.CODE,
            ),
        ]

    def _proven_evidence(
        self,
        *,
        hypothesis_id: str,
        handler: Handler,
        expected_guard: str,
    ) -> list[EvidenceLedgerEntry]:
        return [
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation="source",
                status=EvidenceStatus.SATISFIED,
                kind=EvidenceKind.ROUTE_REGISTRATION,
                claim=f"{handler.route} is registered as an externally reachable route.",
                evidence=[f"{handler.rel_file}:{handler.line}"],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
            ),
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation="reachability",
                status=EvidenceStatus.SATISFIED,
                kind=EvidenceKind.DEFINITION,
                claim=f"The route dispatches to handler {handler.symbol}.",
                evidence=[f"{handler.rel_file}:{handler.line}"],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
            ),
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation="asset",
                status=EvidenceStatus.SATISFIED,
                kind=EvidenceKind.DEFINITION,
                claim=f"The handler belongs to protected route group {handler.group}.",
                evidence=[handler.route],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
            ),
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation="missing_guard",
                status=EvidenceStatus.SATISFIED,
                kind=EvidenceKind.NEGATIVE_EVIDENCE,
                claim=f"Expected guard {expected_guard} is absent from the handler.",
                evidence=[f"observed guards: {', '.join(handler.guards) or 'none'}"],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
            ),
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis_id,
                obligation="impact",
                status=EvidenceStatus.SATISFIED,
                kind=EvidenceKind.STATIC_TRACE,
                claim=(
                    "A route in a guarded group without the expected guard can expose "
                    "protected resource operations."
                ),
                evidence=[handler.route],
                file=handler.rel_file,
                line=handler.line,
                symbol=handler.symbol,
            ),
        ]


def _is_route_decorator(name: str | None) -> bool:
    if not name:
        return False
    normalized = _normalized_name(name).lower()
    return normalized in {"route", "get", "post", "put", "patch", "delete"} or (
        "." in name and normalized == "route"
    )


def _route_group(route: str, fallback: str) -> str:
    cleaned = route.strip()
    parts = [part for part in cleaned.split("/") if part and not part.startswith("<")]
    return parts[0] if parts else Path(fallback).stem


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _first_string_argument(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    for keyword in node.keywords:
        if keyword.arg not in {"path", "rule", "route"}:
            continue
        value = keyword.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
    return None


def _normalized_name(name: str) -> str:
    return name.rsplit(".", 1)[-1]
