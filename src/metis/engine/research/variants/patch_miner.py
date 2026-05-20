# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re

from metis.engine.research.models import (
    EvidenceKind,
    EvidenceLedgerEntry,
    EvidenceObligation,
    EvidenceStatus,
    FlowStep,
    Hypothesis,
    HypothesisStatus,
    ResearchPriority,
    SecurityGraph,
    SecurityGraphNode,
    SourceTrust,
    VariantPattern,
    build_hypothesis_id,
)


VARIANT_HUNTER = "variant_patch"
VARIANT_BASE_OBLIGATIONS = (
    EvidenceObligation(
        name="source",
        description="The candidate route or entrypoint is reachable.",
    ),
    EvidenceObligation(
        name="reachability",
        description="The candidate dispatches to the analyzed handler.",
    ),
    EvidenceObligation(
        name="asset",
        description="The candidate is comparable to the fixed vulnerable shape.",
    ),
    EvidenceObligation(
        name="impact",
        description="The missing fix can expose the same protected behavior.",
    ),
)

_HUNK_RE = re.compile(r"@@ -(?P<old>\d+)(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@")
_GUARD_RE = re.compile(
    r"\b("
    r"require_[A-Za-z0-9_]+|"
    r"check_[A-Za-z0-9_]+|"
    r"authorize[A-Za-z0-9_]*|"
    r"ensure_[A-Za-z0-9_]+|"
    r"verify_[A-Za-z0-9_]+|"
    r"permission_[A-Za-z0-9_]+|"
    r"login_required|jwt_required|permission_required"
    r")\b"
)
_SANITIZER_RE = re.compile(
    r"\b("
    r"sanitize[A-Za-z0-9_]*|validate[A-Za-z0-9_]*|escape[A-Za-z0-9_]*|"
    r"canonical[A-Za-z0-9_]*|normalize[A-Za-z0-9_]*|safe_join|allowlist"
    r")\b"
)
_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_LOCATION_RE = re.compile(
    r"(?P<file>[\w./-]+\.(?:py|c|h|cc|cpp|hpp|rs|sv|svh|v|vh)):(?P<line>\d+)"
)


@dataclass(frozen=True)
class VariantMiningResult:
    patterns: list[VariantPattern]
    hypotheses: list[Hypothesis]


@dataclass(frozen=True)
class _PatchAddedLine:
    file: str
    line: int
    text: str


@dataclass(frozen=True)
class _FixSignature:
    kind: str
    token: str
    obligation: str
    evidence_kind: EvidenceKind
    vulnerability_class: str

    @property
    def label(self) -> str:
        return self.kind.replace("_", " ")


class PatchVariantMiner:
    """Mine patch-shaped fixes into variant hypotheses."""

    name = VARIANT_HUNTER

    def mine(
        self,
        root: str | Path,
        *,
        security_graph: SecurityGraph,
        from_fix: str | Path | None = None,
        from_sarif: str | Path | None = None,
        from_report: str | Path | None = None,
    ) -> VariantMiningResult:
        if not any((from_fix, from_sarif, from_report)):
            raise ValueError("one of from_fix, from_sarif, or from_report is required")
        root_path = Path(root).resolve()
        patterns: list[VariantPattern] = []
        if from_fix is not None:
            patterns.extend(
                self.patterns_from_fix(
                    root_path,
                    Path(from_fix),
                    security_graph=security_graph,
                )
            )
        if from_sarif is not None:
            patterns.extend(
                self.patterns_from_sarif(
                    root_path,
                    Path(from_sarif),
                    security_graph=security_graph,
                )
            )
        if from_report is not None:
            patterns.extend(
                self.patterns_from_report(
                    root_path,
                    Path(from_report),
                    security_graph=security_graph,
                )
            )
        deduped = _dedupe_patterns(patterns)
        hypotheses: list[Hypothesis] = []
        for pattern in deduped:
            hypotheses.extend(self.hypotheses_for_pattern(pattern, security_graph))
        return VariantMiningResult(patterns=deduped, hypotheses=hypotheses)

    def patterns_from_fix(
        self,
        root: str | Path,
        patch_path: Path,
        *,
        security_graph: SecurityGraph,
    ) -> list[VariantPattern]:
        root_path = Path(root).resolve()
        added_lines = _parse_added_lines(patch_path)
        patterns: list[VariantPattern] = []
        for added in added_lines:
            guard = _extract_guard(added.text)
            sanitizer = _extract_sanitizer(added.text)
            bounds_check = _extract_bounds_check(added.text)
            invariant = _extract_invariant(added.text)
            if not any((guard, sanitizer, bounds_check, invariant)):
                continue
            pattern = self._pattern_from_location(
                root_path,
                source="fix",
                source_path=str(patch_path),
                file=added.file,
                line=added.line,
                security_graph=security_graph,
                fixed_guard=guard,
                fixed_sanitizer=sanitizer,
                fixed_invariant=invariant,
                added_bounds_check=bounds_check,
            )
            if pattern is not None:
                patterns.append(pattern)
        return patterns

    def patterns_from_sarif(
        self,
        root: str | Path,
        sarif_path: Path,
        *,
        security_graph: SecurityGraph,
    ) -> list[VariantPattern]:
        try:
            payload = json.loads(sarif_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ValueError(f"Unable to read SARIF source: {sarif_path}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid SARIF JSON: {sarif_path}") from exc
        root_path = Path(root).resolve()
        patterns: list[VariantPattern] = []
        for run in payload.get("runs", []) or []:
            for result in run.get("results", []) or []:
                if not isinstance(result, dict):
                    continue
                props = result.get("properties") or {}
                message = result.get("message") or {}
                message_text = str(message.get("text") or message.get("markdown") or "")
                guard = str(
                    props.get("metisExpectedGuard")
                    or props.get("metisMissingGuard")
                    or _extract_guard(message_text)
                    or ""
                ).strip()
                sanitizer = str(
                    props.get("metisExpectedSanitizer")
                    or props.get("metisMissingSanitizer")
                    or _extract_sanitizer(message_text)
                    or ""
                ).strip()
                bounds_check = str(
                    props.get("metisExpectedBoundsCheck")
                    or props.get("metisMissingBoundsCheck")
                    or _extract_bounds_check(message_text)
                    or ""
                ).strip()
                invariant = str(
                    props.get("metisExpectedInvariant")
                    or props.get("metisMissingInvariant")
                    or _extract_invariant(message_text)
                    or ""
                ).strip()
                if not any((guard, sanitizer, bounds_check, invariant)):
                    continue
                cwe = str(
                    result.get("ruleId")
                    or props.get("metisVulnerabilityClass")
                    or _extract_cwe(message_text)
                    or _vulnerability_class_for_pattern(
                        guard=guard or None,
                        sanitizer=sanitizer or None,
                        bounds_check=bounds_check or None,
                        invariant=invariant or None,
                    )
                )
                for location in result.get("locations", []) or []:
                    physical = location.get("physicalLocation") or {}
                    artifact = physical.get("artifactLocation") or {}
                    region = physical.get("region") or {}
                    file = str(artifact.get("uri") or "").strip()
                    line = int(region.get("startLine") or 1)
                    if not file:
                        continue
                    pattern = self._pattern_from_location(
                        root_path,
                        source="sarif",
                        source_path=str(sarif_path),
                        file=file,
                        line=line,
                        security_graph=security_graph,
                        fixed_guard=guard or None,
                        fixed_sanitizer=sanitizer or None,
                        fixed_invariant=invariant or None,
                        added_bounds_check=bounds_check or None,
                        vulnerability_class=cwe,
                    )
                    if pattern is not None:
                        patterns.append(pattern)
        return patterns

    def patterns_from_report(
        self,
        root: str | Path,
        report_path: Path,
        *,
        security_graph: SecurityGraph,
    ) -> list[VariantPattern]:
        try:
            text = report_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Unable to read report source: {report_path}") from exc
        root_path = Path(root).resolve()
        guard = _extract_guard(text)
        sanitizer = _extract_sanitizer(text)
        bounds_check = _extract_bounds_check(text)
        invariant = _extract_invariant(text)
        if not any((guard, sanitizer, bounds_check, invariant)):
            return []
        cwe = _extract_cwe(text) or _vulnerability_class_for_pattern(
            guard=guard,
            sanitizer=sanitizer,
            bounds_check=bounds_check,
            invariant=invariant,
        )
        patterns: list[VariantPattern] = []
        for match in _LOCATION_RE.finditer(text):
            pattern = self._pattern_from_location(
                root_path,
                source="report",
                source_path=str(report_path),
                file=match.group("file"),
                line=int(match.group("line")),
                security_graph=security_graph,
                fixed_guard=guard,
                fixed_sanitizer=sanitizer,
                fixed_invariant=invariant,
                added_bounds_check=bounds_check,
                vulnerability_class=cwe,
            )
            if pattern is not None:
                patterns.append(pattern)
        return patterns

    def hypotheses_for_pattern(
        self,
        pattern: VariantPattern,
        security_graph: SecurityGraph,
    ) -> list[Hypothesis]:
        signature = _fix_signature(pattern)
        if signature is None:
            return []
        route_group = _predicate_value(pattern, "route_group")
        file_predicate = _predicate_value(pattern, "file")
        symbol_prefix = _predicate_value(pattern, "symbol_prefix")
        hypotheses: list[Hypothesis] = []
        for node in _candidate_nodes(
            security_graph,
            route_group=route_group,
            file_predicate=file_predicate,
            symbol_prefix=symbol_prefix,
        ):
            observed = _observed_fix_tokens(node, signature, security_graph)
            is_negative = _matches_negative_example(pattern, node)
            if is_negative:
                hypotheses.append(
                    _variant_hypothesis(
                        pattern=pattern,
                        node=node,
                        signature=signature,
                        status=HypothesisStatus.CANDIDATE,
                        evidence=_killed_evidence(
                            pattern=pattern,
                            node=node,
                            signature=signature,
                        ),
                        observed_fix=", ".join(observed) if observed else None,
                    )
                )
                continue
            if _fix_present(node, signature, security_graph):
                continue
            hypotheses.append(
                _variant_hypothesis(
                    pattern=pattern,
                    node=node,
                    signature=signature,
                    status=HypothesisStatus.CANDIDATE,
                    evidence=_proven_evidence(
                        pattern=pattern,
                        node=node,
                        signature=signature,
                    ),
                    observed_fix=", ".join(observed) if observed else None,
                )
            )
        return hypotheses

    def _pattern_from_location(
        self,
        root_path: Path,
        *,
        source: str,
        source_path: str,
        file: str,
        line: int,
        security_graph: SecurityGraph,
        fixed_guard: str | None = None,
        fixed_sanitizer: str | None = None,
        fixed_invariant: str | None = None,
        added_bounds_check: str | None = None,
        vulnerability_class: str | None = None,
    ) -> VariantPattern | None:
        node = _node_for_location(security_graph, file=file, line=line)
        if node is None or not node.file or not node.symbol:
            return None
        route = str(node.metadata.get("route_path") or "")
        route_group = str(
            node.metadata.get("route_group") or _route_group(route, node.file)
        )
        guard = fixed_guard or None
        cwe = vulnerability_class or _vulnerability_class_for_pattern(
            guard=guard,
            sanitizer=fixed_sanitizer,
            bounds_check=added_bounds_check,
            invariant=fixed_invariant,
        )
        negative = _flow_step_for_node(
            node,
            role="fixed_location",
            detail=f"Fixed location from {source_path}",
        )
        predicates = [f"file:{_normalize_file(file)}", f"route_group:{route_group}"]
        if not route:
            predicates.append(f"symbol_prefix:{_symbol_prefix(node.symbol)}")
        if guard:
            predicates.append(f"missing_guard:{guard}")
        if fixed_sanitizer:
            predicates.append(f"missing_sanitizer:{fixed_sanitizer}")
        if added_bounds_check:
            predicates.append(f"missing_bounds_check:{added_bounds_check}")
        if fixed_invariant:
            predicates.append(f"missing_invariant:{fixed_invariant}")
        shape = _shape_summary(
            node=node,
            fixed_guard=guard,
            fixed_sanitizer=fixed_sanitizer,
            added_bounds_check=added_bounds_check,
            fixed_invariant=fixed_invariant,
        )
        changed_sinks = _node_tag_values(node, kind="sink")
        return VariantPattern(
            id=build_hypothesis_id(
                str(root_path),
                self.name,
                source,
                source_path,
                node.file,
                node.symbol,
                guard,
                fixed_sanitizer,
                added_bounds_check,
                fixed_invariant,
            ),
            source=source,
            source_path=source_path,
            vulnerability_class=cwe,
            original_vulnerability_shape=shape,
            fixed_guard=guard,
            fixed_sanitizer=fixed_sanitizer,
            fixed_invariant=fixed_invariant,
            search_predicates=predicates,
            negative_examples=[negative],
            changed_sinks=changed_sinks,
            added_guards=[guard] if guard else [],
            added_sanitizers=[fixed_sanitizer] if fixed_sanitizer else [],
            added_bounds_checks=[added_bounds_check] if added_bounds_check else [],
            changed_route_access_policy=[route] if route and guard else [],
            changed_lifetime_or_privilege_invariants=(
                [fixed_invariant] if fixed_invariant else []
            ),
        )


def _parse_added_lines(patch_path: Path) -> list[_PatchAddedLine]:
    try:
        lines = patch_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"Unable to read fix patch: {patch_path}") from exc
    added: list[_PatchAddedLine] = []
    current_file: str | None = None
    new_line: int | None = None
    old_line: int | None = None
    for raw in lines:
        if raw.startswith("+++ "):
            current_file = _normalize_diff_path(raw[4:].strip())
            continue
        hunk = _HUNK_RE.match(raw)
        if hunk:
            old_line = int(hunk.group("old"))
            new_line = int(hunk.group("new"))
            continue
        if current_file is None or new_line is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            added.append(
                _PatchAddedLine(
                    file=current_file,
                    line=new_line,
                    text=raw[1:],
                )
            )
            new_line += 1
            continue
        if raw.startswith("-") and not raw.startswith("---"):
            if old_line is not None:
                old_line += 1
            continue
        if raw.startswith(" "):
            new_line += 1
            if old_line is not None:
                old_line += 1
    return added


def _normalize_diff_path(raw: str) -> str | None:
    if raw == "/dev/null":
        return None
    path = raw.split("\t", 1)[0]
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    return path


def _extract_guard(text: str) -> str | None:
    match = _GUARD_RE.search(text)
    return match.group(1) if match else None


def _extract_sanitizer(text: str) -> str | None:
    match = _SANITIZER_RE.search(text)
    return match.group(1) if match else None


def _extract_bounds_check(text: str) -> str | None:
    lowered = text.lower()
    if "bounds" in lowered or "range" in lowered or "len(" in lowered:
        return text.strip()
    if any(operator in text for operator in ("<=", ">=", "<", ">")) and "if " in text:
        return text.strip()
    return None


def _extract_invariant(text: str) -> str | None:
    lowered = text.lower()
    markers = ("lifetime", "refcount", "lock", "privilege", "secure", "debug")
    if any(marker in lowered for marker in markers):
        return text.strip()
    return None


def _extract_cwe(text: str) -> str | None:
    match = _CWE_RE.search(text)
    return match.group(0).upper() if match else None


def _node_for_location(
    security_graph: SecurityGraph,
    *,
    file: str,
    line: int,
) -> SecurityGraphNode | None:
    normalized_file = _normalize_file(file)
    candidates = [
        node
        for node in security_graph.nodes
        if node.type == "function"
        and _file_matches(_normalize_file(node.file or ""), normalized_file)
    ]
    for node in candidates:
        start = int(node.line or 1)
        end = int(node.end_line or start)
        if start <= line <= end:
            return node
    nearby = [
        node
        for node in candidates
        if node.line is not None and 0 <= int(node.line) - line <= 5
    ]
    if nearby:
        return sorted(nearby, key=lambda node: int(node.line or 1))[0]
    return None


def _normalize_file(file: str) -> str:
    if file.startswith("a/") or file.startswith("b/"):
        file = file[2:]
    return file.replace("\\", "/").lstrip("./")


def _file_matches(node_file: str, requested_file: str) -> bool:
    return node_file == requested_file or node_file.endswith(f"/{requested_file}")


def _node_guards(node: SecurityGraphNode) -> tuple[str, ...]:
    values = {
        str(item)
        for item in node.metadata.get("guards", [])
        if isinstance(item, str) and item
    }
    values.update(tag.value for tag in node.tags if tag.kind == "guard")
    return tuple(sorted(values))


def _fix_signature(pattern: VariantPattern) -> _FixSignature | None:
    if pattern.fixed_guard:
        return _FixSignature(
            kind="guard",
            token=pattern.fixed_guard,
            obligation="missing_guard",
            evidence_kind=EvidenceKind.GUARD_CHECK,
            vulnerability_class=pattern.vulnerability_class,
        )
    if pattern.fixed_sanitizer:
        return _FixSignature(
            kind="sanitizer",
            token=pattern.fixed_sanitizer,
            obligation="missing_sanitizer",
            evidence_kind=EvidenceKind.SANITIZER_CHECK,
            vulnerability_class=pattern.vulnerability_class,
        )
    if pattern.added_bounds_checks:
        return _FixSignature(
            kind="bounds_check",
            token=pattern.added_bounds_checks[0],
            obligation="missing_bounds_check",
            evidence_kind=EvidenceKind.TYPE_CONSTRAINT,
            vulnerability_class=pattern.vulnerability_class,
        )
    if pattern.fixed_invariant:
        return _FixSignature(
            kind="invariant",
            token=pattern.fixed_invariant,
            obligation="missing_invariant",
            evidence_kind=EvidenceKind.CONFIG_CHECK,
            vulnerability_class=pattern.vulnerability_class,
        )
    return None


def _candidate_nodes(
    security_graph: SecurityGraph,
    *,
    route_group: str | None,
    file_predicate: str | None,
    symbol_prefix: str | None,
) -> list[SecurityGraphNode]:
    candidates = [
        node
        for node in security_graph.nodes
        if node.type == "function"
        and (
            not file_predicate
            or _file_matches(
                _normalize_file(node.file or ""),
                _normalize_file(file_predicate),
            )
        )
    ]
    if symbol_prefix:
        candidates = [
            node
            for node in candidates
            if str(node.symbol or "").startswith(symbol_prefix)
        ]
    elif route_group:
        candidates = [
            node
            for node in candidates
            if _route_path(node) and _route_group_for_node(node) == route_group
        ]
    return sorted(candidates, key=_node_sort_key)


def _node_sort_key(node: SecurityGraphNode) -> tuple[str, int, str]:
    return (node.file or "", int(node.line or 0), node.symbol or "")


def _observed_fix_tokens(
    node: SecurityGraphNode,
    signature: _FixSignature,
    security_graph: SecurityGraph,
) -> list[str]:
    source_text = _node_source_text(node, security_graph)
    values: set[str] = set()
    if signature.kind == "guard":
        values.update(_node_guards(node))
    elif signature.kind == "sanitizer":
        values.update(_node_tag_values(node, kind="sanitizer"))
        values.update(
            str(item)
            for item in node.metadata.get("call_names", [])
            if isinstance(item, str) and _extract_sanitizer(item)
        )
    elif signature.kind == "invariant":
        values.update(_node_tag_values(node, kind="guard"))
        values.update(_node_tag_values(node, kind="config"))
        values.update(
            str(item)
            for item in node.metadata.get("call_names", [])
            if isinstance(item, str) and _token_matches(item, signature.token)
        )
    if _source_contains_token(source_text, signature.token):
        values.add(signature.token)
    return sorted(value for value in values if _token_matches(value, signature.token))


def _fix_present(
    node: SecurityGraphNode,
    signature: _FixSignature,
    security_graph: SecurityGraph,
) -> bool:
    return bool(_observed_fix_tokens(node, signature, security_graph))


def _node_tag_values(node: SecurityGraphNode, *, kind: str) -> list[str]:
    values = {
        tag.value
        for tag in node.tags
        if tag.kind == kind and isinstance(tag.value, str) and tag.value
    }
    if kind == "guard":
        values.update(
            str(item)
            for item in node.metadata.get("guards", [])
            if isinstance(item, str) and item
        )
    return sorted(values)


def _node_source_text(
    node: SecurityGraphNode,
    security_graph: SecurityGraph,
) -> str:
    for path in _node_source_paths(node, security_graph):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        start = max(0, int(node.line or 1) - 1)
        end = int(node.end_line or len(lines))
        return "\n".join(lines[start:end])
    return ""


def _node_source_paths(
    node: SecurityGraphNode,
    security_graph: SecurityGraph,
) -> list[Path]:
    if not node.file:
        return []
    raw = Path(node.file)
    if raw.is_absolute():
        return [raw]
    analysis_root = Path(security_graph.analysis_root).resolve()
    normalized = _normalize_file(node.file)
    candidates = [
        analysis_root / normalized,
        analysis_root.parent / normalized,
        analysis_root / Path(normalized).name,
    ]
    if normalized.startswith(f"{analysis_root.name}/"):
        candidates.append(analysis_root / normalized[len(analysis_root.name) + 1 :])
    deduped: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in deduped:
            deduped.append(resolved)
    return deduped


def _source_contains_token(source_text: str, token: str) -> bool:
    if not source_text or not token:
        return False
    normalized_token = _normalize_token(token)
    return any(
        normalized_token in _normalize_token(line) for line in source_text.splitlines()
    )


def _token_matches(value: str, token: str) -> bool:
    normalized_value = _normalize_token(value)
    normalized_token = _normalize_token(token)
    return bool(
        normalized_value
        and normalized_token
        and (
            normalized_value == normalized_token
            or normalized_value in normalized_token
            or normalized_token in normalized_value
        )
    )


def _normalize_token(value: str) -> str:
    return " ".join(str(value).strip().lower().split())


def _symbol_prefix(symbol: str) -> str:
    head, sep, _tail = symbol.rpartition("_")
    return head if sep and head else symbol


def _predicate_value(pattern: VariantPattern, prefix: str) -> str | None:
    needle = f"{prefix}:"
    for predicate in pattern.search_predicates:
        if predicate.startswith(needle):
            return predicate[len(needle) :]
    return None


def _matches_negative_example(
    pattern: VariantPattern,
    node: SecurityGraphNode,
) -> bool:
    for example in pattern.negative_examples:
        if _normalize_file(example.file) != _normalize_file(node.file or ""):
            continue
        if example.symbol and node.symbol and example.symbol == node.symbol:
            return True
        if example.symbol or node.symbol:
            continue
        if example.line and node.line and abs(example.line - node.line) <= 5:
            return True
    return False


def _variant_hypothesis(
    *,
    pattern: VariantPattern,
    node: SecurityGraphNode,
    signature: _FixSignature,
    status: HypothesisStatus,
    evidence: list[EvidenceLedgerEntry],
    observed_fix: str | None,
) -> Hypothesis:
    route = str(node.metadata.get("route_path") or node.symbol or "")
    route_group = str(
        node.metadata.get("route_group") or _route_group(route, node.file or "")
    )
    title_state = "fixed" if observed_fix else "missing"
    missing_guard = (
        signature.token if signature.kind == "guard" and observed_fix is None else None
    )
    return Hypothesis(
        id=build_hypothesis_id(pattern.id, node.file, node.symbol, route),
        hunter=VARIANT_HUNTER,
        vulnerability_class=pattern.vulnerability_class,
        title=(
            f"Variant {title_state} {signature.label} "
            f"{signature.token} on {node.symbol}"
        ),
        source=route,
        path=[_flow_step_for_node(node, role="entrypoint", detail=f"Route {route}")],
        asset=route_group,
        expected_guard=signature.token if signature.kind == "guard" else None,
        observed_guard=observed_fix if signature.kind == "guard" else None,
        missing_guard=missing_guard,
        impact=_impact_for_signature(signature),
        evidence_obligations=_variant_obligations(signature),
        evidence=evidence,
        status=status,
        confidence=0.8 if observed_fix is None else 0.9,
        locations=[
            _flow_step_for_node(node, role="entrypoint", detail=f"Route {route}")
        ],
        sarif_rule_id=pattern.vulnerability_class,
        priority=ResearchPriority.HIGH,
    )


def _proven_evidence(
    *,
    pattern: VariantPattern,
    node: SecurityGraphNode,
    signature: _FixSignature,
) -> list[EvidenceLedgerEntry]:
    hypothesis_id = build_hypothesis_id(
        pattern.id, node.file, node.symbol, _route(node)
    )
    return [
        _evidence(
            hypothesis_id,
            "source",
            EvidenceStatus.SATISFIED,
            _source_evidence_kind(node),
            _source_claim(node, fixed=False),
            node,
        ),
        _evidence(
            hypothesis_id,
            "reachability",
            EvidenceStatus.SATISFIED,
            EvidenceKind.DEFINITION,
            f"The candidate dispatches to analyzed handler {node.symbol}.",
            node,
        ),
        _evidence(
            hypothesis_id,
            "asset",
            EvidenceStatus.SATISFIED,
            EvidenceKind.DEFINITION,
            f"The handler belongs to route group {_route_group_for_node(node)}.",
            node,
        ),
        _evidence(
            hypothesis_id,
            signature.obligation,
            EvidenceStatus.SATISFIED,
            EvidenceKind.NEGATIVE_EVIDENCE,
            (
                f"Fix-derived {signature.label} {signature.token} is absent "
                "from this candidate."
            ),
            node,
            evidence=[f"variant pattern: {pattern.id}"],
        ),
        _evidence(
            hypothesis_id,
            "impact",
            EvidenceStatus.SATISFIED,
            EvidenceKind.STATIC_TRACE,
            _impact_evidence_claim(signature),
            node,
        ),
    ]


def _killed_evidence(
    *,
    pattern: VariantPattern,
    node: SecurityGraphNode,
    signature: _FixSignature,
) -> list[EvidenceLedgerEntry]:
    hypothesis_id = build_hypothesis_id(
        pattern.id, node.file, node.symbol, _route(node)
    )
    return [
        _evidence(
            hypothesis_id,
            "source",
            EvidenceStatus.SATISFIED,
            _source_evidence_kind(node),
            _source_claim(node, fixed=True),
            node,
        ),
        _evidence(
            hypothesis_id,
            "reachability",
            EvidenceStatus.SATISFIED,
            EvidenceKind.DEFINITION,
            f"The candidate dispatches to analyzed handler {node.symbol}.",
            node,
        ),
        _evidence(
            hypothesis_id,
            "asset",
            EvidenceStatus.SATISFIED,
            EvidenceKind.DEFINITION,
            f"The handler belongs to route group {_route_group_for_node(node)}.",
            node,
        ),
        _evidence(
            hypothesis_id,
            signature.obligation,
            EvidenceStatus.FAILED,
            signature.evidence_kind,
            (
                f"Fix-derived {signature.label} {signature.token} is present "
                "at the original location."
            ),
            node,
            evidence=[f"variant pattern: {pattern.id}"],
        ),
        _evidence(
            hypothesis_id,
            "impact",
            EvidenceStatus.NOT_APPLICABLE,
            EvidenceKind.NEGATIVE_EVIDENCE,
            "The fixed original location is killed before impact analysis.",
            node,
        ),
    ]


def _variant_obligations(signature: _FixSignature) -> list[EvidenceObligation]:
    obligations: list[EvidenceObligation] = []
    for obligation in VARIANT_BASE_OBLIGATIONS:
        if obligation.name == "impact":
            obligations.append(
                EvidenceObligation(
                    name=signature.obligation,
                    description=(
                        f"The candidate is missing the {signature.label} "
                        "added by the fix."
                    ),
                )
            )
        obligations.append(obligation)
    return obligations


def _source_evidence_kind(node: SecurityGraphNode) -> EvidenceKind:
    return (
        EvidenceKind.ROUTE_REGISTRATION
        if _route_path(node)
        else EvidenceKind.DEFINITION
    )


def _source_claim(node: SecurityGraphNode, *, fixed: bool) -> str:
    if _route_path(node):
        role = "fixed original route" if fixed else "registered sibling route"
        return f"{_route_path(node)} is the {role} from the variant pattern."
    role = "fixed original function" if fixed else "candidate sibling function"
    return f"{node.symbol} is the {role} from the variant pattern."


def _impact_for_signature(signature: _FixSignature) -> str:
    if signature.kind == "guard":
        return (
            "A route or entrypoint similar to a fixed vulnerability may remain "
            "reachable without the same guard."
        )
    if signature.kind == "sanitizer":
        return (
            "A sibling data path may still process attacker-controlled data without "
            "the sanitizer added by the fix."
        )
    if signature.kind == "bounds_check":
        return (
            "A sibling data path may still accept unchecked sizes or indexes without "
            "the bounds check added by the fix."
        )
    return (
        "A sibling privileged or lifetime-sensitive path may still run without the "
        "invariant added by the fix."
    )


def _impact_evidence_claim(signature: _FixSignature) -> str:
    return (
        f"Missing the fix-derived {signature.label} can expose the same "
        "vulnerable behavior in a sibling path."
    )


def _evidence(
    hypothesis_id: str,
    obligation: str,
    status: EvidenceStatus,
    kind: EvidenceKind,
    claim: str,
    node: SecurityGraphNode,
    *,
    evidence: list[str] | None = None,
) -> EvidenceLedgerEntry:
    return EvidenceLedgerEntry(
        hypothesis_id=hypothesis_id,
        obligation=obligation,
        status=status,
        kind=kind,
        claim=claim,
        evidence=evidence or [_node_ref(node)],
        file=node.file,
        line=node.line,
        symbol=node.symbol,
        source_trust=SourceTrust.CODE,
    )


def _node_ref(node: SecurityGraphNode) -> str:
    if node.file and node.line:
        return f"{node.file}:{node.line}"
    return str(node.symbol or node.id)


def _route(node: SecurityGraphNode) -> str:
    return str(node.metadata.get("route_path") or node.symbol or "")


def _route_path(node: SecurityGraphNode) -> str:
    return str(node.metadata.get("route_path") or "")


def _route_group_for_node(node: SecurityGraphNode) -> str:
    return str(
        node.metadata.get("route_group") or _route_group(_route(node), node.file or "")
    )


def _flow_step_for_node(
    node: SecurityGraphNode,
    *,
    role: str,
    detail: str | None = None,
) -> FlowStep:
    return FlowStep(
        file=node.file or "",
        line=node.line,
        symbol=node.symbol,
        role=role,
        detail=detail,
    )


def _route_group(route: str, fallback: str) -> str:
    parts = [
        part for part in route.strip().split("/") if part and not part.startswith("<")
    ]
    return parts[0] if parts else Path(fallback).stem


def _shape_summary(
    *,
    node: SecurityGraphNode,
    fixed_guard: str | None,
    fixed_sanitizer: str | None,
    added_bounds_check: str | None,
    fixed_invariant: str | None,
) -> str:
    route = _route(node)
    if fixed_guard:
        return f"{route or node.symbol} fixed by adding guard {fixed_guard}."
    if fixed_sanitizer:
        return f"{node.symbol} fixed by adding sanitizer {fixed_sanitizer}."
    if added_bounds_check:
        return f"{node.symbol} fixed by adding bounds check {added_bounds_check}."
    if fixed_invariant:
        return f"{node.symbol} fixed by adding invariant {fixed_invariant}."
    return f"{node.symbol} changed by a fix patch."


def _vulnerability_class_for_pattern(
    *,
    guard: str | None,
    sanitizer: str | None,
    bounds_check: str | None,
    invariant: str | None,
) -> str:
    if guard:
        lowered = guard.lower()
        auth_tokens = (
            "auth",
            "permission",
            "member",
            "role",
            "tenant",
            "owner",
            "admin",
        )
        if any(token in lowered for token in auth_tokens):
            return "CWE-862"
        return "CWE-693"
    if sanitizer:
        return "CWE-20"
    if bounds_check:
        return "CWE-129"
    if invariant:
        return "CWE-664"
    return "CWE-693"


def _dedupe_patterns(patterns: list[VariantPattern]) -> list[VariantPattern]:
    deduped: dict[str, VariantPattern] = {}
    for pattern in patterns:
        deduped.setdefault(pattern.id, pattern)
    return list(deduped.values())
