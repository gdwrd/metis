# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any

from .base import AnalyzerRequest


@dataclass(frozen=True)
class TreeSitterDefinition:
    symbol: str
    line: int


@dataclass(frozen=True)
class TreeSitterReference:
    symbol: str
    line: int


@dataclass(frozen=True)
class TreeSitterFlowHop:
    role: str
    line: int
    detail: str
    symbol: str = ""


@dataclass(frozen=True)
class TreeSitterFunctionInfo:
    name: str
    line_start: int
    line_end: int
    node: Any
    calls: list[TreeSitterReference]
    checks: list[TreeSitterFlowHop]


@dataclass(frozen=True)
class TreeSitterAstConfig:
    function_node_types: frozenset[str]
    call_node_types: frozenset[str]
    name_fields: tuple[str, ...]
    call_name_fields: tuple[str, ...]
    definition_node_types: frozenset[str]
    reference_node_types: frozenset[str]
    parameter_node_types: frozenset[str]
    import_node_types: frozenset[str]
    return_node_types: frozenset[str]
    check_node_types: frozenset[str]
    condition_fields: tuple[str, ...]
    identifier_node_types: frozenset[str]


@dataclass(frozen=True)
class TreeSitterAstIndex:
    root: Any
    source: bytes
    node_index: list[Any]
    parent_map: dict[int, Any | None]
    definitions: dict[str, list[TreeSitterDefinition]]
    references: dict[str, list[TreeSitterReference]]
    calls: dict[str, list[TreeSitterReference]]
    functions: dict[str, list[TreeSitterFunctionInfo]]


def normalize_analyzer_config(raw: Mapping[str, Any] | None) -> TreeSitterAstConfig:
    raw = raw or {}
    function_types = _items(
        raw.get("function_node_types"),
        raw.get("method_node_types"),
        raw.get("function"),
    )
    call_types = _items(raw.get("call_node_types"), raw.get("call"))
    name_fields = _items(
        raw.get("name_fields"),
        raw.get("function_name_fields"),
        raw.get("name"),
        ("name", "declarator", "function", "property", "field"),
    )
    call_name_fields = _items(
        raw.get("call_name_fields"),
        raw.get("call_name_field"),
        ("function", "callee", "name", "field", "property", *name_fields),
    )
    identifier_types = _items(
        raw.get("identifier_node_types"),
        (
            "identifier",
            "field_identifier",
            "property_identifier",
            "type_identifier",
            "constant",
        ),
    )
    definition_types = _items(
        raw.get("definition_node_types"),
        raw.get("definition"),
        function_types,
    )
    reference_types = _items(
        raw.get("reference_node_types"),
        raw.get("reference"),
        identifier_types,
    )
    check_types = _items(
        raw.get("check_node_types"),
        raw.get("guard_node_types"),
        (
            "if_statement",
            "while_statement",
            "for_statement",
            "for_in_statement",
            "switch_statement",
            "match_expression",
            "assert_statement",
        ),
    )
    parameter_types = _items(raw.get("parameter_node_types"), raw.get("parameter"))
    import_types = _items(raw.get("import_node_types"), raw.get("import"))
    return_types = _items(
        raw.get("return_node_types"),
        raw.get("return"),
        ("return_statement", "return_expression"),
    )
    condition_fields = _items(raw.get("condition_fields"), ("condition", "value"))
    return TreeSitterAstConfig(
        function_node_types=frozenset(function_types),
        call_node_types=frozenset(call_types),
        name_fields=tuple(name_fields),
        call_name_fields=tuple(call_name_fields),
        definition_node_types=frozenset(definition_types),
        reference_node_types=frozenset(reference_types),
        parameter_node_types=frozenset(parameter_types),
        import_node_types=frozenset(import_types),
        return_node_types=frozenset(return_types),
        check_node_types=frozenset(check_types),
        condition_fields=tuple(condition_fields),
        identifier_node_types=frozenset(identifier_types),
    )


def collect_tree_sitter_ast(root, source: bytes, config: TreeSitterAstConfig):
    node_index, parent_map = index_tree(root)
    definitions = collect_definitions(root, source, config, parent_map)
    references = collect_references(root, source, config)
    calls = collect_calls(root, source, config)
    functions = collect_functions(root, source, config, parent_map)
    return TreeSitterAstIndex(
        root=root,
        source=source,
        node_index=node_index,
        parent_map=parent_map,
        definitions=definitions,
        references=references,
        calls=calls,
        functions=functions,
    )


def index_tree(root) -> tuple[list[Any], dict[int, Any | None]]:
    nodes: list[Any] = []
    parent_map: dict[int, Any | None] = {}
    stack = [(root, None)]
    while stack:
        node, parent = stack.pop()
        nodes.append(node)
        parent_map[id(node)] = parent
        children = list(getattr(node, "children", []) or [])
        stack.extend((child, node) for child in reversed(children))
    return nodes, parent_map


def find_anchor_node(nodes: list[Any], line: int):
    best = None
    best_score = 1_000_000
    best_span = 1_000_000
    for node in nodes:
        start = node_line(node)
        end = node_end_line(node)
        if start <= line <= end:
            score = 0
            span = max(1, end - start + 1)
        else:
            score = min(abs(start - line), abs(end - line))
            span = max(1, end - start + 1)
        if score < best_score or (score == best_score and span < best_span):
            best = node
            best_score = score
            best_span = span
    return best


def select_anchor_function(
    *,
    request_line: int,
    anchor_node,
    parent_map: dict[int, Any | None],
    functions: dict[str, list[TreeSitterFunctionInfo]],
    config: TreeSitterAstConfig,
) -> TreeSitterFunctionInfo | None:
    fn_node = nearest_enclosing(anchor_node, parent_map, config.function_node_types)
    if fn_node is not None:
        start = node_line(fn_node)
        end = node_end_line(fn_node)
        for variants in functions.values():
            for info in variants:
                if info.line_start == start and info.line_end == end:
                    return info
    best = None
    best_score = 1_000_000
    for variants in functions.values():
        for info in variants:
            if info.line_start <= request_line <= info.line_end:
                score = 0
            else:
                score = min(
                    abs(info.line_start - request_line),
                    abs(info.line_end - request_line),
                )
            if score < best_score:
                best = info
                best_score = score
    return best


def select_wanted_symbols(
    *,
    definitions: dict[str, list[TreeSitterDefinition]],
    references: dict[str, list[TreeSitterReference]],
    calls: dict[str, list[TreeSitterReference]],
    request: AnalyzerRequest,
) -> list[str]:
    candidates = [
        derive_symbols_near_line(
            definitions,
            references,
            calls,
            line=request.line,
            limit=10,
        ),
        [s for s in request.candidate_symbols if s][:8],
        list(definitions.keys())[:6],
    ]
    for symbols in candidates:
        if symbols:
            return symbols
    return []


def derive_symbols_near_line(
    definitions: dict[str, list[TreeSitterDefinition]],
    references: dict[str, list[TreeSitterReference]],
    calls: dict[str, list[TreeSitterReference]],
    *,
    line: int,
    limit: int,
) -> list[str]:
    scores: dict[str, int] = {}

    def update(symbol: str, distance: int, weight: int):
        if not symbol:
            return
        score = max(0, 200 - min(distance, 200)) + weight
        prev = scores.get(symbol)
        if prev is None or score > prev:
            scores[symbol] = score

    for symbol, items in calls.items():
        for item in items[:8]:
            update(symbol, abs(item.line - line), 40)
    for symbol, items in definitions.items():
        for item in items[:8]:
            update(symbol, abs(item.line - line), 25)
    for symbol, items in references.items():
        for item in items[:8]:
            update(symbol, abs(item.line - line), 10)

    ordered = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    return [symbol for symbol, _ in ordered[:limit]]


def collect_functions(
    root,
    source: bytes,
    config: TreeSitterAstConfig,
    parent_map: dict[int, Any | None],
) -> dict[str, list[TreeSitterFunctionInfo]]:
    out: dict[str, list[TreeSitterFunctionInfo]] = {}
    for node in walk_tree(root):
        if node_type(node) not in config.function_node_types:
            continue
        name = function_name(node, parent_map, source, config)
        if not is_probable_symbol(name):
            continue
        info = TreeSitterFunctionInfo(
            name=name,
            line_start=node_line(node),
            line_end=node_end_line(node),
            node=node,
            calls=collect_calls_in_scope(node, source, config),
            checks=collect_guard_hops(node, source, config, node_line(node)),
        )
        out.setdefault(name, []).append(info)
    for name in list(out.keys()):
        out[name] = sorted(out[name], key=lambda f: (f.line_start, f.line_end))
    return out


def collect_definitions(
    root,
    source: bytes,
    config: TreeSitterAstConfig,
    parent_map: dict[int, Any | None],
) -> dict[str, list[TreeSitterDefinition]]:
    out: dict[str, list[TreeSitterDefinition]] = {}

    def add(symbol: str, line: int):
        if not is_probable_symbol(symbol):
            return
        out.setdefault(symbol, []).append(
            TreeSitterDefinition(symbol=symbol, line=line)
        )

    for node in walk_tree(root):
        if node_type(node) not in config.definition_node_types:
            continue
        if node_type(node) in config.function_node_types:
            add(function_name(node, parent_map, source, config), node_line(node))
            continue
        add(identifier_text(node, source, config), node_line(node))

    for symbol in list(out.keys()):
        out[symbol] = sorted(out[symbol], key=lambda item: item.line)
    return out


def collect_references(
    root, source: bytes, config: TreeSitterAstConfig
) -> dict[str, list[TreeSitterReference]]:
    out: dict[str, list[TreeSitterReference]] = {}
    for node in walk_tree(root):
        if node_type(node) not in config.reference_node_types:
            continue
        symbol = identifier_text(node, source, config)
        if not is_probable_symbol(symbol):
            continue
        out.setdefault(symbol, []).append(
            TreeSitterReference(symbol=symbol, line=node_line(node))
        )
    for symbol in list(out.keys()):
        out[symbol] = sorted(out[symbol], key=lambda item: item.line)
    return out


def collect_calls(
    root, source: bytes, config: TreeSitterAstConfig
) -> dict[str, list[TreeSitterReference]]:
    out: dict[str, list[TreeSitterReference]] = {}
    for ref in collect_calls_in_scope(root, source, config):
        out.setdefault(ref.symbol, []).append(ref)
    for symbol in list(out.keys()):
        out[symbol] = sorted(out[symbol], key=lambda item: item.line)
    return out


def collect_calls_in_scope(
    scope_node, source: bytes, config: TreeSitterAstConfig
) -> list[TreeSitterReference]:
    out: list[TreeSitterReference] = []
    if scope_node is None:
        return out
    for node in walk_tree(scope_node):
        if node_type(node) not in config.call_node_types:
            continue
        symbol = call_name(node, source, config)
        if not is_probable_symbol(symbol):
            continue
        out.append(TreeSitterReference(symbol=symbol, line=node_line(node)))
    out.sort(key=lambda item: (item.line, item.symbol.lower()))
    return out


def collect_guard_hops(
    scope_node,
    source: bytes,
    config: TreeSitterAstConfig,
    line: int,
) -> list[TreeSitterFlowHop]:
    guards: list[TreeSitterFlowHop] = []
    if scope_node is None:
        return guards
    for node in walk_tree(scope_node):
        if node_type(node) not in config.check_node_types:
            continue
        condition = None
        for field in config.condition_fields:
            condition = child_by_field(node, field)
            if condition is not None:
                break
        detail = identifier_text(condition or node, source, config) or node_type(node)
        guards.append(
            TreeSitterFlowHop(
                role="check",
                line=node_line(node),
                detail=f"guard '{detail}'",
            )
        )
    guards.sort(key=lambda h: (abs(h.line - line), h.line))
    return guards[:4]


def nearest_enclosing(
    node, parent_map: dict[int, Any | None], types: frozenset[str]
):
    cur = node
    while cur is not None:
        if node_type(cur) in types:
            return cur
        cur = parent_map.get(id(cur))
    return None


def walk_tree(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        children = list(getattr(current, "children", []) or [])
        stack.extend(reversed(children))


def function_name(
    node,
    parent_map: dict[int, Any | None],
    source: bytes,
    config: TreeSitterAstConfig,
) -> str:
    for field_name in config.name_fields:
        found = identifier_text(child_by_field(node, field_name), source, config)
        if found:
            return found

    parent = parent_map.get(id(node))
    if node_type(node) in {"arrow_function", "function", "closure_expression"}:
        found = identifier_text(parent, source, config)
        if found:
            return found

    found = identifier_text(node, source, config)
    if found:
        return found
    if parent is not None:
        return identifier_text(parent, source, config)
    return ""


def call_name(node, source: bytes, config: TreeSitterAstConfig) -> str:
    for field_name in config.call_name_fields:
        found = identifier_text(child_by_field(node, field_name), source, config)
        if found:
            return found
    return identifier_text(node, source, config)


def identifier_text(node, source: bytes, config: TreeSitterAstConfig) -> str:
    if node is None:
        return ""
    current_type = node_type(node)
    if current_type in {
        "attribute",
        "member_expression",
        "selector_expression",
        "field_expression",
        "qualified_identifier",
        "scoped_identifier",
    }:
        for field_name in ("attribute", "property", "field", "name", "member"):
            found = identifier_text(child_by_field(node, field_name), source, config)
            if found:
                return found
        identifiers = [
            node_text(child, source).strip()
            for child in walk_tree(node)
            if node_type(child) in config.identifier_node_types
        ]
        if identifiers:
            return clean_symbol_tail(identifiers[-1])

    if current_type in config.identifier_node_types:
        return clean_symbol_tail(node_text(node, source).strip())

    for child in getattr(node, "children", []) or []:
        found = identifier_text(child, source, config)
        if found:
            return found

    direct = node_text(node, source).strip()
    if direct and "\n" not in direct and len(direct) <= 120:
        return clean_symbol_tail(direct.split("(", 1)[0].strip())
    return ""


def read_signature(function_node, source: bytes) -> str:
    text = node_text(function_node, source).strip()
    if not text:
        return ""
    first = text.split("{", 1)[0].strip()
    first = " ".join(first.split())
    return first[:160]


def child_by_field(node, field_name: str):
    if node is None or not field_name:
        return None
    try:
        return node.child_by_field_name(field_name)
    except Exception:
        return None


def node_text(node, source: bytes) -> str:
    if node is None:
        return ""
    start = int(getattr(node, "start_byte", 0) or 0)
    end = int(getattr(node, "end_byte", 0) or 0)
    if end > start:
        try:
            return source[start:end].decode("utf-8", errors="ignore")
        except Exception:
            return ""
    text = getattr(node, "text", "")
    if isinstance(text, bytes):
        return text.decode("utf-8", errors="ignore")
    return str(text or "")


def node_line(node: Any) -> int:
    return _point_row(getattr(node, "start_point", (0, 0))) + 1


def node_end_line(node: Any) -> int:
    end = getattr(node, "end_point", None)
    if end is not None:
        return _point_row(end) + 1
    return node_line(node)


def node_type(node) -> str:
    return str(getattr(node, "type", "") or "")


def _point_row(point) -> int:
    row = getattr(point, "row", None)
    if row is not None:
        return int(row)
    try:
        return int(point[0])
    except Exception:
        return 0


def clean_symbol_tail(value: str) -> str:
    text = str(value or "").strip()
    text = text.split(".")[-1].split("::")[-1].strip()
    text = text.strip("{}()[];,:")
    return text


def is_probable_symbol(symbol: str) -> bool:
    text = str(symbol or "").strip()
    if not text:
        return False
    if text[0] in "{}()[];,:.":
        return False
    return any(character.isalnum() or character in "_$" for character in text)


def is_actionable_symbol(symbol: str) -> bool:
    text = str(symbol or "").strip()
    if not text:
        return False
    if not re.match(r"^[A-Za-z_$][A-Za-z0-9_$]{1,127}$", text):
        return False
    if text.startswith("__"):
        return False
    if text.isupper():
        return False
    if "_" in text and text.upper() == text:
        return False
    return True


def dedup_keep_order(values: list[str]) -> list[str]:
    out: list[str] = []
    seen = set()
    for item in values:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _items(*values) -> list[str]:
    out: list[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            raw_items = [value]
        elif isinstance(value, Mapping):
            raw_items = value.values()
        else:
            try:
                raw_items = list(value)
            except TypeError:
                raw_items = [value]
        for raw in raw_items:
            if raw is None:
                continue
            if isinstance(raw, (list, tuple, set, frozenset)):
                nested = raw
            else:
                nested = [raw]
            for item in nested:
                text = str(item or "").strip()
                if text and text not in out:
                    out.append(text)
    return out
