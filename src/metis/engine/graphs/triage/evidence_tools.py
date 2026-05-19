# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import TimeoutError as FutureTimeout
import os
import re
import threading
import time
from typing import Any

from metis.engine.analysis.c_family_macro import (
    collect_c_macro_definition_sections,
    collect_c_macro_like_calls_from_scope,
    is_c_family_file_path,
)

from . import constants as C
from .debug import _emit_debug
from ..types import TriageState
from .evidence_text import (
    _assignment_pattern,
    _extend_hits,
    _call_pattern,
    _limit_output,
    _parse_grep_hits,
    _token_pattern,
)

_TERMINAL_WRAPPER_TARGETS = {
    "alloca",
    "calloc",
    "free",
    "malloc",
    "memcpy",
    "memmove",
    "realloc",
    "strcat",
    "strcpy",
    "strncat",
    "strncpy",
}


def _safe_tool_capture(
    state: TriageState,
    sections: list[str],
    *,
    tool_name: str,
    tool_args: dict,
    section_label: str | None = None,
    error_label: str | None = None,
    max_lines: int = C.DEFAULT_CAPTURE_MAX_LINES,
    max_chars: int = C.DEFAULT_CAPTURE_MAX_CHARS,
    append_error_section: bool = False,
    emit_debug: bool = True,
    invoke,
) -> str | None:
    if _triage_evidence_deadline_exceeded(state):
        if append_error_section and error_label:
            sections.append(f"[{error_label}]\ntriage evidence deadline exceeded")
        if emit_debug:
            _emit_debug(
                state,
                "tool_call",
                tool_name=tool_name,
                tool_args=tool_args,
                tool_output="Tool execution skipped: triage evidence deadline exceeded",
            )
        return None
    try:
        output = _invoke_with_deadline(state, invoke)
    except Exception as exc:
        if append_error_section and error_label:
            sections.append(f"[{error_label}]\n{exc}")
        if emit_debug:
            _emit_debug(
                state,
                "tool_call",
                tool_name=tool_name,
                tool_args=tool_args,
                tool_output=f"Tool execution failed: {exc}",
            )
        return None

    if output is None:
        return None

    clipped = _limit_output(output, max_lines=max_lines, max_chars=max_chars)
    if section_label:
        sections.append(f"[{section_label}]\n{clipped}")
    if emit_debug:
        _emit_debug(
            state,
            "tool_call",
            tool_name=tool_name,
            tool_args=tool_args,
            tool_output=clipped,
        )
    return output


def _invoke_with_deadline(
    state: TriageState, invoke: Callable[[], str | None]
) -> str | None:
    deadline = float(state.get("triage_evidence_deadline_at", 0.0) or 0.0)
    if deadline <= 0:
        return invoke()

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("triage evidence deadline exceeded")

    executor = state.get("triage_tool_executor")
    submit = getattr(executor, "submit", None)
    if not callable(submit):
        return invoke()

    if _running_in_executor_thread(executor):
        return invoke()

    future = submit(invoke)
    try:
        return future.result(timeout=remaining)
    except FutureTimeout as exc:
        future.cancel()
        raise TimeoutError("triage evidence deadline exceeded") from exc


def _running_in_executor_thread(executor: Any) -> bool:
    # ThreadPoolExecutor has no public worker-membership API; keep this guard isolated.
    current_thread = threading.current_thread()
    try:
        if current_thread in getattr(executor, "_threads", set()):
            return True
    except TypeError:
        pass
    thread_name_prefix = str(getattr(executor, "_thread_name_prefix", "") or "")
    return bool(
        thread_name_prefix and current_thread.name.startswith(thread_name_prefix)
    )


def _triage_evidence_deadline_exceeded(state: TriageState) -> bool:
    deadline = float(state.get("triage_evidence_deadline_at", 0.0) or 0.0)
    if deadline <= 0:
        return False
    return time.monotonic() > deadline


def _tool_debug_args(toolbox, tool_name: str, **tool_args) -> dict:
    out = dict(tool_args)
    describe = getattr(toolbox, "describe", None)
    if not callable(describe):
        return out
    try:
        details = describe(tool_name)
    except Exception:
        return out
    if not isinstance(details, dict):
        return out
    for key, value in details.items():
        out.setdefault(key, value)
    return out


def _collect_file_context(
    state: TriageState,
    sections: list[str],
    *,
    toolbox,
    file_path: str,
    line: int,
    window_radius: int,
) -> str:
    exact_line_context = ""

    if not file_path:
        return exact_line_context

    radius = max(1, int(window_radius or 1))
    start = max(1, line - radius)
    end = line + radius
    _safe_tool_capture(
        state,
        sections,
        tool_name="sed",
        tool_args=_tool_debug_args(
            toolbox,
            "sed",
            path=file_path,
            start_line=start,
            end_line=end,
        ),
        section_label=f"FILE_WINDOW {file_path}:{start}-{end}",
        error_label="FILE_WINDOW_ERROR",
        max_lines=C.DEFAULT_CAPTURE_MAX_LINES,
        max_chars=C.DEFAULT_CAPTURE_MAX_CHARS,
        append_error_section=True,
        invoke=lambda: toolbox.sed(file_path, start, end),
    )
    exact = _safe_tool_capture(
        state,
        sections,
        tool_name="sed",
        tool_args=_tool_debug_args(
            toolbox,
            "sed",
            path=file_path,
            start_line=line,
            end_line=line,
        ),
        section_label=f"REPORTED_LINE {file_path}:{line}",
        error_label="REPORTED_LINE_ERROR",
        max_lines=C.REPORTED_LINE_MAX_LINES,
        max_chars=C.REPORTED_LINE_MAX_CHARS,
        append_error_section=True,
        invoke=lambda: toolbox.sed(file_path, line, line),
    )
    if exact:
        exact_line_context = exact

    return exact_line_context


def _collect_treesitter_scope_symbols(
    state: TriageState,
    sections: list[str],
    *,
    file_path: str,
    line: int,
    max_symbols: int,
) -> tuple[list[str], list[str]]:
    analyzer = state.get("triage_analyzer")
    if analyzer is None:
        return [], []
    runtime = getattr(analyzer, "runtime", None)
    if runtime is None or not bool(getattr(runtime, "is_available", False)):
        sections.append("[TREE_SITTER_SCOPE]\nunavailable")
        return [], []
    supports_file = getattr(analyzer, "supports_file", None)
    if callable(supports_file):
        try:
            if not supports_file(file_path):
                sections.append("[TREE_SITTER_SCOPE]\nunsupported_file")
                return [], []
        except Exception:
            return [], []
    try:
        parsed = runtime.parse_file(
            state.get("triage_codebase_path", ".") or ".", file_path
        )
    except Exception as exc:
        sections.append(f"[TREE_SITTER_SCOPE]\nparse_failed: {exc}")
        return [], []

    source = bytes(parsed.text, "utf-8")
    root = parsed.tree.root_node
    nodes: list[Any] = []
    parent_map: dict[int, Any | None] = {}

    def _walk(node: Any, parent: Any | None) -> None:
        nodes.append(node)
        parent_map[id(node)] = parent
        for child in getattr(node, "children", []) or []:
            _walk(child, node)

    _walk(root, None)
    anchor = _find_anchor_node(nodes, line=line)
    if anchor is None:
        sections.append("[TREE_SITTER_SCOPE]\nanchor_not_found")
        return [], []
    scope = _nearest_enclosing_scope(anchor, parent_map)
    if scope is None:
        scope = anchor

    scope_start = int(getattr(scope, "start_point", (0, 0))[0]) + 1
    scope_end = int(getattr(scope, "end_point", (0, 0))[0]) + 1
    sections.append(
        f"[TREE_SITTER_SCOPE {file_path}:{scope_start}-{scope_end}]\ntype={getattr(scope, 'type', '')}"
    )

    line_symbols = _collect_identifier_symbols(
        anchor, source, max_symbols=max_symbols * 2
    )
    upward_symbols = _collect_identifier_symbols_until_line(
        scope,
        source,
        line=line,
        max_symbols=max_symbols * 4,
    )
    merged: list[str] = []
    seen: set[str] = set()
    for symbol in line_symbols + upward_symbols:
        if not symbol or symbol in seen:
            continue
        seen.add(symbol)
        merged.append(symbol)
        if len(merged) >= max_symbols:
            break
    macros: list[str] = []
    if is_c_family_file_path(file_path):
        macros = collect_c_macro_like_calls_from_scope(
            scope,
            source,
            max_macros=max_symbols,
            collect_identifier_symbols=_collect_identifier_symbols,
        )
    if merged:
        sections.append("[TREE_SITTER_SCOPE_SYMBOLS]\n" + ", ".join(merged))
    if macros:
        sections.append("[TREE_SITTER_MACROS]\n" + ", ".join(macros))
    return merged, macros


def _find_anchor_node(nodes: list[Any], *, line: int) -> Any | None:
    best = None
    best_score = 1_000_000
    best_span = 1_000_000
    for node in nodes:
        start = int(getattr(node, "start_point", (0, 0))[0]) + 1
        end = int(getattr(node, "end_point", (0, 0))[0]) + 1
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


def _nearest_enclosing_scope(
    node: Any, parent_map: dict[int, Any | None]
) -> Any | None:
    scope_types = {
        "function_definition",
        "method_definition",
        "function_declaration",
        "compound_statement",
        "block",
        "if_statement",
        "while_statement",
        "for_statement",
        "switch_statement",
    }
    cur = node
    while cur is not None:
        if str(getattr(cur, "type", "") or "") in scope_types:
            return cur
        cur = parent_map.get(id(cur))
    return None


def _collect_identifier_symbols(
    node: Any, source: bytes, *, max_symbols: int
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def _walk(cur: Any) -> None:
        nonlocal out
        if len(out) >= max_symbols:
            return
        node_type = str(getattr(cur, "type", "") or "")
        if node_type in {"identifier", "field_identifier"}:
            text = _node_text(cur, source).strip()
            if _is_symbol_like(text) and text not in seen:
                seen.add(text)
                out.append(text)
        for child in getattr(cur, "children", []) or []:
            _walk(child)

    _walk(node)
    return out


def _collect_identifier_symbols_until_line(
    node: Any,
    source: bytes,
    *,
    line: int,
    max_symbols: int,
) -> list[str]:
    scored: dict[str, int] = {}

    def _walk(cur: Any) -> None:
        start = int(getattr(cur, "start_point", (0, 0))[0]) + 1
        if start > line:
            return
        node_type = str(getattr(cur, "type", "") or "")
        if node_type in {"identifier", "field_identifier"}:
            text = _node_text(cur, source).strip()
            if _is_symbol_like(text):
                distance = abs(line - start)
                score = max(0, 1000 - min(distance, 1000))
                prev = scored.get(text)
                if prev is None or score > prev:
                    scored[text] = score
        for child in getattr(cur, "children", []) or []:
            _walk(child)

    _walk(node)
    ordered = sorted(scored.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    return [symbol for symbol, _ in ordered[:max_symbols]]


def _node_text(node: Any, source: bytes) -> str:
    start = int(getattr(node, "start_byte", 0) or 0)
    end = int(getattr(node, "end_byte", 0) or 0)
    try:
        return source[start:end].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _is_symbol_like(text: str) -> bool:
    value = str(text or "").strip()
    if not value:
        return False
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{1,127}$", value):
        return False
    return True


def _collect_macro_definition_sections(
    state: TriageState,
    sections: list[str],
    *,
    toolbox,
    file_path: str,
    macro_names: list[str],
    max_sections: int,
) -> tuple[list[str], dict[str, str]]:
    if not is_c_family_file_path(file_path) or not macro_names:
        return [], {}

    def _dispatch_invoke(invoke):
        op = invoke()
        if not isinstance(op, tuple) or not op:
            return None
        kind = op[0]
        if kind == "grep" and len(op) == 3:
            _, path, pattern = op
            return toolbox.grep(pattern, path)
        if kind == "sed" and len(op) == 4:
            _, path, start, end = op
            return toolbox.sed(path, start, end)
        return None

    def _safe_capture(
        *,
        tool_name: str,
        tool_args: dict,
        section_label: str | None = None,
        max_lines: int = C.DEFAULT_CAPTURE_MAX_LINES,
        max_chars: int = C.DEFAULT_CAPTURE_MAX_CHARS,
        append_error_section: bool = False,
        invoke,
    ) -> str | None:
        return _safe_tool_capture(
            state,
            sections,
            tool_name=tool_name,
            tool_args=_tool_debug_args(toolbox, tool_name, **tool_args),
            section_label=section_label,
            max_lines=max_lines,
            max_chars=max_chars,
            append_error_section=append_error_section,
            invoke=lambda: _dispatch_invoke(invoke),
        )

    return collect_c_macro_definition_sections(
        sections=sections,
        file_path=file_path,
        macro_names=macro_names,
        max_sections=max_sections,
        max_citations=C.MAX_CITATIONS,
        related_grep_max_lines=C.RELATED_GREP_MAX_LINES,
        related_grep_max_chars=C.RELATED_GREP_MAX_CHARS,
        max_targeted_hits=C.MAX_TARGETED_HITS,
        max_targeted_context_hits=C.MAX_TARGETED_CONTEXT_HITS,
        targeted_hit_radius=C.TARGETED_HIT_RADIUS,
        targeted_hit_context_max_lines=C.TARGETED_HIT_CONTEXT_MAX_LINES,
        targeted_hit_context_max_chars=C.TARGETED_HIT_CONTEXT_MAX_CHARS,
        safe_tool_capture=_safe_capture,
        parse_grep_hits=_parse_grep_hits,
        find_name_paths=lambda name: toolbox.find_name(
            name,
            max_results=C.FIND_NAME_MAX_RESULTS,
        ),
        root_probe_path=".",
    )


def _build_fallback_paths(file_path: str, global_scope: str = ".") -> list[str]:
    fallback_paths: list[str] = []
    if file_path:
        file_dir = os.path.dirname(file_path)
        if file_dir:
            fallback_paths.append(file_dir)
        top = file_path.split("/", 1)[0]
        if top and top not in fallback_paths:
            fallback_paths.append(top)
    if not fallback_paths:
        fallback_paths = [global_scope]
    return sorted(set(fallback_paths), key=lambda p: p.lower())


def _gather_symbol_definition_hits(
    state: TriageState,
    sections: list[str],
    *,
    toolbox,
    symbols: list[str],
    file_path: str,
    max_followup_hits: int,
    max_sections: int,
    max_symbol_hops: int = 1,
    scope_mode: str = "line_local",
) -> tuple[list[tuple[str, int]], set[str], list[str]]:
    followup_hits: list[tuple[str, int]] = []
    definition_hints: set[str] = set()
    resolved: set[str] = set()
    wrapper_chains_recorded: set[str] = set()

    if not symbols:
        return followup_hits, definition_hints, []

    line_local = str(scope_mode or "").strip().lower() == "line_local"
    fallback_paths = (
        [file_path] if line_local and file_path else _build_fallback_paths(file_path)
    )
    local_path = (
        file_path if file_path else (fallback_paths[0] if fallback_paths else ".")
    )
    fallback_paths = [path for path in fallback_paths if path != local_path]

    def _read_hit_context(path: str, line: int) -> tuple[str, int]:
        start = max(1, line - C.HIT_CONTEXT_RADIUS)
        end = line + C.HIT_CONTEXT_RADIUS
        output = _safe_tool_capture(
            state,
            sections,
            tool_name="sed",
            tool_args=_tool_debug_args(
                toolbox,
                "sed",
                path=path,
                start_line=start,
                end_line=end,
            ),
            max_lines=C.HIT_CONTEXT_MAX_LINES,
            max_chars=C.HIT_CONTEXT_MAX_CHARS,
            append_error_section=False,
            emit_debug=True,
            invoke=lambda p=path, s=start, e=end: toolbox.sed(p, s, e),
        )
        return output or "", start

    def _resolve_symbol_once(symbol: str) -> tuple[tuple[str, int], str] | None:
        start_index = len(followup_hits)
        if _probe_symbol(
            symbol,
            local_path,
            "wrapper-local",
            follow_wrappers=False,
        ):
            hit = _first_wrapper_definition_hit(symbol, followup_hits[start_index:])
            if hit is not None:
                return hit
        for path in fallback_paths:
            start_index = len(followup_hits)
            if _probe_symbol(
                symbol,
                path,
                "wrapper-fallback",
                follow_wrappers=False,
            ):
                hit = _first_wrapper_definition_hit(symbol, followup_hits[start_index:])
                if hit is not None:
                    return hit
        return None

    def _first_wrapper_definition_hit(
        symbol: str, hits: list[tuple[str, int]]
    ) -> tuple[tuple[str, int], str] | None:
        for hit_path, hit_line in hits:
            if not hit_path:
                continue
            context, context_start = _read_hit_context(hit_path, hit_line)
            definition = _extract_thin_wrapper_definition(
                symbol, context, context_start
            )
            if definition is not None:
                definition_line, _target = definition
                return (hit_path, definition_line), context
        return None

    def _record_wrapper_chain(symbol: str, parsed: list[tuple[str, int]]) -> None:
        if max_symbol_hops <= 1 or not parsed or len(sections) >= max_sections:
            return
        if symbol in wrapper_chains_recorded:
            return
        seed: tuple[str, int] | None = None
        seed_context = ""
        for candidate_path, candidate_line in parsed:
            context, context_start = _read_hit_context(candidate_path, candidate_line)
            definition = _extract_thin_wrapper_definition(
                symbol, context, context_start
            )
            if definition is not None:
                definition_line, _target = definition
                seed = (candidate_path, definition_line)
                seed_context = context
                break
        if seed is None:
            return
        chain: list[tuple[str, str, int | None]] = [(symbol, seed[0], seed[1])]
        seen_symbols = {symbol}
        current_symbol = symbol
        current_path, current_line = seed

        for _hop in range(1, max(1, max_symbol_hops)):
            if seed_context:
                context = seed_context
            else:
                context, _context_start = _read_hit_context(current_path, current_line)
            seed_context = ""
            target = _extract_thin_wrapper_target(current_symbol, context)
            if not target or target in seen_symbols:
                break
            seen_symbols.add(target)
            resolved_hit = _resolve_symbol_once(target)
            if resolved_hit is None:
                if _is_terminal_wrapper_target(target):
                    chain.append((target, "<terminal>", None))
                    break
                chain.append((target, "<unresolved>", None))
                break
            hit, seed_context = resolved_hit
            current_symbol = target
            current_path, current_line = hit
            chain.append((target, current_path, current_line))

        if len(chain) <= 1 or len(sections) >= max_sections:
            return

        wrapper_chains_recorded.add(symbol)
        _append_structured_wrapper_chain(state, symbol=symbol, chain=chain)
        lines = [
            f"{name} @ {path}:{line}" if line is not None else f"{name} @ {path}"
            for name, path, line in chain
        ]
        sections.append(f"[SYMBOL_RESOLUTION_CHAIN {symbol}]\n" + "\n".join(lines))
        definition_hints.add(
            " -> ".join(
                f"{name} @ {path}:{line}" if line is not None else f"{name} @ {path}"
                for name, path, line in chain
            )
        )

    def _probe_symbol(
        symbol: str,
        path: str,
        mode: str,
        *,
        follow_wrappers: bool = True,
    ) -> bool:
        if len(sections) >= max_sections or len(followup_hits) >= max_followup_hits:
            return False
        hit_found = False
        probes = (
            _token_pattern(symbol),
            _call_pattern(symbol),
            _assignment_pattern(symbol),
        )
        for probe in probes:
            if len(sections) >= max_sections or len(followup_hits) >= max_followup_hits:
                break
            output = _safe_tool_capture(
                state,
                sections,
                tool_name="grep",
                tool_args=_tool_debug_args(
                    toolbox,
                    "grep",
                    pattern=probe,
                    path=path,
                    mode=mode,
                ),
                section_label=f"SYMBOL_GREP {symbol} IN {path} ({mode})",
                max_lines=C.RELATED_GREP_MAX_LINES,
                max_chars=C.RELATED_GREP_MAX_CHARS,
                append_error_section=False,
                invoke=lambda p=path, q=probe: toolbox.grep(q, p),
            )
            if output is None:
                continue
            parsed = _parse_grep_hits(output)
            if parsed:
                hit_found = True
                _extend_hits(followup_hits, parsed, max_total=max_followup_hits)
                if follow_wrappers:
                    _record_wrapper_chain(symbol, parsed)
        return hit_found

    unresolved: list[str] = []
    for symbol in symbols:
        if len(sections) >= max_sections:
            break
        if _probe_symbol(symbol, local_path, "local"):
            resolved.add(symbol)
        else:
            unresolved.append(symbol)

    unresolved_remaining: list[str] = []
    for symbol in unresolved:
        if len(sections) >= max_sections:
            unresolved_remaining.append(symbol)
            continue
        found = False
        for path in fallback_paths:
            if len(sections) >= max_sections:
                break
            if _probe_symbol(symbol, path, "fallback"):
                resolved.add(symbol)
                found = True
                break
        if not found:
            unresolved_remaining.append(symbol)

    return followup_hits, definition_hints, unresolved_remaining


def _append_structured_wrapper_chain(
    state: TriageState,
    *,
    symbol: str,
    chain: list[tuple[str, str, int | None]],
) -> None:
    existing = list(state.get("symbol_resolution_chains") or [])
    entry = {
        "symbol": symbol,
        "resolution_chain": [
            {"symbol": name, "file": path, "line": line} for name, path, line in chain
        ],
    }
    existing.append(entry)
    state["symbol_resolution_chains"] = existing


def _extract_thin_wrapper_target(symbol: str, context: str) -> str | None:
    wrapper = str(symbol or "").strip()
    if not wrapper:
        return None
    text = context or ""
    definition = _extract_braced_wrapper_definition(wrapper, text, 1)
    if definition:
        return definition[1]
    definition = _extract_python_wrapper_definition(wrapper, text, 1)
    if definition:
        return definition[1]
    return None


def _extract_thin_wrapper_definition(
    symbol: str, context: str, start_line: int
) -> tuple[int, str] | None:
    wrapper = str(symbol or "").strip()
    if not wrapper:
        return None
    text = context or ""
    definition = _extract_braced_wrapper_definition(wrapper, text, start_line)
    if definition:
        return definition
    return _extract_python_wrapper_definition(wrapper, text, start_line)


def _is_terminal_wrapper_target(symbol: str) -> bool:
    return str(symbol or "").strip() in _TERMINAL_WRAPPER_TARGETS


def _extract_braced_wrapper_definition(
    symbol: str, text: str, start_line: int
) -> tuple[int, str] | None:
    match = re.search(
        rf"\b{re.escape(symbol)}\s*\([^)]*\)\s*\{{(?P<body>.*?)\}}",
        text or "",
        flags=re.DOTALL,
    )
    if not match:
        return None
    body = _strip_comments(match.group("body"))
    statements = [part.strip() for part in body.split(";") if part.strip()]
    if not statements or len(statements) > 2:
        return None
    calls = [
        name
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)
        if name != symbol
    ]
    unique_calls = list(dict.fromkeys(calls))
    if len(unique_calls) != 1:
        return None
    line = start_line + (text or "")[: match.start()].count("\n")
    return line, unique_calls[0]


def _extract_python_wrapper_definition(
    symbol: str, text: str, start_line: int
) -> tuple[int, str] | None:
    match = re.search(
        rf"def\s+{re.escape(symbol)}\s*\([^)]*\):(?P<body>.*?)(?:\ndef\s+|\nclass\s+|\Z)",
        text or "",
        flags=re.DOTALL,
    )
    if not match:
        return None
    body_lines = [
        line.strip()
        for line in match.group("body").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not body_lines or len(body_lines) > 2:
        return None
    calls = [
        name
        for name in re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", "\n".join(body_lines)
        )
        if name != symbol
    ]
    unique_calls = list(dict.fromkeys(calls))
    if len(unique_calls) != 1:
        return None
    line = start_line + (text or "")[: match.start()].count("\n")
    return line, unique_calls[0]


def _strip_comments(text: str) -> str:
    no_block = re.sub(r"/\*.*?\*/", "", text or "", flags=re.DOTALL)
    return re.sub(r"//.*", "", no_block)


def _collect_hit_context_sections(
    state: TriageState,
    sections: list[str],
    *,
    toolbox,
    followup_hits: list[tuple[str, int]],
    max_followup_hits: int,
    max_sections: int,
) -> None:
    seen_ctx: set[tuple[str, int]] = set()
    for path, hit_line in followup_hits:
        if len(sections) >= max_sections:
            break
        if (path, hit_line) in seen_ctx:
            continue
        seen_ctx.add((path, hit_line))
        if len(seen_ctx) > max_followup_hits:
            break
        start = max(1, hit_line - C.HIT_CONTEXT_RADIUS)
        end = hit_line + C.HIT_CONTEXT_RADIUS
        _safe_tool_capture(
            state,
            sections,
            tool_name="sed",
            tool_args=_tool_debug_args(
                toolbox,
                "sed",
                path=path,
                start_line=start,
                end_line=end,
            ),
            section_label=f"HIT_CONTEXT {path}:{start}-{end}",
            error_label=f"HIT_CONTEXT_ERROR {path}:{hit_line}",
            max_lines=C.HIT_CONTEXT_MAX_LINES,
            max_chars=C.HIT_CONTEXT_MAX_CHARS,
            append_error_section=True,
            invoke=lambda p=path, s=start, e=end: toolbox.sed(p, s, e),
        )
