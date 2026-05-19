# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from .base import AnalyzerRequest
from .treesitter_ast import (
    TreeSitterAstConfig,
    TreeSitterAstIndex,
    TreeSitterFlowHop,
    TreeSitterFunctionInfo,
    collect_calls_in_scope,
    find_anchor_node,
    is_actionable_symbol,
    read_signature,
    select_anchor_function,
)


def build_common_flow_chain(
    *,
    request: AnalyzerRequest,
    ast: TreeSitterAstIndex,
    config: TreeSitterAstConfig,
    max_hops: int,
    max_depth: int,
) -> tuple[list[TreeSitterFlowHop], list[str], list[str], list[str]]:
    unresolved: list[str] = []
    fallback_targets: list[str] = []
    hops: list[TreeSitterFlowHop] = []
    packet_sections: list[str] = []

    anchor = find_anchor_node(ast.node_index, request.line)
    if anchor is None:
        return [], ["FLOW_ANCHOR_NOT_FOUND"], [], []

    anchor_fn = select_anchor_function(
        request_line=request.line,
        anchor_node=anchor,
        parent_map=ast.parent_map,
        functions=ast.functions,
        config=config,
    )

    if anchor_fn is None:
        packet_sections.append("path.anchor: <none>")
        unresolved.append("FLOW_ENCLOSING_FUNCTION_UNRESOLVED")
        anchor_calls = collect_calls_in_scope(ast.root, ast.source, config)[:6]
        hops.append(
            TreeSitterFlowHop(
                role="source",
                line=request.line,
                detail="reported context outside resolvable function scope",
            )
        )
        if anchor_calls:
            first = anchor_calls[0]
            hops.append(
                TreeSitterFlowHop(
                    role="unknown",
                    line=first.line,
                    detail=f"top-level call '{first.symbol}'",
                    symbol=first.symbol,
                )
            )
            unresolved.append(f"FLOW_SINK_CLASS_UNRESOLVED:{first.symbol}")
            if is_actionable_symbol(first.symbol):
                fallback_targets.append(first.symbol)
        else:
            unresolved.append("FLOW_SINK_NOT_FOUND")
        return hops[:max_hops], unresolved, fallback_targets, packet_sections

    packet_sections.append(
        f"path.anchor: {anchor_fn.name} [{anchor_fn.line_start}-{anchor_fn.line_end}]"
    )

    hops.append(
        TreeSitterFlowHop(
            role="source",
            line=request.line,
            detail=f"reported context in function '{anchor_fn.name}'",
            symbol=anchor_fn.name,
        )
    )

    near_checks = sorted(
        anchor_fn.checks,
        key=lambda item: (abs(item.line - request.line), item.line),
    )[:3]
    hops.extend(near_checks)

    callers = collect_callers(
        anchor_name=anchor_fn.name,
        functions=ast.functions,
        max_depth=max_depth,
    )
    if callers:
        packet_sections.append("path.callers: " + " -> ".join(callers[:4]))
        for idx, caller in enumerate(callers[:2]):
            hops.append(
                TreeSitterFlowHop(
                    role="source",
                    line=anchor_fn.line_start,
                    detail=f"upstream caller '{caller}' reaches '{anchor_fn.name}' (depth {idx + 1})",
                    symbol=caller,
                )
            )

    endpoint_found = False
    visited: set[tuple[str, int]] = set()
    queue: list[tuple[TreeSitterFunctionInfo, int]] = [(anchor_fn, 0)]
    callee_path_parts: list[str] = [anchor_fn.name]
    while queue and len(hops) < max_hops:
        fn, depth = queue.pop(0)
        state_key = (fn.name, fn.line_start)
        if state_key in visited:
            continue
        visited.add(state_key)

        for call in fn.calls[:12]:
            if len(hops) >= max_hops:
                break
            hops.append(
                TreeSitterFlowHop(
                    role="unknown",
                    line=call.line,
                    detail=f"{fn.name} calls '{call.symbol}'",
                    symbol=call.symbol,
                )
            )
            endpoint_found = True
            if not callee_path_parts or callee_path_parts[-1] != call.symbol:
                callee_path_parts.append(call.symbol)

            if not is_actionable_symbol(call.symbol):
                continue
            variants = ast.functions.get(call.symbol, [])
            if variants and depth < max_depth:
                next_fn = variants[0]
                queue.append((next_fn, depth + 1))
            else:
                unresolved.append(f"FLOW_EXTERNAL_CALLEE_UNRESOLVED:{call.symbol}")
                fallback_targets.append(call.symbol)

    if len(callee_path_parts) > 1:
        packet_sections.append("path.callees: " + " -> ".join(callee_path_parts[:8]))
    if not endpoint_found:
        unresolved.append("FLOW_SINK_NOT_FOUND")
    if len(hops) >= max_hops and queue:
        unresolved.append("FLOW_CHAIN_TRUNCATED_BY_BOUND")

    for fn_name in callee_path_parts[1:4]:
        fn_variants = ast.functions.get(fn_name, [])
        if not fn_variants:
            continue
        fn = fn_variants[0]
        packet_sections.append(
            f"path.hop: {fn.name} [{fn.line_start}-{fn.line_end}] sig='{read_signature(fn.node, ast.source)}'"
        )

    return hops[:max_hops], unresolved, fallback_targets, packet_sections[:8]


def collect_callers(
    *,
    anchor_name: str,
    functions: dict[str, list[TreeSitterFunctionInfo]],
    max_depth: int,
) -> list[str]:
    reverse: dict[str, set[str]] = {}
    for caller, variants in functions.items():
        for info in variants:
            for ref in info.calls:
                if not is_actionable_symbol(ref.symbol):
                    continue
                reverse.setdefault(ref.symbol, set()).add(caller)

    out: list[str] = []
    seen = set()
    frontier = [(anchor_name, 0)]
    while frontier:
        symbol, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for caller in sorted(reverse.get(symbol, set()), key=lambda s: s.lower()):
            if caller in seen:
                continue
            seen.add(caller)
            out.append(caller)
            frontier.append((caller, depth + 1))
            if len(out) >= 8:
                return out
    return out
