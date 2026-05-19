# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re
from typing import Any

from .base import AnalyzerEvidence, AnalyzerRequest
from .flow_common import build_common_flow_chain
from .treesitter_ast import (
    collect_tree_sitter_ast,
    dedup_keep_order,
    is_actionable_symbol,
    normalize_analyzer_config,
    select_wanted_symbols,
)
from .treesitter_runtime import TreeSitterRuntime
from .xref_common import (
    compute_fallback_targets_from_unresolved,
    resolve_unresolved_hops_across_codebase,
)


class GenericTreeSitterAnalyzer:
    def __init__(
        self,
        *,
        codebase_path: str,
        language_name: str,
        supported_extensions: list[str],
        analyzer_config: dict[str, Any] | None = None,
    ):
        self.codebase_path = codebase_path
        self.language_name = language_name
        self.runtime = TreeSitterRuntime(language_name)
        self.supported_extensions = {str(ext).lower() for ext in supported_extensions}
        self.ast_config = normalize_analyzer_config(analyzer_config)

    def supports_file(self, rel_path: str) -> bool:
        ext = os.path.splitext(rel_path or "")[1].lower()
        return ext in self.supported_extensions

    def collect_evidence(self, request: AnalyzerRequest) -> AnalyzerEvidence:
        if not self.supports_file(request.file_path):
            return AnalyzerEvidence(
                supported=False,
                language=self.language_name,
                summary="Analyzer does not support this file extension.",
            )

        if not self.runtime.is_available:
            return AnalyzerEvidence(
                supported=False,
                language=self.language_name,
                summary="Tree-sitter runtime unavailable; falling back to text tools.",
                unresolved_hops=[f"TREE_SITTER_UNAVAILABLE:{self.language_name}"],
            )

        try:
            parsed = self.runtime.parse_file(request.codebase_path, request.file_path)
        except Exception as exc:
            return AnalyzerEvidence(
                supported=False,
                language=self.language_name,
                summary="Tree-sitter parse failed; falling back to text tools.",
                unresolved_hops=[f"TREE_SITTER_PARSE_FAILURE:{exc}"],
            )

        if not self.ast_config.function_node_types or not self.ast_config.call_node_types:
            return self._collect_window_evidence(request, parsed.text)

        source = bytes(parsed.text, "utf-8")
        root = parsed.tree.root_node
        ast = collect_tree_sitter_ast(root, source, self.ast_config)

        wanted = select_wanted_symbols(
            definitions=ast.definitions,
            references=ast.references,
            calls=ast.calls,
            request=request,
        )

        flow_hops, flow_unresolved, flow_fallback_targets, path_sections = (
            build_common_flow_chain(
                request=request,
                ast=ast,
                config=self.ast_config,
                max_hops=12,
                max_depth=3,
            )
        )

        citations: list[str] = []
        resolution_chain: list[str] = []
        unresolved_hops: list[str] = list(flow_unresolved)
        fallback_targets: list[str] = list(flow_fallback_targets)
        sections: list[str] = list(path_sections)
        flow_chain: list[str] = []

        for hop in flow_hops:
            citations.append(f"{request.file_path}:{hop.line}")
            flow_chain.append(
                f"{hop.role} at {request.file_path}:{hop.line} - {hop.detail}"
            )
            resolution_chain.append(
                f"{hop.role} hop resolved at {request.file_path}:{hop.line} ({hop.detail})"
            )

        for symbol in wanted:
            sym_defs = ast.definitions.get(symbol, [])
            sym_calls = ast.calls.get(symbol, [])
            sym_refs = ast.references.get(symbol, [])

            if sym_defs:
                definition = sym_defs[0]
                citations.append(f"{request.file_path}:{definition.line}")
                resolution_chain.append(
                    f"{symbol} definition resolved at {request.file_path}:{definition.line}"
                )
            else:
                unresolved_hops.append(f"SYMBOL_DEFINITION_UNRESOLVED:{symbol}")
                if is_actionable_symbol(symbol):
                    fallback_targets.append(symbol)

            if sym_calls:
                call = sym_calls[0]
                citations.append(f"{request.file_path}:{call.line}")
                resolution_chain.append(
                    f"{symbol} call/reference observed at {request.file_path}:{call.line}"
                )
            elif sym_refs and sym_defs:
                ref = sym_refs[0]
                citations.append(f"{request.file_path}:{ref.line}")
                resolution_chain.append(
                    f"{symbol} identifier usage observed at {request.file_path}:{ref.line}"
                )

            if sym_defs or sym_calls or sym_refs:
                parts = []
                if sym_defs:
                    parts.append(
                        "defs=" + ", ".join(str(item.line) for item in sym_defs[:3])
                    )
                if sym_calls:
                    parts.append(
                        "calls=" + ", ".join(str(item.line) for item in sym_calls[:3])
                    )
                if sym_refs:
                    parts.append(
                        "refs=" + ", ".join(str(item.line) for item in sym_refs[:3])
                    )
                sections.append(f"evidence.local.{symbol}: " + " | ".join(parts))

        unresolved_hops, xref_sections, xref_citations, xref_resolution = (
            resolve_unresolved_hops_across_codebase(
                unresolved_hops=unresolved_hops,
                codebase_path=request.codebase_path,
                file_path=request.file_path,
                top_symbol_hint=wanted[:6],
                supported_extensions=self.supported_extensions,
            )
        )
        sections.extend(xref_sections)
        citations.extend(xref_citations)
        resolution_chain.extend(xref_resolution)

        dedup_citations: list[str] = []
        seen = set()
        for citation in citations:
            if citation in seen:
                continue
            seen.add(citation)
            dedup_citations.append(citation)
            if len(dedup_citations) >= max(1, request.max_citations):
                break

        unresolved_hops = dedup_keep_order(unresolved_hops)[: request.max_citations]
        ast_seed_targets = [
            symbol for symbol in wanted if is_actionable_symbol(symbol)
        ]
        fallback_targets = compute_fallback_targets_from_unresolved(
            unresolved_hops=unresolved_hops,
            preferred_symbols=ast_seed_targets + fallback_targets,
            limit=request.max_citations,
        )

        if flow_chain:
            sections.insert(0, "evidence.flow_chain: " + " | ".join(flow_chain[:10]))

        matched_symbols = len(
            [s for s in wanted if s in ast.definitions or s in ast.calls]
        )
        summary = (
            f"Tree-sitter({self.language_name}) analyzed {request.file_path}; "
            f"functions={sum(len(v) for v in ast.functions.values())}; "
            f"matched {matched_symbols} symbol(s); flow_hops={len(flow_hops)}."
        )

        return AnalyzerEvidence(
            supported=True,
            language=self.language_name,
            summary=summary,
            citations=dedup_citations,
            resolution_chain=resolution_chain[: request.max_citations],
            flow_chain=flow_chain[: request.max_citations],
            unresolved_hops=unresolved_hops,
            fallback_targets=fallback_targets,
            sections=sections[:16],
        )

    def _collect_window_evidence(
        self, request: AnalyzerRequest, source_text: str
    ) -> AnalyzerEvidence:
        lines = source_text.splitlines()
        anchor = max(1, int(request.line or 1))
        lo = max(1, anchor - 12)
        hi = min(max(anchor + 12, lo), max(1, len(lines)))
        window = "\n".join(lines[lo - 1 : hi])

        call_names = self._extract_call_names(window)[:6]
        citations = [f"{request.file_path}:{anchor}"]
        flow_chain = [f"source at {request.file_path}:{anchor} - reported context"]
        resolution = [
            f"source hop resolved at {request.file_path}:{anchor} (reported context)"
        ]
        unresolved: list[str] = []

        if "if " in window or "if(" in window or "guard" in window.lower():
            flow_chain.append(
                f"check at {request.file_path}:{anchor} - local conditional context"
            )
            resolution.append(
                f"check hop resolved at {request.file_path}:{anchor} (local conditional context)"
            )

        if call_names:
            sink = call_names[0]
            role = "unknown"
            flow_chain.append(f"{role} at {request.file_path}:{anchor} - call '{sink}'")
            resolution.append(
                f"{role} hop resolved at {request.file_path}:{anchor} (call '{sink}')"
            )
            unresolved.append(f"FLOW_SINK_CLASS_UNRESOLVED:{sink}")
        else:
            unresolved.append("FLOW_SINK_NOT_FOUND")

        sections = []
        if call_names:
            sections.append("calls: " + ", ".join(call_names[:6]))
        sections.append("flow: " + " | ".join(flow_chain))

        return AnalyzerEvidence(
            supported=True,
            language=self.language_name,
            summary=f"Tree-sitter({self.language_name}) analyzed {request.file_path}; generic structural pass.",
            citations=citations,
            resolution_chain=resolution[: request.max_citations],
            flow_chain=flow_chain[: request.max_citations],
            unresolved_hops=unresolved[: request.max_citations],
            fallback_targets=call_names[:3],
            sections=sections[:12],
        )

    def _extract_call_names(self, text: str) -> list[str]:
        raw = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text or "")
        out: list[str] = []
        seen = set()
        for name in raw:
            if name in seen:
                continue
            seen.add(name)
            out.append(name)
            if len(out) >= 10:
                break
        return out


def build_generic_treesitter_analyzer_factory(
    language_name: str,
    *,
    supported_extensions: list[str],
    analyzer_config: dict[str, Any] | None = None,
):

    def _factory(codebase_path: str):
        return GenericTreeSitterAnalyzer(
            codebase_path=codebase_path,
            language_name=language_name,
            supported_extensions=supported_extensions,
            analyzer_config=analyzer_config,
        )

    return _factory
