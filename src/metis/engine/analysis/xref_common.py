# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re

from .treesitter_ast import dedup_keep_order, is_actionable_symbol


@dataclass(frozen=True)
class CrossFileHit:
    symbol: str
    file_path: str
    line: int
    kind: str


def resolve_unresolved_hops_across_codebase(
    *,
    unresolved_hops: list[str],
    codebase_path: str,
    file_path: str,
    top_symbol_hint: list[str],
    supported_extensions: set[str],
) -> tuple[list[str], list[str], list[str], list[str]]:
    remaining: list[str] = []
    sections: list[str] = []
    citations: list[str] = []
    resolution: list[str] = []

    for hop in unresolved_hops:
        symbol = extract_symbol_from_unresolved(hop)
        if not symbol or not is_actionable_symbol(symbol):
            remaining.append(hop)
            continue
        hits = search_symbol_hits(
            codebase_path=codebase_path,
            file_path=file_path,
            symbol=symbol,
            prefer_hint=top_symbol_hint,
            supported_extensions=supported_extensions,
            max_hits=2,
        )
        if not hits:
            remaining.append(hop)
            continue
        hit = choose_best_symbol_hit(hits)
        citations.append(f"{hit.file_path}:{hit.line}")
        sections.append(
            f"evidence.cross_file.{symbol}: {hit.kind} at {hit.file_path}:{hit.line}"
        )
        resolution.append(
            f"cross-file symbol resolution for {symbol} found {hit.kind} at {hit.file_path}:{hit.line}"
        )
    return remaining, sections, citations, resolution


def choose_best_symbol_hit(hits: list[CrossFileHit]) -> CrossFileHit:
    if not hits:
        return CrossFileHit(symbol="", file_path="", line=0, kind="none")
    priority = {
        "definition": 0,
        "function_like": 1,
        "function_ref": 2,
        "identifier_ref": 3,
    }
    ordered = sorted(
        hits,
        key=lambda h: (priority.get(h.kind, 9), h.file_path.lower(), h.line),
    )
    return ordered[0]


def extract_symbol_from_unresolved(hop: str) -> str:
    text = str(hop or "").strip()
    if ":" not in text:
        return ""
    parts = text.split(":")
    if len(parts) < 2:
        return ""
    candidate = parts[1].strip()
    if not candidate:
        return ""
    return candidate.split(":", 1)[0].strip()


def search_symbol_hits(
    *,
    codebase_path: str,
    file_path: str,
    symbol: str,
    prefer_hint: list[str],
    supported_extensions: set[str],
    max_hits: int,
) -> list[CrossFileHit]:
    hits: list[CrossFileHit] = []
    escaped = re.escape(symbol)
    definition_res = [
        re.compile(rf"^\s*(async\s+)?def\s+{escaped}\s*\("),
        re.compile(rf"^\s*(export\s+)?(async\s+)?function\s+{escaped}\s*\("),
        re.compile(rf"^\s*(export\s+)?const\s+{escaped}\s*="),
        re.compile(rf"^\s*func\s+(\([^)]*\)\s*)?{escaped}\s*\("),
        re.compile(rf"^\s*(pub\s+)?(async\s+)?fn\s+{escaped}\s*\("),
        re.compile(rf"^\s*function\s+{escaped}\s*\("),
    ]
    function_re = re.compile(rf"\b{escaped}\s*\(")
    identifier_re = re.compile(rf"\b{escaped}\b")

    for rel in walk_code_files(
        codebase_path=codebase_path,
        file_path=file_path,
        prefer_hint=prefer_hint,
        supported_extensions=supported_extensions,
        limit=1200,
    ):
        try:
            text = (Path(codebase_path).resolve() / rel).read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except Exception:
            continue
        for idx, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            if any(pattern.search(line) for pattern in definition_res):
                hits.append(
                    CrossFileHit(
                        symbol=symbol,
                        file_path=rel,
                        line=idx,
                        kind="definition",
                    )
                )
            elif function_re.search(line):
                hits.append(
                    CrossFileHit(
                        symbol=symbol,
                        file_path=rel,
                        line=idx,
                        kind="function_ref",
                    )
                )
            elif identifier_re.search(line):
                hits.append(
                    CrossFileHit(
                        symbol=symbol,
                        file_path=rel,
                        line=idx,
                        kind="identifier_ref",
                    )
                )
            if len(hits) >= max_hits * 3:
                break
        if len(hits) >= max_hits * 3:
            break
    return hits[: max_hits * 3]


def walk_code_files(
    *,
    codebase_path: str,
    file_path: str,
    prefer_hint: list[str],
    supported_extensions: set[str],
    limit: int,
) -> list[str]:
    root = Path(codebase_path).resolve()
    allowed_ext = {str(ext).lower() for ext in supported_extensions if ext}
    base_top = file_path.split("/", 1)[0] if "/" in file_path else ""
    prefer_set = {base_top} if base_top else set()
    for hint in prefer_hint:
        if hint and "/" in hint:
            prefer_set.add(hint.split("/", 1)[0])

    preferred: list[str] = []
    rest: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if name
            not in {".git", ".hg", ".svn", ".venv", "node_modules", "__pycache__"}
        ]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if allowed_ext and ext not in allowed_ext:
                continue
            full = Path(dirpath) / name
            try:
                rel = full.relative_to(root).as_posix()
            except Exception:
                continue
            bucket = rest
            top = rel.split("/", 1)[0] if "/" in rel else rel
            if top in prefer_set:
                bucket = preferred
            bucket.append(rel)
            if len(preferred) + len(rest) >= limit:
                break
        if len(preferred) + len(rest) >= limit:
            break
    return preferred + rest


def is_critical_unresolved_hop(hop: str) -> bool:
    text = str(hop or "").strip()
    if not text:
        return False
    critical_prefixes = (
        "FLOW_ANCHOR_NOT_FOUND",
        "FLOW_ENCLOSING_FUNCTION_UNRESOLVED",
        "FLOW_SINK_NOT_FOUND",
        "FLOW_EXTERNAL_CALLEE_UNRESOLVED:",
        "TREE_SITTER_UNAVAILABLE:",
        "TREE_SITTER_PARSE_FAILURE:",
    )
    return any(text.startswith(prefix) for prefix in critical_prefixes)


def compute_fallback_targets_from_unresolved(
    *,
    unresolved_hops: list[str],
    preferred_symbols: list[str],
    limit: int,
) -> list[str]:
    out: list[str] = []
    for hop in unresolved_hops:
        if not is_critical_unresolved_hop(hop):
            continue
        symbol = extract_symbol_from_unresolved(hop)
        if symbol and is_actionable_symbol(symbol):
            out.append(symbol)
    for symbol in preferred_symbols:
        if symbol and is_actionable_symbol(symbol):
            out.append(symbol)
    return dedup_keep_order(out)[:limit]
