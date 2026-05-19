# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any

from llama_index.core.schema import (
    MetadataMode,
    NodeRelationship,
    RelatedNodeInfo,
    TextNode,
)

from metis.utils import count_tokens

logger = logging.getLogger("metis")

FUNCTION_INDEX_VERSION = 1
DEFAULT_PER_FUNCTION_CHARS = 1500
DEFAULT_MAX_FUNCTIONS = 6
DEFAULT_TOTAL_CHARS = 8000
DEFAULT_EMBEDDING_TOKEN_LIMIT = 6000
DEFAULT_EMBEDDING_TOKEN_MODEL = "text-embedding-3-large"
DEFAULT_EXCLUDED_EMBED_METADATA_KEYS = (
    "signature",
    "callees",
    "chunk_index",
    "chunk_count",
    "embedding_chunk_index",
    "embedding_chunk_count",
)
LineRange = tuple[int, int]


@dataclass
class FunctionEntry:
    qualified_name: str
    name: str
    file: str
    start_line: int
    end_line: int
    signature: str
    language: str
    call_names: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "signature": self.signature,
            "language": self.language,
            "call_names": list(self.call_names),
            "callees": list(self.callees),
            "callers": list(self.callers),
        }

    @classmethod
    def from_dict(cls, qualified_name: str, payload: dict[str, Any]) -> "FunctionEntry":
        return cls(
            qualified_name=qualified_name,
            name=_name_from_qualified(qualified_name),
            file=str(payload.get("file") or ""),
            start_line=int(payload.get("start_line") or 0),
            end_line=int(payload.get("end_line") or 0),
            signature=str(payload.get("signature") or ""),
            language=str(payload.get("language") or ""),
            call_names=[str(item) for item in payload.get("call_names", []) or []],
            callees=[str(item) for item in payload.get("callees", []) or []],
            callers=[str(item) for item in payload.get("callers", []) or []],
        )


@dataclass
class FunctionIndex:
    functions: dict[str, FunctionEntry] = field(default_factory=dict)
    by_name: dict[str, list[str]] = field(default_factory=dict)
    file_hashes: dict[str, str] = field(default_factory=dict)
    version: int = FUNCTION_INDEX_VERSION
    indexed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    def add(self, entry: FunctionEntry) -> None:
        self.functions[entry.qualified_name] = entry
        names = self.by_name.setdefault(entry.name, [])
        if entry.qualified_name not in names:
            names.append(entry.qualified_name)

    def merge(self, other: "FunctionIndex", *, rebuild: bool = True) -> None:
        for entry in other.functions.values():
            self.add(entry)
        for file_path, file_hash in other.file_hashes.items():
            self.set_file_hash(file_path, file_hash)
        if rebuild:
            self.rebuild_edges()

    def remove_file(self, file_path: str, *, rebuild: bool = True) -> None:
        for qname, entry in list(self.functions.items()):
            if _same_file(entry.file, file_path):
                del self.functions[qname]
        for hashed_file in list(self.file_hashes):
            if _same_file(hashed_file, file_path):
                del self.file_hashes[hashed_file]
        self.by_name = {}
        for entry in self.functions.values():
            self.by_name.setdefault(entry.name, []).append(entry.qualified_name)
        if rebuild:
            self.rebuild_edges()

    def set_file_hash(self, file_path: str, file_hash: str | None) -> None:
        normalized = os.path.normpath(str(file_path or ""))
        normalized_hash = str(file_hash or "")
        if normalized and normalized_hash:
            self.file_hashes[normalized] = normalized_hash

    def file_hash_matches(self, file_path: str, file_hash: str | None) -> bool:
        normalized_hash = str(file_hash or "")
        if not normalized_hash:
            return False
        for indexed_file, indexed_hash in self.file_hashes.items():
            if _same_file(indexed_file, file_path):
                return indexed_hash == normalized_hash
        return False

    def files(self) -> set[str]:
        files = set(self.file_hashes)
        files.update(entry.file for entry in self.functions.values())
        return files

    def rebuild_edges(self) -> None:
        for entry in self.functions.values():
            resolved: list[str] = []
            for call_name in entry.call_names:
                for candidate in self.resolve_name(call_name, same_file=entry.file):
                    if candidate != entry.qualified_name and candidate not in resolved:
                        resolved.append(candidate)
            entry.callees = resolved
            entry.callers = []
        for caller in self.functions.values():
            for callee_name in caller.callees:
                callee = self.functions.get(callee_name)
                if callee is None:
                    continue
                if caller.qualified_name not in callee.callers:
                    callee.callers.append(caller.qualified_name)

    def resolve_name(self, name: str, *, same_file: str | None = None) -> list[str]:
        candidates = list(self.by_name.get(name, []) or [])
        if same_file:
            same = [
                qname
                for qname in candidates
                if _same_file(self.functions[qname].file, same_file)
            ]
            rest = [qname for qname in candidates if qname not in same]
            candidates = same + rest
        return candidates[:3]

    def functions_for_snippet(
        self,
        file_path: str,
        snippet: str,
        *,
        codebase_path: str = "",
        line_ranges: Sequence[LineRange] | None = None,
        limit: int = 3,
    ) -> list[FunctionEntry]:
        same_file = [
            entry
            for entry in self.functions.values()
            if _same_file(entry.file, file_path, codebase_path=codebase_path)
        ]
        if not same_file:
            return []
        normalized_ranges = _normalize_line_ranges(line_ranges)
        if normalized_ranges:
            matched_by_line = [
                entry
                for entry in same_file
                if any(
                    _line_ranges_overlap(
                        entry.start_line,
                        entry.end_line,
                        start_line,
                        end_line,
                    )
                    for start_line, end_line in normalized_ranges
                )
            ]
            if matched_by_line:
                return matched_by_line[:limit]

        snippet_text = snippet or ""
        return [
            entry
            for entry in same_file
            if entry.signature and entry.signature in snippet_text
        ][:limit]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "indexed_at": self.indexed_at,
            "file_hashes": {
                file_path: self.file_hashes[file_path]
                for file_path in sorted(self.file_hashes)
            },
            "functions": {
                qname: entry.to_dict()
                for qname, entry in sorted(self.functions.items())
            },
            "by_name": {
                name: sorted(qnames) for name, qnames in sorted(self.by_name.items())
            },
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FunctionIndex":
        index = cls(
            version=int(payload.get("version") or FUNCTION_INDEX_VERSION),
            indexed_at=str(payload.get("indexed_at") or ""),
        )
        for qname, raw_entry in (payload.get("functions") or {}).items():
            if isinstance(raw_entry, dict):
                index.add(FunctionEntry.from_dict(str(qname), raw_entry))
        if isinstance(payload.get("file_hashes"), dict):
            index.file_hashes = {
                os.path.normpath(str(file_path)): str(file_hash)
                for file_path, file_hash in payload["file_hashes"].items()
                if str(file_path or "") and str(file_hash or "")
            }
        if isinstance(payload.get("by_name"), dict):
            index.by_name = {
                str(name): [str(qname) for qname in qnames or []]
                for name, qnames in payload["by_name"].items()
            }
        else:
            index.by_name = {}
            for entry in index.functions.values():
                index.by_name.setdefault(entry.name, []).append(entry.qualified_name)
        if any(entry.call_names for entry in index.functions.values()):
            index.rebuild_edges()
        return index

    @classmethod
    def read(cls, path: str | os.PathLike[str]) -> "FunctionIndex":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    def write(self, path: str | os.PathLike[str]) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, path)


def extract_function_nodes_from_document(
    document,
    plugin,
) -> tuple[list[TextNode], FunctionIndex]:
    text = str(getattr(document, "text", "") or "")
    file_path = str(
        getattr(document, "id_", "") or getattr(document, "doc_id", "") or ""
    )
    document_hash = str(getattr(document, "hash", "") or "")
    declarations = _function_declarations(plugin)
    if not declarations:
        index = FunctionIndex()
        index.set_file_hash(file_path, document_hash)
        return [], index

    language = _parser_language_for_document(file_path, str(plugin.get_name() or ""))
    if not text or not file_path or not language:
        return [], FunctionIndex()

    try:
        from tree_sitter_language_pack import get_parser

        tree = get_parser(language).parse(text.encode("utf-8"))  # type: ignore[arg-type]
    except Exception as exc:
        logger.warning("Function extraction unavailable for %s: %s", file_path, exc)
        return [], FunctionIndex()

    root = getattr(tree, "root_node", None)
    if root is None:
        return [], FunctionIndex()

    functions = set(declarations.get("function", []) or [])
    call_types = set(declarations.get("call", []) or [])
    name_fields = list(declarations.get("name", []) or [])
    source = text.encode("utf-8")
    parent_map: dict[int, Any | None] = {}
    _build_parent_map(root, parent_map, None)

    raw_entries: list[tuple[FunctionEntry, list[str]]] = []
    used_qnames: set[str] = set()
    for node in _walk(root):
        if str(getattr(node, "type", "") or "") not in functions:
            continue
        name = _function_name(node, parent_map, source, name_fields)
        if not _is_probable_function_name(name):
            continue
        start_line = _line_start(node)
        end_line = _line_end(node)
        body = _node_text(node, source)
        signature = _signature_from_body(body)
        qname = _qualified_name(file_path, name, start_line, used_qnames)
        entry = FunctionEntry(
            qualified_name=qname,
            name=name,
            file=file_path,
            start_line=start_line,
            end_line=end_line,
            signature=signature,
            language=language,
            call_names=_collect_calls(node, source, call_types, name_fields),
        )
        raw_entries.append((entry, entry.call_names))

    index = FunctionIndex()
    index.set_file_hash(file_path, document_hash)
    for entry, _calls in raw_entries:
        index.add(entry)
    index.rebuild_edges()

    nodes = [
        node
        for entry in index.functions.values()
        for node in _text_nodes_for_entry(entry, text, source_doc_id=file_path)
    ]
    return nodes, index


def format_related_functions(
    index: FunctionIndex | None,
    *,
    codebase_path: str,
    file_path: str,
    snippet: str,
    line_ranges: Sequence[LineRange] | None = None,
    per_function_chars: int = DEFAULT_PER_FUNCTION_CHARS,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    total_chars: int = DEFAULT_TOTAL_CHARS,
) -> str:
    if index is None:
        return ""
    anchors = index.functions_for_snippet(
        file_path,
        snippet,
        codebase_path=codebase_path,
        line_ranges=line_ranges,
    )
    if not anchors:
        return ""

    selected: list[str] = []
    for anchor in anchors:
        for qname in anchor.callees:
            if qname not in selected:
                selected.append(qname)
        for qname in anchor.callers[:1]:
            if qname not in selected:
                selected.append(qname)
    selected = selected[:max_functions]
    if not selected:
        return ""

    sections = []
    remaining = total_chars
    for qname in selected:
        entry = index.functions.get(qname)
        if entry is None or remaining <= 0:
            continue
        body = _read_entry_body(codebase_path, entry)
        if not body:
            continue
        header = (
            f"- {entry.qualified_name} "
            f"({entry.file}:{entry.start_line}-{entry.end_line})"
        )
        wrapper = f"{header}\n```{entry.language}\n\n```"
        limit = min(per_function_chars, remaining - len(wrapper))
        if limit <= 0:
            break
        truncated = body[:limit]
        if len(body) > limit:
            truncated = truncated.rstrip() + "\n... [truncated] ..."
        block = f"{header}\n```{entry.language}\n{truncated.rstrip()}\n```"
        if len(block) > remaining:
            break
        sections.append(block)
        remaining -= len(block)

    if not sections:
        return ""
    return "RELATED_FUNCTIONS:\n" + "\n\n".join(sections)


def load_function_index(path: str | os.PathLike[str] | None) -> FunctionIndex | None:
    if not path:
        return None
    try:
        if not os.path.exists(path):
            return None
        return FunctionIndex.read(path)
    except Exception as exc:
        logger.warning("Could not load function index %s: %s", path, exc)
        return None


def _text_nodes_for_entry(
    entry: FunctionEntry,
    document_text: str,
    *,
    source_doc_id: str,
) -> list[TextNode]:
    lines = document_text.splitlines()
    body = "\n".join(lines[entry.start_line - 1 : entry.end_line])
    chunks = _split_text_for_embedding(body)
    if not chunks:
        return []
    nodes = []
    for index, chunk in enumerate(chunks):
        chunk_count = len(chunks)
        node_id = (
            entry.qualified_name
            if chunk_count == 1
            else f"{entry.qualified_name}#chunk-{index + 1}"
        )
        nodes.append(
            TextNode(
                text=chunk,
                id_=node_id,
                excluded_embed_metadata_keys=list(DEFAULT_EXCLUDED_EMBED_METADATA_KEYS),
                relationships={
                    NodeRelationship.SOURCE: RelatedNodeInfo(node_id=source_doc_id)
                },
                metadata={
                    "file_name": entry.file,
                    "function_name": entry.name,
                    "qualified_name": entry.qualified_name,
                    "start_line": entry.start_line,
                    "end_line": entry.end_line,
                    "signature": entry.signature,
                    "language": entry.language,
                    "callees": ",".join(entry.callees),
                    "chunk_index": index,
                    "chunk_count": chunk_count,
                },
            )
        )
    return nodes


def ensure_embedding_safe_nodes(
    nodes,
    *,
    max_tokens: int = DEFAULT_EMBEDDING_TOKEN_LIMIT,
    model: str = DEFAULT_EMBEDDING_TOKEN_MODEL,
):
    safe_nodes = []
    for node in nodes:
        node = _exclude_embed_metadata(
            node,
            DEFAULT_EXCLUDED_EMBED_METADATA_KEYS,
        )
        node = _exclude_all_metadata_if_needed(
            node,
            max_tokens=max_tokens,
            model=model,
        )
        if _embedding_token_count(node, model=model) <= max_tokens:
            safe_nodes.append(node)
            continue
        text = str(getattr(node, "text", "") or "")
        if not text:
            logger.warning("Embedding node %s exceeds token limit", _node_id(node))
            safe_nodes.append(node)
            continue
        text_budget = _embedding_text_budget(node, max_tokens=max_tokens, model=model)
        chunks = _split_text_for_embedding(text, max_tokens=text_budget, model=model)
        if len(chunks) <= 1:
            logger.warning("Embedding node %s exceeds token limit", _node_id(node))
            safe_nodes.append(node)
            continue
        chunk_count = len(chunks)
        for index, chunk in enumerate(chunks):
            chunk_node = node.model_copy(deep=True)
            try:
                chunk_node.text = chunk
            except AttributeError:
                chunk_node.set_content(chunk)
            chunk_node.id_ = f"{_node_id(node)}#embed-chunk-{index + 1}"
            chunk_node.metadata = dict(getattr(chunk_node, "metadata", {}) or {})
            chunk_node.metadata["embedding_chunk_index"] = index
            chunk_node.metadata["embedding_chunk_count"] = chunk_count
            chunk_node = _exclude_embed_metadata(
                chunk_node,
                DEFAULT_EXCLUDED_EMBED_METADATA_KEYS,
            )
            safe_nodes.append(chunk_node)
    return safe_nodes


def _exclude_embed_metadata(node, keys):
    existing = list(getattr(node, "excluded_embed_metadata_keys", []) or [])
    merged = list(dict.fromkeys([*existing, *(str(key) for key in keys)]))
    try:
        node.excluded_embed_metadata_keys = merged
    except Exception:
        return node
    return node


def _exclude_all_metadata_if_needed(
    node,
    *,
    max_tokens: int,
    model: str,
):
    if _embedding_metadata_token_count(node, model=model) <= max_tokens - 256:
        return node
    metadata = dict(getattr(node, "metadata", {}) or {})
    if not metadata:
        return node
    return _exclude_embed_metadata(node, metadata.keys())


def _embedding_token_count(
    node,
    *,
    model: str = DEFAULT_EMBEDDING_TOKEN_MODEL,
) -> int:
    try:
        content = node.get_content(metadata_mode=MetadataMode.EMBED)
    except Exception:
        content = str(getattr(node, "text", "") or "")
    return count_tokens(content, model=model)


def _embedding_metadata_token_count(
    node,
    *,
    model: str = DEFAULT_EMBEDDING_TOKEN_MODEL,
) -> int:
    if not hasattr(node, "model_copy"):
        return 0
    metadata_only = node.model_copy(deep=True)
    try:
        metadata_only.text = ""
    except AttributeError:
        metadata_only.set_content("")
    return _embedding_token_count(metadata_only, model=model)


def _embedding_text_budget(
    node,
    *,
    max_tokens: int,
    model: str,
) -> int:
    try:
        overhead = _embedding_metadata_token_count(node, model=model)
    except Exception:
        overhead = 0
    return max(1, max_tokens - overhead - 256)


def _node_id(node) -> str:
    return str(
        getattr(node, "node_id", None)
        or getattr(node, "id_", None)
        or getattr(node, "id", None)
        or "node"
    )


def _split_text_for_embedding(
    text: str,
    *,
    max_tokens: int = DEFAULT_EMBEDDING_TOKEN_LIMIT,
    model: str = DEFAULT_EMBEDDING_TOKEN_MODEL,
) -> list[str]:
    if not text:
        return []
    try:
        import tiktoken

        encoding = tiktoken.encoding_for_model(model)
    except Exception:
        return _split_text_by_chars(text, max(1, max_tokens * 3))

    chunks: list[str] = []
    current: list[str] = []
    current_tokens = 0
    for line in text.splitlines(keepends=True):
        line_tokens = encoding.encode(line)
        if len(line_tokens) > max_tokens:
            if current:
                chunks.append("".join(current))
                current = []
                current_tokens = 0
            for start in range(0, len(line_tokens), max_tokens):
                chunks.append(encoding.decode(line_tokens[start : start + max_tokens]))
            continue
        if current and current_tokens + len(line_tokens) > max_tokens:
            chunks.append("".join(current))
            current = [line]
            current_tokens = len(line_tokens)
            continue
        current.append(line)
        current_tokens += len(line_tokens)
    if current:
        chunks.append("".join(current))
    return [chunk for chunk in chunks if chunk]


def _split_text_by_chars(text: str, max_chars: int) -> list[str]:
    chunks = []
    for start in range(0, len(text), max_chars):
        chunk = text[start : start + max_chars]
        if chunk:
            chunks.append(chunk)
    return chunks


def _function_declarations(plugin) -> dict[str, list[str]]:
    try:
        declarations = plugin.get_function_node_types()
    except Exception:
        return {}
    if not isinstance(declarations, dict):
        return {}
    return declarations


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        children = list(getattr(current, "children", []) or [])
        stack.extend(reversed(children))


def _build_parent_map(node, parent_map: dict[int, Any | None], parent) -> None:
    stack = [(node, parent)]
    while stack:
        current, current_parent = stack.pop()
        parent_map[id(current)] = current_parent
        children = list(getattr(current, "children", []) or [])
        stack.extend((child, current) for child in reversed(children))


def _point_row(point) -> int:
    row = getattr(point, "row", None)
    if row is not None:
        return int(row)
    return int(point[0])


def _line_start(node) -> int:
    return _point_row(getattr(node, "start_point")) + 1


def _line_end(node) -> int:
    return _point_row(getattr(node, "end_point")) + 1


def _node_text(node, source: bytes) -> str:
    return source[getattr(node, "start_byte") : getattr(node, "end_byte")].decode(
        "utf-8", errors="ignore"
    )


def _child_by_field(node, field_name: str):
    try:
        return node.child_by_field_name(field_name)
    except Exception:
        return None


def _identifier_text(node, source: bytes) -> str:
    if node is None:
        return ""
    node_type = str(getattr(node, "type", "") or "")
    if node_type in {
        "attribute",
        "member_expression",
        "selector_expression",
        "field_expression",
        "qualified_identifier",
    }:
        for field_name in ("attribute", "property", "field", "name", "member"):
            found = _identifier_text(_child_by_field(node, field_name), source)
            if found:
                return found
        identifiers = [
            _node_text(child, source).strip()
            for child in _walk(node)
            if str(getattr(child, "type", "") or "")
            in {
                "identifier",
                "field_identifier",
                "property_identifier",
                "type_identifier",
            }
        ]
        if identifiers:
            return identifiers[-1].split(".")[-1].split("::")[-1].strip()
    if node_type in {
        "identifier",
        "field_identifier",
        "property_identifier",
        "type_identifier",
        "constant",
    }:
        return _node_text(node, source).split(".")[-1].split("::")[-1].strip()
    for child in getattr(node, "children", []) or []:
        found = _identifier_text(child, source)
        if found:
            return found
    direct = _node_text(node, source).strip()
    if direct and "\n" not in direct and len(direct) <= 120:
        return direct.split(".")[-1].split("::")[-1].split("(")[0].strip()
    return ""


def _function_name(
    node,
    parent_map: dict[int, Any | None],
    source: bytes,
    name_fields: list[str],
) -> str:
    for field_name in name_fields:
        child = _child_by_field(node, field_name)
        found = _identifier_text(child, source)
        if found:
            return found

    node_type = str(getattr(node, "type", "") or "")
    parent = parent_map.get(id(node))
    if node_type in {"arrow_function", "function", "closure_expression"}:
        found = _identifier_text(parent, source)
        if found:
            return found

    found = _identifier_text(node, source)
    if found:
        return found

    if parent is not None:
        return _identifier_text(parent, source)
    return ""


def _is_probable_function_name(name: str) -> bool:
    name = str(name or "").strip()
    if not name:
        return False
    if name[0] in "{}()[];,:.":
        return False
    return any(character.isalnum() or character in "_$" for character in name)


def _collect_calls(
    function_node,
    source: bytes,
    call_types: set[str],
    name_fields: list[str],
) -> list[str]:
    if not call_types:
        return []
    calls: list[str] = []
    for node in _walk(function_node):
        if str(getattr(node, "type", "") or "") not in call_types:
            continue
        name = ""
        for field_name in ("function", "name", "callee", *name_fields):
            name = _identifier_text(_child_by_field(node, field_name), source)
            if name:
                break
        if not name:
            name = _identifier_text(node, source)
        if name and name not in calls:
            calls.append(name)
    return calls


def _signature_from_body(body: str) -> str:
    first = (body or "").strip().splitlines()
    return first[0].strip() if first else ""


def _qualified_name(
    file_path: str,
    name: str,
    start_line: int,
    used_qnames: set[str],
) -> str:
    base = f"{_clean_path(file_path)}::{name}"
    qname = base
    if qname in used_qnames:
        qname = f"{base}@{start_line}"
    used_qnames.add(qname)
    return qname


def _name_from_qualified(qualified_name: str) -> str:
    raw = qualified_name.rsplit("::", 1)[-1]
    return raw.split("@", 1)[0]


def _clean_path(path: str) -> str:
    return os.path.normpath(str(path or "")).replace("\\", "/").lstrip("./")


def _parser_language_for_document(file_path: str, plugin_name: str) -> str:
    if os.path.splitext(file_path)[1].lower() in {".jsx", ".tsx"}:
        return "tsx"
    return plugin_name


def _same_file(left: str, right: str, *, codebase_path: str = "") -> bool:
    return _canonical_match_path(left, codebase_path) == _canonical_match_path(
        right, codebase_path
    )


def _normalize_line_ranges(
    line_ranges: Sequence[LineRange] | None,
) -> list[LineRange]:
    normalized: list[LineRange] = []
    for raw_start, raw_end in line_ranges or []:
        start = max(1, int(raw_start or 0))
        end = max(start, int(raw_end or start))
        normalized.append((start, end))
    return normalized


def _line_ranges_overlap(
    left_start: int,
    left_end: int,
    right_start: int,
    right_end: int,
) -> bool:
    return left_start <= right_end and right_start <= left_end


def _canonical_match_path(path: str, codebase_path: str = "") -> str:
    clean = _clean_path(path)
    if not codebase_path:
        return clean
    prefix = Path(codebase_path).resolve().name + "/"
    if clean.startswith(prefix):
        return clean[len(prefix) :]
    return clean


def _read_entry_body(codebase_path: str, entry: FunctionEntry) -> str:
    candidate = _resolve_entry_path(codebase_path, entry.file)
    if candidate is None:
        return ""
    try:
        lines = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
        return "\n".join(lines[entry.start_line - 1 : entry.end_line])
    except Exception:
        return ""
    return ""


def _resolve_entry_path(codebase_path: str, entry_file: str) -> Path | None:
    try:
        root = Path(codebase_path).resolve()
    except Exception:
        return None
    raw = Path(entry_file)
    candidates: list[Path]
    if raw.is_absolute():
        candidates = [raw]
    else:
        clean = _clean_path(entry_file)
        stripped = clean
        prefix = root.name + "/"
        if clean.startswith(prefix):
            stripped = clean[len(prefix) :]
        candidates = [root / clean]
        if stripped != clean:
            candidates.append(root / stripped)

    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            if os.path.commonpath([str(root), str(resolved)]) != str(root):
                continue
            if resolved.is_file():
                return resolved
        except Exception:
            continue
    return None
