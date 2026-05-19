# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

STRING_REDACTION = "[STRING_REDACTED]"

_PYTHON_EXTS = {".py", ".pyw"}
_HASH_COMMENT_EXTS = _PYTHON_EXTS | {".sh", ".rb", ".yaml", ".yml", ".toml"}
_C_STYLE_EXTS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".sol",
    ".java",
}


def sanitize_source(text: str, *, file_path: str = "", language: str = "") -> str:
    """
    Remove comments and redact string literals from untrusted tool output.

    The sanitizer is intentionally conservative: strings are replaced with a
    marker instead of dropped so security-relevant constants are not silently
    erased from the prompt context.
    """
    if not text:
        return ""
    lang = (language or "").lower()
    suffix = Path(file_path).suffix.lower()
    if lang == "python" or suffix in _PYTHON_EXTS:
        return _strip_python(text)
    if suffix in _HASH_COMMENT_EXTS:
        return _redact_hash_strings(_strip_hash_comments(text))
    if suffix in _C_STYLE_EXTS or lang in {
        "c",
        "cpp",
        "javascript",
        "typescript",
        "go",
        "rust",
        "solidity",
        "java",
    }:
        return _strip_c_style(text)
    return _strip_c_style(_strip_hash_comments(text))


def _strip_python(text: str) -> str:
    out: list[str] = []
    i = 0
    in_string: str | None = None
    triple = False
    while i < len(text):
        ch = text[i]
        three = text[i : i + 3]
        if in_string:
            if ch == "\n":
                out.append("\n")
                i += 1
                if not triple:
                    in_string = None
                continue
            if ch == "\\":
                i += 2
                continue
            if triple and three == in_string * 3:
                in_string = None
                triple = False
                i += 3
                continue
            if not triple and ch == in_string:
                in_string = None
            i += 1
            continue
        if ch == "#":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if ch in {"'", '"'}:
            out.append(STRING_REDACTION)
            in_string = ch
            triple = three == ch * 3
            i += 3 if triple else 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_hash_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        before, _sep, _after = line.partition("#")
        lines.append(before.rstrip())
    return "\n".join(lines)


def _redact_hash_strings(text: str) -> str:
    out: list[str] = []
    i = 0
    in_string: str | None = None
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == "\n":
                out.append("\n")
                in_string = None
                i += 1
                continue
            if ch == "\\":
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in {"'", '"'}:
            out.append(STRING_REDACTION)
            in_string = ch
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_c_style(text: str) -> str:
    out: list[str] = []
    i = 0
    in_string: str | None = None
    in_block_comment = False
    while i < len(text):
        ch = text[i]
        nxt = text[i : i + 2]
        if in_block_comment:
            if ch == "\n":
                out.append("\n")
            if nxt == "*/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if ch == "\n":
                out.append("\n")
                if in_string != "`":
                    in_string = None
                i += 1
                continue
            if ch == "\\":
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if nxt == "//":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if nxt == "/*":
            in_block_comment = True
            i += 2
            continue
        if ch in {"'", '"', "`"}:
            out.append(STRING_REDACTION)
            in_string = ch
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)
