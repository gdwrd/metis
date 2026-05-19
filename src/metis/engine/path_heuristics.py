# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
import re

DEFAULT_TEST_PATH_PATTERNS: tuple[str, ...] = (
    "tests/**",
    "test/**",
    "**/tests/**",
    "**/test/**",
    "__tests__/**",
    "**/__tests__/**",
    "*_test.go",
    "*_test.py",
    "test_*.py",
    "*.spec.ts",
    "*.spec.tsx",
    "*.spec.js",
    "*.spec.jsx",
    "*.test.ts",
    "*.test.tsx",
    "*.test.js",
    "*.test.jsx",
    "*Test.java",
    "*Tests.cs",
    "*_spec.rb",
    "testcases/**",
    "**/testcases/**",
    "BenchmarkTest*.java",
)

_TEST_DIRECTORY_NAMES = frozenset({"tests", "test", "__tests__", "testcases"})


def is_test_path(
    path: str,
    language: str | None = None,
    *,
    extra_patterns: Iterable[str] | None = None,
) -> bool:
    """Return True when a path is likely test, fixture, or benchmark code."""
    normalized = _normalize_path(path)
    if not normalized:
        return False

    parts = PurePosixPath(normalized).parts
    if any(part in _TEST_DIRECTORY_NAMES for part in parts[:-1]):
        return True

    patterns = [*DEFAULT_TEST_PATH_PATTERNS, *list(extra_patterns or ())]
    basename = parts[-1] if parts else normalized
    return any(
        _matches_pattern(normalized, basename, pattern)
        for pattern in _dedupe_patterns(patterns)
    )


def _matches_pattern(path: str, basename: str, pattern: str) -> bool:
    normalized_pattern = _normalize_path(pattern)
    if not normalized_pattern:
        return False
    if normalized_pattern == "BenchmarkTest*.java":
        return bool(re.fullmatch(r"BenchmarkTest[0-9].*\.java", basename))
    if "/" in normalized_pattern:
        return fnmatchcase(path, normalized_pattern)
    return fnmatchcase(basename, normalized_pattern)


def _normalize_path(path: str) -> str:
    normalized = str(path or "").replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.strip("/")


def _dedupe_patterns(patterns: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    deduped: list[str] = []
    for pattern in patterns:
        text = str(pattern or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        deduped.append(text)
    return tuple(deduped)
