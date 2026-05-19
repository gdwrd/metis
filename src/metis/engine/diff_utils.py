# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from pathlib import Path

from metis.utils import count_tokens, read_file_content

logger = logging.getLogger("metis")


def resolve_patch_path(
    codebase_path: str,
    path: str,
) -> tuple[str, str] | None:
    raw = Path(path)
    if raw.is_absolute() or ".." in raw.parts:
        return None
    try:
        base = Path(codebase_path).resolve()
        resolved = (base / raw).resolve()
        if os.path.commonpath([str(base), str(resolved)]) != str(base):
            return None
        return str(resolved), os.path.relpath(resolved, base)
    except Exception:
        return None


def extract_content_from_diff(file_diff):
    content_lines = []
    for hunk in file_diff:
        for line in hunk:
            if line.is_added:
                content_lines.append(line.value)
    return "".join(content_lines)


def extract_added_line_ranges(file_diff) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    current_start: int | None = None
    current_end: int | None = None

    for hunk in file_diff:
        for line in hunk:
            if not line.is_added:
                continue
            target_line = getattr(line, "target_line_no", None)
            if target_line is None:
                continue
            target_line = int(target_line)
            if current_start is None:
                current_start = current_end = target_line
                continue
            if current_end is not None and target_line == current_end + 1:
                current_end = target_line
                continue
            ranges.append((current_start, current_end or current_start))
            current_start = current_end = target_line

    if current_start is not None:
        ranges.append((current_start, current_end or current_start))
    return ranges


def process_diff_file(
    codebase_path,
    file_diff,
    max_token_length,
    *,
    original_file_path: str | None = None,
):
    changed_lines = []
    for hunk in file_diff:
        for line in hunk:
            if line.is_added:
                changed_lines.append("+" + line.value)
            elif line.is_removed:
                changed_lines.append("-" + line.value)
    snippet = "".join(changed_lines)
    if original_file_path is None:
        resolved = resolve_patch_path(codebase_path, file_diff.path)
        original_file_path = resolved[0] if resolved is not None else ""
    original_content = read_file_content(original_file_path)
    if original_content:
        logger.info(f"Fetched original content for {file_diff.path}.")
        total_tokens = count_tokens(original_content) + count_tokens(snippet)
        if total_tokens <= max_token_length:
            snippet = f"ORIGINAL_FILE:\n{original_content}\n\nFILE_CHANGES:\n{snippet}"
        else:
            snippet = f"FILE_CHANGES:\n{snippet}"
    return snippet
