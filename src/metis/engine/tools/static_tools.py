# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from fnmatch import fnmatch
from typing import Sequence

from .sanitize import sanitize_source

_PYTHON_REGEX_REWRITES = (
    ("[[:space:]]", r"\s"),
    ("[[:blank:]]", r"[ \t]"),
)
_GREP_REPO_MAX_LINE_CHARS = 20000


class StaticToolRunner:
    def __init__(
        self,
        *,
        codebase_path: str,
        timeout_seconds: int = 8,
        max_chars: int = 16000,
        function_index=None,
    ):
        self.codebase_path = Path(codebase_path).resolve()
        self.timeout_seconds = timeout_seconds
        self.max_chars = max_chars
        self.function_index = function_index
        self._has_grep = shutil.which("grep") is not None
        self._has_find = shutil.which("find") is not None
        self._has_cat = shutil.which("cat") is not None
        self._has_sed = shutil.which("sed") is not None
        self._file_text_cache: dict[str, str] = {}

    def describe_tool(self, name: str) -> dict[str, str]:
        if name == "grep":
            backend = "shell_grep" if self._has_grep else "python_regex"
            return {"backend": backend}
        if name == "find_name":
            backend = "shell_find" if self._has_find else "python_walk"
            return {"backend": backend}
        if name == "cat":
            return {"backend": "python_cached_read"}
        if name == "sed":
            return {"backend": "python_cached_slice"}
        if name in {"get_function_body", "get_callers", "grep_repo"}:
            return {"backend": "python_bounded"}
        return {}

    def _resolve_path(self, raw_path: str) -> Path:
        raw = Path(raw_path)
        if raw.is_absolute():
            raise ValueError("Absolute paths are not allowed")
        if ".." in raw.parts:
            raise ValueError("Parent traversal is not allowed")
        candidate = (self.codebase_path / raw_path).resolve()
        if (
            candidate != self.codebase_path
            and self.codebase_path not in candidate.parents
        ):
            raise ValueError("Path escapes codebase")
        return candidate

    def _run(
        self,
        argv: Sequence[str],
        *,
        ok_returncodes: tuple[int, ...] = (0,),
    ) -> str:
        proc = subprocess.run(
            list(argv),
            cwd=str(self.codebase_path),
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if proc.returncode not in ok_returncodes:
            detail = stderr or stdout or f"exit status {proc.returncode}"
            raise RuntimeError(f"{' '.join(argv)} failed: {detail}")
        return self._clip(stdout)

    def _clip(self, text: str) -> str:
        if len(text) > self.max_chars:
            return text[: self.max_chars] + "\n...[truncated]"
        return text

    def _iter_files(self, base: Path):
        if base.is_file():
            yield base
            return
        if not base.exists():
            return
        for root, _, files in os.walk(base):
            root_path = Path(root)
            for name in files:
                yield root_path / name

    def grep(self, pattern: str, path: str) -> str:
        target = self._resolve_path(path)
        if self._has_grep:
            return self._run(
                ["grep", "-HREn", "--", pattern, str(target)],
                ok_returncodes=(0, 1),
            )

        try:
            translated = pattern
            for source, replacement in _PYTHON_REGEX_REWRITES:
                translated = translated.replace(source, replacement)
            regex = re.compile(translated)
        except re.error as exc:
            raise ValueError(f"Invalid grep pattern: {exc}") from exc

        lines: list[str] = []
        for file_path in self._iter_files(target):
            rel = file_path.relative_to(self.codebase_path).as_posix()
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    lines.append(f"{rel}:{lineno}:{line}")
                    if sum(len(x) + 1 for x in lines) >= self.max_chars:
                        return self._clip("\n".join(lines))
        return self._clip("\n".join(lines))

    def find_name(self, name: str, max_results: int = 20) -> list[str]:
        if not name or "/" in name or "\\" in name:
            return []
        if self._has_find:
            output = self._run(["find", ".", "-type", "f", "-name", name])
            found: list[str] = []
            for line in (output or "").splitlines():
                item = line.strip()
                if not item or item.startswith("find:"):
                    continue
                if item.startswith("./"):
                    item = item[2:]
                found.append(item.replace("\\", "/"))
        else:
            found = []
            for file_path in self._iter_files(self.codebase_path):
                if file_path.name != name:
                    continue
                try:
                    item = file_path.relative_to(self.codebase_path).as_posix()
                except Exception:
                    continue
                found.append(item)
        results: list[str] = []
        for item in sorted(set(found), key=lambda p: p.lower()):
            results.append(item)
            if len(results) >= max_results:
                break
        return results

    def cat(self, path: str) -> str:
        target = self._resolve_path(path)
        if not target.is_file():
            raise FileNotFoundError(str(target))
        return self._clip(self._read_file_text(target))

    def sed(self, path: str, start_line: int, end_line: int) -> str:
        if end_line < start_line:
            raise ValueError("end_line must be >= start_line")
        target = self._resolve_path(path)
        if not target.is_file():
            raise FileNotFoundError(str(target))
        lines = self._read_file_text(target).splitlines()
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), end_line)
        return self._clip("\n".join(lines[start_idx:end_idx]))

    def get_function_body(self, name: str) -> str:
        index = self.function_index
        if index is None or not name:
            return ""
        sections: list[str] = []
        remaining = min(self.max_chars, 4000)
        deadline = self._deadline()
        for qname in index.resolve_name(str(name))[:3]:
            self._check_deadline(deadline, "get_function_body timed out")
            entry = index.functions.get(qname)
            if entry is None or remaining <= 0:
                continue
            body = self._entry_lines(
                entry,
                deadline=deadline,
                max_chars=remaining,
                timeout_message="get_function_body timed out",
            )
            if not body:
                continue
            sanitized = sanitize_source(
                body,
                file_path=str(entry.file),
                language=str(getattr(entry, "language", "") or ""),
            )
            header = f"{entry.qualified_name} ({entry.file}:{entry.start_line}-{entry.end_line})"
            block = f"{header}\n{sanitized.strip()}"
            if len(block) > remaining:
                block = block[:remaining].rstrip() + "\n...[truncated]"
            sections.append(block)
            remaining -= len(block)
        return "\n\n".join(sections)

    def get_callers(self, name: str) -> list[dict[str, object]]:
        index = self.function_index
        if index is None or not name:
            return []
        callers: list[dict[str, object]] = []
        seen: set[str] = set()
        deadline = self._deadline()
        for qname in index.resolve_name(str(name))[:3]:
            self._check_deadline(deadline, "get_callers timed out")
            entry = index.functions.get(qname)
            if entry is None:
                continue
            for caller_qname in list(entry.callers or []):
                self._check_deadline(deadline, "get_callers timed out")
                if caller_qname in seen:
                    continue
                caller = index.functions.get(caller_qname)
                if caller is None:
                    continue
                snippet = self._entry_lines(
                    caller,
                    start_line=max(1, caller.start_line - 5),
                    end_line=caller.end_line + 5,
                    deadline=deadline,
                    max_chars=4000,
                    timeout_message="get_callers timed out",
                )
                if not snippet:
                    continue
                callers.append(
                    {
                        "file": caller.file,
                        "line": caller.start_line,
                        "snippet": sanitize_source(
                            snippet,
                            file_path=str(caller.file),
                            language=str(getattr(caller, "language", "") or ""),
                        ).strip(),
                    }
                )
                seen.add(caller_qname)
                if len(callers) >= 5:
                    return callers
        return callers

    def grep_repo(self, pattern: str, path_glob: str | None = None) -> str:
        pattern = str(pattern or "")
        if re.fullmatch(r"[\.\*\s]+", pattern):
            raise ValueError("grep_repo pattern must not be only wildcards")
        if len(pattern) < 3:
            raise ValueError("grep_repo pattern must be at least 3 characters")
        hits: list[str] = []
        glob = path_glob.replace("\\", "/") if path_glob else ""
        deadline = self._deadline()
        for file_path in self._iter_files(self.codebase_path):
            self._check_deadline(deadline, "grep_repo timed out")
            try:
                rel = file_path.relative_to(self.codebase_path).as_posix()
            except Exception:
                continue
            if glob and not (fnmatch(rel, glob) or fnmatch("/" + rel, glob)):
                continue
            try:
                resolved_file = file_path.resolve()
                if (
                    resolved_file != self.codebase_path
                    and self.codebase_path not in resolved_file.parents
                ):
                    continue
                line_iter = _iter_bounded_lines(
                    resolved_file,
                    deadline=deadline,
                    timeout_message="grep_repo timed out",
                )
            except Exception:
                continue
            for lineno, line in line_iter:
                self._check_deadline(deadline, "grep_repo timed out")
                if pattern not in line:
                    continue
                self._check_deadline(deadline, "grep_repo timed out")
                sanitized = sanitize_source(line, file_path=rel).strip()
                hits.append(f"{rel}:{lineno}:{sanitized}")
                if len(hits) >= 30:
                    return "\n".join(hits)
        return "\n".join(hits)

    def _entry_lines(
        self,
        entry,
        *,
        start_line: int | None = None,
        end_line: int | None = None,
        deadline: float | None = None,
        max_chars: int | None = None,
        timeout_message: str = "tool timed out",
    ) -> str:
        try:
            target = self._resolve_index_file(str(entry.file))
        except ValueError:
            return ""
        if not target.is_file():
            return ""
        start = int(start_line or entry.start_line)
        end = int(end_line or entry.end_line)
        if end < start:
            return ""
        limit = max_chars if max_chars is not None else self.max_chars
        lines: list[str] = []
        total_chars = 0
        for lineno, line in enumerate(
            self._read_file_text(target).splitlines(), start=1
        ):
            self._check_deadline(deadline, timeout_message)
            if lineno > end:
                break
            if lineno < start:
                continue
            self._check_deadline(deadline, timeout_message)
            remaining = max(0, limit - total_chars)
            if remaining == 0:
                break
            if len(line) > remaining:
                lines.append(line[:remaining])
                break
            lines.append(line)
            total_chars += len(line) + 1
        return "\n".join(lines)

    def _read_file_text(self, path: Path) -> str:
        key = str(path)
        cached = self._file_text_cache.get(key)
        if cached is not None:
            return cached
        text = path.read_text(encoding="utf-8", errors="ignore")
        self._file_text_cache[key] = text
        return text

    def _resolve_index_file(self, raw_path: str) -> Path:
        raw = Path(raw_path)
        if raw.is_absolute():
            candidate = raw.resolve()
        else:
            if ".." in raw.parts:
                raise ValueError("Parent traversal is not allowed")
            candidate = (self.codebase_path / raw_path).resolve()
        if (
            candidate != self.codebase_path
            and self.codebase_path not in candidate.parents
        ):
            raise ValueError("Path escapes codebase")
        return candidate

    def _deadline(self) -> float:
        return time.monotonic() + max(0.001, float(self.timeout_seconds))

    @staticmethod
    def _check_deadline(deadline: float | None, message: str) -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError(message)


def _iter_bounded_lines(
    file_path: Path,
    *,
    deadline: float | None = None,
    timeout_message: str = "tool timed out",
):
    with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
        lineno = 1
        while True:
            if deadline is not None and time.monotonic() > deadline:
                raise TimeoutError(timeout_message)
            line = handle.readline(_GREP_REPO_MAX_LINE_CHARS + 1)
            if line == "":
                break
            truncated = len(line) > _GREP_REPO_MAX_LINE_CHARS
            if truncated:
                line = line[:_GREP_REPO_MAX_LINE_CHARS]
                while True:
                    if deadline is not None and time.monotonic() > deadline:
                        raise TimeoutError(timeout_message)
                    rest = handle.readline(_GREP_REPO_MAX_LINE_CHARS + 1)
                    if rest == "" or rest.endswith("\n"):
                        break
            yield lineno, line.rstrip("\n")
            lineno += 1
