# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

MAX_CONTEXT_CHARS = 24000


@dataclass(frozen=True, slots=True)
class LoadedContext:
    status: str
    path: Path
    text: str = ""
    message: str = ""
    truncated: bool = False


class ContextLoader:
    def __init__(
        self, codebase_path: str | Path, *, max_chars: int = MAX_CONTEXT_CHARS
    ):
        self.codebase_path = Path(codebase_path).resolve()
        self.max_chars = max_chars
        self.path = self.codebase_path / "CONTEXT.md"

    def load(self) -> LoadedContext:
        if not self.path.exists():
            return LoadedContext("missing", self.path, message="CONTEXT.md not found")
        try:
            resolved = self.path.resolve(strict=True)
            if (
                resolved != self.codebase_path
                and self.codebase_path not in resolved.parents
            ):
                return LoadedContext(
                    "error",
                    self.path,
                    message="CONTEXT.md symlink escapes codebase",
                )
            text = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return LoadedContext("error", self.path, message=str(exc))
        truncated = len(text) > self.max_chars
        if truncated:
            text = text[: self.max_chars] + "\n\n[CONTEXT.md truncated for TUI chat]"
        return LoadedContext(
            "loaded",
            self.path,
            text=text,
            message=f"Loaded {self.path.name}",
            truncated=truncated,
        )


def _safe_iter(root: Path):
    ignored = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
    for path in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if path.name in ignored:
            continue
        yield path


def generate_context_document(
    codebase_path: str | Path, *, max_chars: int = MAX_CONTEXT_CHARS
) -> str:
    root = Path(codebase_path).resolve()
    top_level = []
    key_files = []
    for path in _safe_iter(root):
        if path.is_dir():
            top_level.append(f"- `{path.name}/`")
        elif path.name in {
            "pyproject.toml",
            "README.md",
            "metis.yaml",
            "metis.yml",
            "plugins.yaml",
        }:
            key_files.append(f"- `{path.name}`")

    src_modules = []
    src_root = root / "src"
    if src_root.exists():
        for path in sorted(src_root.rglob("*.py"))[:40]:
            try:
                src_modules.append(f"- `{path.relative_to(root).as_posix()}`")
            except ValueError:
                continue

    lines = [
        "# Metis Project Context",
        "",
        "## Purpose",
        "Metis is an AI-assisted security review and SARIF triage tool for source repositories.",
        "",
        "## Structure",
        *(top_level or ["- No top-level entries found."]),
        "",
        "## Key Files",
        *(key_files or ["- No common project metadata files found."]),
        "",
        "## Key Modules",
        *(src_modules or ["- No Python source modules found under `src/`."]),
        "",
        "## Common Commands",
        "- `uv run metis --help`",
        "- `uv run metis tui --codebase-path .`",
        "- `uv run pytest`",
        "",
        "## TUI Notes",
        "The TUI loads this file at startup and includes it as compact repository context in normal chat prompts.",
    ]
    text = "\n".join(lines).strip() + "\n"
    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + "\n\n[Truncated to TUI context cap]\n"
    return text


def write_context_document(
    codebase_path: str | Path, *, max_chars: int = MAX_CONTEXT_CHARS
) -> Path:
    root = Path(codebase_path).resolve()
    path = root / "CONTEXT.md"
    text = generate_context_document(root, max_chars=max_chars)
    temp_path: Path | None = None
    try:
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=root,
            prefix=".CONTEXT.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(text)
        temp_path.replace(path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
    return path
