# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, cast

from metis.engine.tools.registry import build_toolbox

from .commands import TuiCommandName, TuiCommandRequest

WRITE_LIKE_TOOLS = {
    "write",
    "edit",
    "patch",
    "delete",
    "move",
    "mkdir",
    "touch",
    "shell",
    "bash",
    "exec",
}
READ_ONLY_TOOLS = {
    "cat",
    "file_slice",
    "find_file",
    "find_name",
    "grep",
    "list_dir",
    "project_tree",
    "read_file",
    "search_text",
    "sed",
}
DOMAIN_TOOLS = {
    "index",
    "review_code",
    "review_file",
    "review_patch",
    "triage",
    "security_report",
}
IGNORED_TREE_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}


class TuiAgentToolPolicy:
    def __init__(self, codebase_path: str | Path):
        self.codebase_path = Path(codebase_path).resolve()

    def validate_tool(self, name: str) -> None:
        if name in WRITE_LIKE_TOOLS:
            raise ValueError(f"Tool is not allowed in TUI chat: {name}")
        if name not in READ_ONLY_TOOLS and name not in DOMAIN_TOOLS:
            raise ValueError(f"Unknown TUI agent tool: {name}")

    def validate_path(self, raw_path: str) -> Path:
        raw = Path(raw_path)
        if raw.is_absolute():
            raise ValueError("Absolute paths are not allowed for agent tools")
        if ".." in raw.parts:
            raise ValueError("Parent traversal is not allowed for agent tools")
        resolved = (self.codebase_path / raw).resolve()
        if (
            resolved != self.codebase_path
            and self.codebase_path not in resolved.parents
        ):
            raise ValueError("Path escapes codebase")
        return resolved

    def validate_args(self, name: str, args: dict[str, Any]) -> None:
        self.validate_tool(name)
        if name in DOMAIN_TOOLS:
            self._validate_domain_args(name, args)
            return
        if name in {
            "cat",
            "file_slice",
            "grep",
            "list_dir",
            "project_tree",
            "read_file",
            "search_text",
            "sed",
        }:
            path = args.get("path")
            if path is None and name in {"list_dir", "project_tree", "search_text"}:
                path = "."
            if not isinstance(path, str) or not path:
                raise ValueError(f"{name} requires a relative path")
            self.validate_path(path)
        if name in {"grep", "search_text"}:
            pattern = args.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                raise ValueError(f"{name} requires a pattern")
        if name in {"find_file", "find_name"}:
            file_name = args.get("name")
            if not isinstance(file_name, str) or not file_name:
                raise ValueError(f"{name} requires a name")
        if name in {"file_slice", "sed"}:
            if "start_line" not in args or "end_line" not in args:
                raise ValueError(f"{name} requires start_line and end_line")

    def validate_output_path(self, raw_path: str) -> Path:
        target = self.validate_path(raw_path)
        self._validate_results_output_path(target)
        if target.suffix.lower() != ".sarif":
            raise ValueError("Domain output_file must use a .sarif extension")
        return target

    def validate_report_output_path(self, raw_path: str) -> Path:
        target = self.validate_path(raw_path)
        self._validate_results_output_path(target)
        if target.suffix.lower() not in {".md", ".markdown"}:
            raise ValueError("Security report output_file must use a .md extension")
        return target

    def _validate_results_output_path(self, target: Path) -> None:
        try:
            relative = target.relative_to(self.codebase_path)
        except ValueError as exc:
            raise ValueError("Domain output_file must stay inside codebase") from exc
        if not relative.parts or relative.parts[0] != "results":
            raise ValueError("Domain output_file must be under results/")

    def _validate_domain_args(self, name: str, args: dict[str, Any]) -> None:
        if name in {"review_file", "review_patch"}:
            path = args.get("path")
            if not isinstance(path, str) or not path:
                raise ValueError(f"{name} requires path")
            self.validate_path(path)
        if name in {"triage", "security_report"}:
            path = args.get("path") or args.get("sarif_path")
            if path is not None:
                if not isinstance(path, str) or not path:
                    raise ValueError(f"{name} path must be a relative path")
                self.validate_path(path)
        if "output_file" in args:
            output_file = args.get("output_file")
            if not isinstance(output_file, str) or not output_file:
                raise ValueError("output_file must be a relative output path")
            if name == "security_report":
                self.validate_report_output_path(output_file)
            else:
                self.validate_output_path(output_file)
        if "use_retrieval_context" in args and not isinstance(
            args["use_retrieval_context"], bool
        ):
            raise ValueError("use_retrieval_context must be a boolean")


class TuiAgentToolRunner:
    def __init__(self, codebase_path: str | Path, *, domain_runner: Any | None = None):
        self.codebase_path = Path(codebase_path).resolve()
        self.domain_runner = domain_runner
        self.policy = TuiAgentToolPolicy(self.codebase_path)
        self.toolbox = build_toolbox(
            policy="triage_evidence", codebase_path=str(self.codebase_path)
        )

    def instructions(self) -> str:
        return "\n".join(
            (
                f"Filesystem tools are read-only and rooted at: {self.codebase_path}",
                "Use them when you need to inspect the launched project before answering.",
                "Return only JSON when calling tools, for example:",
                '{"tool_calls":[{"name":"project_tree","arguments":{"path":".","max_depth":2}},{"name":"read_file","arguments":{"path":"README.md"}}]}',
                "Available tools:",
                "- project_tree(path='.', max_depth=2, max_entries=200): directory tree for project structure.",
                "- list_dir(path='.', max_entries=100): immediate files and directories.",
                "- read_file(path): read a text file.",
                "- file_slice(path, start_line, end_line): read a line range.",
                "- search_text(pattern, path='.'): search text in the project.",
                "- find_file(name, max_results=20): find files by basename.",
                "",
                "Controlled Metis execution tools are available when the user asks you to run a workflow.",
                "These tools run inside Metis and may create SARIF artifacts; do not call shell commands.",
                "For whole-flow requests such as 'run everything', 'full flow', 'full review', 'full scan', or 'end-to-end', call one ordered tool_calls array with index first, review_code second, triage third, and security_report fourth.",
                "- review_code(output_file='results/review.sarif', use_retrieval_context=true): review the launched project; SARIF is saved by default even when output_file is omitted.",
                "- review_file(path, output_file='results/review.sarif', use_retrieval_context=true): review one relative project file.",
                "- review_patch(path, output_file='results/review.sarif', use_retrieval_context=true): review one relative patch file.",
                "- triage(path='results/review.sarif', output_file='results/triage.sarif', use_retrieval_context=true): triage SARIF; path is optional after a review.",
                "- security_report(path='results/triage.sarif', output_file='results/security-report.md'): review triage SARIF with AI chat and save a Markdown security report with scored attack chains and non-destructive PoCs.",
                "- index(): build retrieval context for the launched project.",
                "Do not claim you inspected files unless a tool result confirms it.",
            )
        )

    def run(self, name: str, **kwargs: Any) -> Any:
        self.policy.validate_args(name, kwargs)
        if name in DOMAIN_TOOLS:
            return self._run_domain_tool(name, **kwargs)
        if name == "list_dir":
            return self.list_dir(
                path=str(kwargs.get("path") or "."),
                max_entries=int(kwargs.get("max_entries") or 100),
            )
        if name == "project_tree":
            return self.project_tree(
                path=str(kwargs.get("path") or "."),
                max_depth=int(kwargs.get("max_depth") or 2),
                max_entries=int(kwargs.get("max_entries") or 200),
            )
        if name == "read_file":
            return self.toolbox.run("cat", path=kwargs["path"])
        if name == "file_slice":
            return self.toolbox.run(
                "sed",
                path=kwargs["path"],
                start_line=int(kwargs["start_line"]),
                end_line=int(kwargs["end_line"]),
            )
        if name == "search_text":
            return self.toolbox.run(
                "grep",
                pattern=kwargs["pattern"],
                path=str(kwargs.get("path") or "."),
            )
        if name == "find_file":
            return self.toolbox.find_name(
                kwargs["name"], max_results=int(kwargs.get("max_results") or 20)
            )
        return self.toolbox.run(name, **kwargs)

    def _run_domain_tool(self, name: str, **kwargs: Any) -> str:
        if self.domain_runner is None:
            raise ValueError("Metis domain tools are unavailable in this chat session")
        request = self._domain_request(name, kwargs)
        self.domain_runner.execute(request)

        produced = self._produced_artifact_path(name)
        output_file = kwargs.get("output_file")
        copied_to: Path | None = None
        if output_file is not None and produced is not None:
            if name == "security_report":
                copied_to = self.policy.validate_report_output_path(str(output_file))
            else:
                copied_to = self.policy.validate_output_path(str(output_file))
            copied_to.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(produced, copied_to)

        lines = [f"/{name} finished"]
        if produced is not None:
            if name == "security_report":
                lines.append(f"default_report={produced}")
            else:
                lines.append(f"default_sarif={produced}")
        if copied_to is not None:
            lines.append(f"output_file={copied_to}")
        log_path = self._latest_command_log_path()
        if log_path is not None:
            lines.append(f"log_file={log_path}")
            log_tail = self._command_log_tail(log_path, limit=100)
            if log_tail:
                lines.append("log_tail:")
                lines.extend(log_tail)
        return "\n".join(lines)

    def _latest_command_log_path(self) -> Path | None:
        artifacts = getattr(self.domain_runner, "artifacts", None)
        manifest = getattr(artifacts, "manifest", None)
        if not isinstance(manifest, dict):
            return None
        commands = manifest.get("commands")
        if not isinstance(commands, list) or not commands:
            return None
        latest = commands[-1]
        if not isinstance(latest, dict):
            return None
        log_path = latest.get("log")
        if not isinstance(log_path, str) or not log_path:
            return None
        path = Path(log_path)
        return path if path.is_file() else None

    def _command_log_tail(self, path: Path, *, limit: int) -> list[str]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        output: list[str] = []
        for line in lines[-limit:]:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                output.append(line)
                continue
            event_type = str(event.get("type") or "event")
            message = str(event.get("message") or "")
            output.append(f"{event_type}: {message}".strip())
        return output

    def _domain_request(self, name: str, kwargs: dict[str, Any]) -> TuiCommandRequest:
        args: list[str] = []
        if name in {"review_file", "review_patch"}:
            args.append(str(self.policy.validate_path(str(kwargs["path"]))))
        elif name in {"triage", "security_report"}:
            path = kwargs.get("path") or kwargs.get("sarif_path")
            if path:
                args.append(str(self.policy.validate_path(str(path))))
        use_retrieval_context = bool(kwargs.get("use_retrieval_context", True))
        return TuiCommandRequest(
            name=cast(TuiCommandName, name),
            args=tuple(args),
            raw=f"/{name}" + (f" {' '.join(args)}" if args else ""),
            use_retrieval_context=use_retrieval_context,
        )

    def _produced_artifact_path(self, name: str) -> Path | None:
        artifacts = getattr(self.domain_runner, "artifacts", None)
        paths = getattr(artifacts, "paths", None)
        if name in {"review_code", "review_file", "review_patch"}:
            path = getattr(paths, "review_sarif", None)
        elif name == "triage":
            path = getattr(paths, "triage_sarif", None)
        elif name == "security_report":
            path = getattr(paths, "security_report", None)
        else:
            path = None
        if path is None:
            return None
        return Path(path)

    def list_dir(self, *, path: str = ".", max_entries: int = 100) -> str:
        target = self.policy.validate_path(path)
        if not target.exists():
            raise FileNotFoundError(path)
        if not target.is_dir():
            raise NotADirectoryError(path)
        lines: list[str] = []
        for item in sorted(target.iterdir(), key=lambda entry: entry.name.lower()):
            if not self._is_within_codebase(item):
                continue
            rel = item.relative_to(self.codebase_path).as_posix()
            suffix = "/" if item.is_dir() else ""
            size = "" if item.is_dir() else f" {item.stat().st_size} bytes"
            lines.append(f"{rel}{suffix}{size}")
            if len(lines) >= max_entries:
                lines.append("...[truncated]")
                break
        return "\n".join(lines)

    def project_tree(
        self, *, path: str = ".", max_depth: int = 2, max_entries: int = 200
    ) -> str:
        root = self.policy.validate_path(path)
        if not root.exists():
            raise FileNotFoundError(path)
        if root.is_file():
            return root.relative_to(self.codebase_path).as_posix()

        entries = 0
        lines = [root.relative_to(self.codebase_path).as_posix() or "."]

        def walk(directory: Path, depth: int, prefix: str) -> None:
            nonlocal entries
            if depth >= max_depth or entries >= max_entries:
                return
            children = [
                child
                for child in sorted(
                    directory.iterdir(),
                    key=lambda entry: entry.name.lower(),
                )
                if child.name not in IGNORED_TREE_DIRS
                and self._is_within_codebase(child)
            ]
            for index, child in enumerate(children):
                if entries >= max_entries:
                    lines.append(f"{prefix}...[truncated]")
                    return
                connector = "`-- " if index == len(children) - 1 else "|-- "
                next_prefix = "    " if index == len(children) - 1 else "|   "
                marker = "/" if child.is_dir() else ""
                lines.append(f"{prefix}{connector}{child.name}{marker}")
                entries += 1
                if child.is_dir():
                    walk(child, depth + 1, prefix + next_prefix)

        walk(root, 0, "")
        return "\n".join(lines)

    def _is_within_codebase(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except Exception:
            return False
        return resolved == self.codebase_path or self.codebase_path in resolved.parents
