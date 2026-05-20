# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from metis.cli.command_registry import COMMANDS

TuiCommandName = Literal[
    "index",
    "review_code",
    "review_file",
    "review_patch",
    "research",
    "triage",
    "security_report",
    "init",
    "status",
    "help",
    "exit",
]

TUI_COMMANDS: tuple[TuiCommandName, ...] = (
    "index",
    "review_code",
    "review_file",
    "review_patch",
    "research",
    "triage",
    "security_report",
    "init",
    "status",
    "help",
    "exit",
)
DOMAIN_COMMANDS: tuple[TuiCommandName, ...] = (
    "index",
    "review_code",
    "review_file",
    "review_patch",
    "research",
    "triage",
    "security_report",
    "init",
)

COMMAND_COMPLETION_HINTS: dict[TuiCommandName, str] = {
    "index": "index the current project",
    "review_code": "review the current project",
    "review_file": "review one file",
    "review_patch": "review a patch file",
    "research": "run research and write report",
    "triage": "triage review SARIF",
    "security_report": "write an attack-chain report",
    "init": "write project context",
    "status": "show provider and tool status",
    "help": "show commands",
    "exit": "close the TUI",
}

COMMAND_COMPLETION_INSERTS: dict[TuiCommandName, str] = {
    "review_file": "/review_file ",
    "review_patch": "/review_patch ",
    "triage": "/triage ",
    "security_report": "/security_report ",
}


@dataclass(frozen=True, slots=True)
class TuiCommandRequest:
    name: TuiCommandName
    args: tuple[str, ...] = ()
    raw: str = ""
    use_retrieval_context: bool = True

    @property
    def target_path(self) -> Path | None:
        if self.name not in {
            "review_file",
            "review_patch",
            "triage",
            "security_report",
        }:
            return None
        if not self.args:
            return None
        return Path(self.args[0])


@dataclass(frozen=True, slots=True)
class TuiResearchCommandOptions:
    hunters: tuple[str, ...] | None = None
    rebuild: bool | None = None
    research_budget: str | None = None
    emit_killed: bool | None = None
    emit_unresolved: bool | None = None
    proof_artifacts: bool | None = None
    evidence_policy: str | None = None


def parse_slash_command(text: str) -> TuiCommandRequest:
    raw = text.strip()
    if not raw.startswith("/"):
        raise ValueError("Slash commands must start with '/'.")
    parts = shlex.split(raw[1:])
    if not parts:
        raise ValueError("Slash command is empty.")

    name = parts[0]
    if name not in TUI_COMMANDS:
        raise ValueError(f"Unknown TUI command: {name}")

    args = []
    use_retrieval_context = True
    for part in parts[1:]:
        if part == "--ignore-index":
            use_retrieval_context = False
            continue
        args.append(part)

    request = TuiCommandRequest(
        name=cast(TuiCommandName, name),
        args=tuple(args),
        raw=raw,
        use_retrieval_context=use_retrieval_context,
    )
    validate_tui_command(request)
    return request


def validate_tui_command(request: TuiCommandRequest) -> None:
    if request.name not in TUI_COMMANDS:
        raise ValueError(f"Unknown TUI command: {request.name}")
    if request.name in {"review_file", "review_patch"} and not request.args:
        raise ValueError(f"/{request.name} requires a file path.")
    if (
        request.name in {"index", "review_code", "help", "exit", "init", "status"}
        and request.args
    ):
        raise ValueError(f"/{request.name} does not accept positional arguments.")
    if request.name == "research":
        _validate_research_args(request.args)
    if not request.use_retrieval_context:
        if request.name == "security_report":
            return
        spec = COMMANDS.get(request.name)
        if spec is None or spec.index_policy != "optional":
            raise ValueError("--ignore-index is not valid for this command.")


def command_help() -> str:
    return "\n".join(
        (
            "/index",
            "/review_code [--ignore-index]",
            "/review_file PATH [--ignore-index]",
            "/review_patch PATH [--ignore-index]",
            "/research [--hunters LIST] [--rebuild] [--research-budget NAME] [--emit-killed] [--emit-unresolved] [--proof-artifacts] [--evidence-policy NAME]",
            "/triage [PATH] [--ignore-index]",
            "/security_report [PATH] [--ignore-index]",
            "/init",
            "/status",
            "/help",
            "/exit",
        )
    )


def command_completion_items(
    prefix: str,
) -> tuple[tuple[TuiCommandName, str, str], ...]:
    normalized = prefix.strip()
    if normalized.startswith("/"):
        normalized = normalized[1:]
    matches: list[tuple[TuiCommandName, str, str]] = []
    for command in TUI_COMMANDS:
        if normalized and not command.startswith(normalized):
            continue
        insert_text = COMMAND_COMPLETION_INSERTS.get(command, f"/{command}")
        hint = COMMAND_COMPLETION_HINTS[command]
        matches.append((command, insert_text, f"/{command:<16} {hint}"))
    return tuple(matches)


def _validate_research_args(args: tuple[str, ...]) -> None:
    parse_research_command_options(args)


def parse_research_command_options(args: tuple[str, ...]) -> TuiResearchCommandOptions:
    hunters: tuple[str, ...] | None = None
    rebuild: bool | None = None
    research_budget: str | None = None
    emit_killed: bool | None = None
    emit_unresolved: bool | None = None
    proof_artifacts: bool | None = None
    evidence_policy: str | None = None
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--hunters":
            raw = _research_value(args, idx, "--hunters")
            hunters = tuple(item.strip() for item in raw.split(",") if item.strip())
            if not hunters:
                raise ValueError("/research --hunters requires a comma-separated list.")
            idx += 2
            continue
        if arg == "--rebuild":
            rebuild = True
            idx += 1
            continue
        if arg == "--no-rebuild":
            rebuild = False
            idx += 1
            continue
        if arg in {"--research-budget", "--budget"}:
            research_budget = _research_value(args, idx, arg)
            idx += 2
            continue
        if arg == "--emit-killed":
            emit_killed = True
            idx += 1
            continue
        if arg == "--no-emit-killed":
            emit_killed = False
            idx += 1
            continue
        if arg == "--emit-unresolved":
            emit_unresolved = True
            idx += 1
            continue
        if arg == "--no-emit-unresolved":
            emit_unresolved = False
            idx += 1
            continue
        if arg == "--proof-artifacts":
            proof_artifacts = True
            idx += 1
            continue
        if arg == "--no-proof-artifacts":
            proof_artifacts = False
            idx += 1
            continue
        if arg == "--evidence-policy":
            evidence_policy = _research_value(args, idx, arg)
            idx += 2
            continue
        raise ValueError(f"Unsupported /research option: {arg}")
    return TuiResearchCommandOptions(
        hunters=hunters,
        rebuild=rebuild,
        research_budget=research_budget,
        emit_killed=emit_killed,
        emit_unresolved=emit_unresolved,
        proof_artifacts=proof_artifacts,
        evidence_policy=evidence_policy,
    )


def _research_value(args: tuple[str, ...], idx: int, option: str) -> str:
    if (
        idx + 1 >= len(args)
        or not args[idx + 1].strip()
        or args[idx + 1].startswith("--")
    ):
        raise ValueError(f"/research {option} requires a value.")
    return args[idx + 1].strip()
