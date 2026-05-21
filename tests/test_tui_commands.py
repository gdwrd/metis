# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.tui.commands import command_completion_items, parse_slash_command


def test_parse_slash_command_supports_allowed_domain_command():
    request = parse_slash_command('/review_file "src/a file.py" --ignore-index')

    assert request.name == "review_file"
    assert request.args == ("src/a file.py",)
    assert request.use_retrieval_context is False


def test_parse_slash_command_rejects_unknown_command():
    with pytest.raises(ValueError, match="Unknown TUI command"):
        parse_slash_command("/shell rm -rf .")


def test_parse_slash_command_requires_paths_for_path_commands():
    with pytest.raises(ValueError, match="requires a file path"):
        parse_slash_command("/review_patch")


def test_parse_slash_command_accepts_init():
    request = parse_slash_command("/init")

    assert request.name == "init"
    assert request.args == ()


def test_parse_slash_command_accepts_status():
    request = parse_slash_command("/status")

    assert request.name == "status"
    assert request.args == ()


def test_parse_slash_command_accepts_security_report_with_optional_path():
    request = parse_slash_command("/security_report results/triage.sarif")

    assert request.name == "security_report"
    assert request.args == ("results/triage.sarif",)


def test_parse_slash_command_accepts_research_hunters():
    request = parse_slash_command("/research --hunters command_injection,ssrf")

    assert request.name == "research"
    assert request.args == ("--hunters", "command_injection,ssrf")


def test_parse_slash_command_rejects_unknown_research_hunter():
    with pytest.raises(ValueError, match="Unknown research hunter: missing"):
        parse_slash_command("/research --hunters command_injection,missing")


def test_parse_slash_command_accepts_research_runtime_overrides():
    request = parse_slash_command(
        "/research --research-budget tiny --emit-killed --emit-unresolved "
        "--proof-artifacts --evidence-policy triage_evidence --rebuild"
    )

    assert request.name == "research"
    assert request.args == (
        "--research-budget",
        "tiny",
        "--emit-killed",
        "--emit-unresolved",
        "--proof-artifacts",
        "--evidence-policy",
        "triage_evidence",
        "--rebuild",
    )


def test_parse_slash_command_rejects_research_options_without_values():
    with pytest.raises(ValueError, match="--research-budget requires a value"):
        parse_slash_command("/research --research-budget")


@pytest.mark.parametrize(
    "command,option",
    (
        ("/research --hunters --rebuild", "--hunters"),
        ("/research --research-budget --emit-killed", "--research-budget"),
        ("/research --evidence-policy --proof-artifacts", "--evidence-policy"),
    ),
)
def test_parse_slash_command_rejects_research_option_tokens_as_values(
    command,
    option,
):
    with pytest.raises(ValueError, match=f"{option} requires a value"):
        parse_slash_command(command)


def test_command_completion_items_filter_slash_commands_and_preserve_path_space():
    matches = command_completion_items("/review_f")

    assert matches == (
        (
            "review_file",
            "/review_file ",
            "/review_file      review one file",
        ),
    )


def test_command_completion_items_lists_all_commands_for_slash_prefix():
    matches = command_completion_items("/")

    assert matches[0][0] == "index"
    assert any(command == "security_report" for command, _insert, _label in matches)
