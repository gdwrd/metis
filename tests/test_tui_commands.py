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
