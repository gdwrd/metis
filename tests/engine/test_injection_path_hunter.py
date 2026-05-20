# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil

from metis.engine.research import HypothesisStatus, ResearchOptions


FIXTURE = "tests/fixtures/research/injection_path_app"


def test_injection_path_hunter_proves_kills_and_leaves_unresolved(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(repo, options=ResearchOptions(hunters=("injection_path",)))

    assert len(result.generated) == 11
    assert result.metric_summary["selected_hunters"] == ("injection_path",)
    assert "injection_path" in result.metric_summary["available_hunters"]
    assert result.metric_summary["injection_path"]["generated"] == 11
    assert result.metric_summary["injection_path"]["proven"] == 6
    assert result.metric_summary["injection_path"]["killed"] == 4
    assert result.metric_summary["injection_path"]["unresolved"] == 1
    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["run_command"].status == HypothesisStatus.PROVEN
    assert by_symbol["run_command"].vulnerability_class == "CWE-74"
    assert by_symbol["run_command"].missing_guard == "sanitizer or parameterization"
    assert {entry.obligation for entry in by_symbol["run_command"].evidence} == {
        "source",
        "reachability",
        "sink",
        "missing_sanitizer",
        "impact",
    }
    assert by_symbol["run_command"].observed_guard is None

    extra_source = by_symbol["run_command_with_extra_source"]
    assert extra_source.status == HypothesisStatus.PROVEN
    assert extra_source.source == "request.args.get"
    assert "run_constant_after_source" not in by_symbol

    check_output = by_symbol["run_check_output_command"]
    assert check_output.status == HypothesisStatus.PROVEN
    assert check_output.sink == "check_output"

    direct_call = by_symbol["run_helper_command"]
    assert direct_call.status == HypothesisStatus.PROVEN
    assert [step.symbol for step in direct_call.locations] == [
        "run_helper_command",
        "command_sink",
    ]
    assert any(
        "flows into a direct call to sink function command_sink" in entry.claim
        for entry in direct_call.evidence
        if entry.obligation == "reachability"
    )
    assert "run_helper_with_constant" not in by_symbol
    assert "run_helper_after_overwrite" not in by_symbol

    killed = by_symbol["run_validated_command"]
    assert killed.status == HypothesisStatus.KILLED
    assert killed.observed_guard == "validate_command"
    assert "validate_command is present" in str(killed.kill_reason)

    later_mitigation = by_symbol["run_validated_after_unrelated_sanitizer"]
    assert later_mitigation.status == HypothesisStatus.KILLED
    assert later_mitigation.observed_guard == "validate_command"

    direct_killed = by_symbol["run_helper_sanitized"]
    assert direct_killed.status == HypothesisStatus.KILLED
    assert direct_killed.observed_guard == "validate_command"
    assert [step.symbol for step in direct_killed.locations] == [
        "run_helper_sanitized",
        "command_sink",
    ]

    callee_killed = by_symbol["run_helper_with_internal_sanitizer"]
    assert callee_killed.status == HypothesisStatus.KILLED
    assert callee_killed.observed_guard == "validate_command"
    assert [step.symbol for step in callee_killed.locations] == [
        "run_helper_with_internal_sanitizer",
        "sanitizing_command_sink",
    ]

    partial = by_symbol["run_conditionally_validated_command"]
    assert partial.status == HypothesisStatus.PROVEN
    assert partial.observed_guard is None
    assert partial.missing_guard == "sanitizer or parameterization"

    overwritten = by_symbol["run_validated_command_overwritten"]
    assert overwritten.status == HypothesisStatus.PROVEN
    assert overwritten.observed_guard is None
    assert overwritten.missing_guard == "sanitizer or parameterization"

    unresolved = by_symbol["run_default_command"]
    assert unresolved.status == HypothesisStatus.UNRESOLVED
    assert unresolved.unresolved_reason == "No attacker-controlled source evidence"

    for hypothesis in result.generated:
        assert {item.name for item in hypothesis.evidence_obligations} == {
            entry.obligation for entry in hypothesis.evidence
        }
