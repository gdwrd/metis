# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil

from metis.engine.research import HypothesisStatus, ResearchOptions

FIXTURE = "tests/fixtures/research/hardware_security_app"


def test_hardware_security_hunter_proves_kills_and_leaves_unresolved(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("hardware_security",)),
    )

    assert result.metric_summary["selected_hunters"] == ("hardware_security",)
    assert "hardware_security" in result.metric_summary["available_hunters"]
    assert result.metric_summary["hardware_security"]["generated"] == 3
    assert result.metric_summary["hardware_security"]["proven"] == 1
    assert result.metric_summary["hardware_security"]["killed"] == 1
    assert result.metric_summary["hardware_security"]["unresolved"] == 1

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    proven = by_symbol["insecure_key_regs"]
    assert proven.status == HypothesisStatus.PROVEN
    assert proven.vulnerability_class == "CWE-1262"
    assert proven.missing_guard == "privilege, lifecycle, or lock guard"
    assert {entry.obligation for entry in proven.evidence} == {
        "source",
        "security_sensitive_write",
        "protected_state",
        "missing_hardware_guard",
        "impact",
    }

    killed = by_symbol["secure_key_regs"]
    assert killed.status == HypothesisStatus.KILLED
    assert killed.observed_guard == "privileged"
    assert "privileged" in str(killed.kill_reason)

    unresolved = by_symbol["boot_key_shadow"]
    assert unresolved.status == HypothesisStatus.UNRESOLVED
    assert unresolved.unresolved_reason == (
        "No externally controlled hardware or firmware source evidence"
    )


def test_hardware_security_hunter_does_not_emit_for_web_fixture(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree("tests/fixtures/research/authz_outlier_app", repo)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("hardware_security",)),
    )

    assert result.generated == []
