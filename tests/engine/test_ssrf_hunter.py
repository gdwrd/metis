# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil

from metis.engine.research import HypothesisStatus, ResearchOptions


FIXTURE = "tests/fixtures/research/ssrf_app"


def test_ssrf_hunter_proves_kills_and_leaves_unresolved(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(repo, options=ResearchOptions(hunters=("ssrf",)))

    assert len(result.generated) == 3
    assert result.metric_summary["ssrf"]["generated"] == 3
    assert result.metric_summary["ssrf"]["proven"] == 1
    assert result.metric_summary["ssrf"]["killed"] == 1
    assert result.metric_summary["ssrf"]["unresolved"] == 1
    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    proven = by_symbol["fetch_url"]
    assert proven.status == HypothesisStatus.PROVEN
    assert proven.vulnerability_class == "CWE-918"
    assert proven.missing_guard == "network allowlist"
    assert {entry.obligation for entry in proven.evidence} == {
        "source",
        "reachability",
        "network_sink",
        "missing_network_allowlist",
        "impact",
    }

    killed = by_symbol["fetch_allowlisted_url"]
    assert killed.status == HypothesisStatus.KILLED
    assert killed.observed_guard == "allowlist_url"
    assert "allowlist_url is present" in str(killed.kill_reason)

    unresolved = by_symbol["fetch_internal_status"]
    assert unresolved.status == HypothesisStatus.UNRESOLVED
    assert unresolved.unresolved_reason == "No attacker-controlled source evidence"
