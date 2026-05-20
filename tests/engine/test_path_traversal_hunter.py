# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil

from metis.engine.research import HypothesisStatus, ResearchOptions


FIXTURE = "tests/fixtures/research/path_traversal_app"


def test_path_traversal_hunter_proves_kills_and_leaves_unresolved(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(repo, options=ResearchOptions(hunters=("path_traversal",)))

    assert len(result.generated) == 3
    assert result.metric_summary["path_traversal"]["generated"] == 3
    assert result.metric_summary["path_traversal"]["proven"] == 1
    assert result.metric_summary["path_traversal"]["killed"] == 1
    assert result.metric_summary["path_traversal"]["unresolved"] == 1
    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    proven = by_symbol["read_file"]
    assert proven.status == HypothesisStatus.PROVEN
    assert proven.vulnerability_class == "CWE-22"
    assert proven.missing_guard == "canonicalization or root confinement"
    assert {entry.obligation for entry in proven.evidence} == {
        "source",
        "reachability",
        "filesystem_sink",
        "missing_canonicalization",
        "impact",
    }

    killed = by_symbol["read_safe_file"]
    assert killed.status == HypothesisStatus.KILLED
    assert killed.observed_guard == "safe_join"
    assert "safe_join is present" in str(killed.kill_reason)

    unresolved = by_symbol["read_default_file"]
    assert unresolved.status == HypothesisStatus.UNRESOLVED
    assert unresolved.unresolved_reason == "No attacker-controlled source evidence"
