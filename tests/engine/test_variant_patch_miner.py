# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil

import pytest

from metis.engine.research import HypothesisStatus, ResearchOptions
from metis.engine.research.variants import PatchVariantMiner


FIXTURE = "tests/fixtures/research/variant_authz_app"


def test_patch_variant_miner_finds_authz_sibling_and_kills_fixed_route(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    graph = engine.research.security_graph.load_or_build(repo, rebuild=True)
    mined = PatchVariantMiner().mine(
        repo,
        security_graph=graph,
        from_fix=repo / "fix_get_project.patch",
    )
    verified = engine.research.verifier.verify_all(mined.hypotheses)

    assert len(mined.patterns) == 1
    pattern = mined.patterns[0]
    assert pattern.fixed_guard == "require_project_member"
    assert pattern.changed_route_access_policy == ["/projects/<project_id>"]
    assert pattern.search_predicates == [
        "file:app.py",
        "route_group:projects",
        "missing_guard:require_project_member",
    ]

    assert {item.status for item in verified} == {
        HypothesisStatus.PROVEN,
        HypothesisStatus.KILLED,
    }
    proven = [item for item in verified if item.status == HypothesisStatus.PROVEN][0]
    killed = [item for item in verified if item.status == HypothesisStatus.KILLED][0]

    assert proven.hunter == "variant_patch"
    assert proven.locations[0].symbol == "update_project_settings"
    assert proven.missing_guard == "require_project_member"
    assert {entry.obligation for entry in proven.evidence} == {
        "source",
        "reachability",
        "asset",
        "missing_guard",
        "impact",
    }

    assert killed.locations[0].symbol == "get_project"
    assert killed.kill_reason == (
        "Candidate invalidated by evidence: Fix-derived guard "
        "require_project_member is present at the original location."
    )


def test_research_service_runs_variants_through_verifier_and_persists(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    result = engine.research.run_variants(
        repo,
        from_fix=repo / "fix_get_project.patch",
        options=ResearchOptions(persist=True, emit_killed=True),
    )

    assert [item.status for item in result.proven] == [HypothesisStatus.PROVEN]
    assert [item.status for item in result.killed] == [HypothesisStatus.KILLED]
    assert result.hypotheses_path.endswith(".metis/research/hypotheses.jsonl")
    assert result.evidence_ledger_path.endswith(".metis/research/evidence.jsonl")
    assert result.sarif_path.endswith(".metis/research/results.sarif")
    assert (tmp_path / ".metis" / "research" / "hypotheses.jsonl").exists()
    assert len(result.metric_summary["variant_patterns"]) == 1


@pytest.mark.parametrize(
    ("patch_name", "obligation", "vulnerability_class", "proven_symbol"),
    [
        (
            "fix_store_project_name.patch",
            "missing_sanitizer",
            "CWE-20",
            "store_project_description",
        ),
        (
            "fix_set_quota_limit.patch",
            "missing_bounds_check",
            "CWE-129",
            "set_quota_default",
        ),
        (
            "fix_update_debug_state.patch",
            "missing_invariant",
            "CWE-664",
            "update_debug_shadow",
        ),
    ],
)
def test_patch_variant_miner_finds_non_guard_siblings(
    engine,
    tmp_path,
    patch_name,
    obligation,
    vulnerability_class,
    proven_symbol,
):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    graph = engine.research.security_graph.load_or_build(repo, rebuild=True)
    mined = PatchVariantMiner().mine(
        repo,
        security_graph=graph,
        from_fix=repo / patch_name,
    )
    verified = engine.research.verifier.verify_all(mined.hypotheses)

    assert len(mined.patterns) == 1
    assert mined.patterns[0].vulnerability_class == vulnerability_class
    assert mined.patterns[0].search_predicates[0] == "file:app.py"
    assert mined.patterns[0].search_predicates[2].startswith("symbol_prefix:")

    proven = [item for item in verified if item.status == HypothesisStatus.PROVEN]
    killed = [item for item in verified if item.status == HypothesisStatus.KILLED]

    assert [item.locations[0].symbol for item in proven] == [proven_symbol]
    assert len(killed) == 1
    assert obligation in {entry.obligation for entry in proven[0].evidence}
    assert obligation in {entry.obligation for entry in killed[0].evidence}


def test_patch_variant_miner_records_changed_sinks_for_invariant_fix(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    graph = engine.research.security_graph.load_or_build(repo, rebuild=True)
    mined = PatchVariantMiner().mine(
        repo,
        security_graph=graph,
        from_fix=repo / "fix_update_debug_state.patch",
    )

    assert mined.patterns[0].changed_sinks == ["debug_enable"]


def test_research_service_rejects_unreadable_variant_fix(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    with pytest.raises(ValueError, match="Unable to read fix patch"):
        engine.research.run_variants(
            repo,
            from_fix=repo / "missing.patch",
            options=ResearchOptions(persist=False),
        )


def test_research_service_requires_variant_source(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    with pytest.raises(
        ValueError,
        match="one of from_fix, from_sarif, or from_report is required",
    ):
        engine.research.run_variants(
            repo,
            options=ResearchOptions(persist=False),
        )


def test_patch_variant_miner_rejects_malformed_sarif(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    bad_sarif = repo / "bad.sarif"
    bad_sarif.write_text("{not-json", encoding="utf-8")
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    graph = engine.research.security_graph.load_or_build(repo, rebuild=True)
    with pytest.raises(ValueError, match="Invalid SARIF JSON"):
        PatchVariantMiner().mine(
            repo,
            security_graph=graph,
            from_sarif=bad_sarif,
        )
