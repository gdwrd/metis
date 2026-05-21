# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HunterRegistry, HypothesisStatus, ResearchOptions


def test_evm_external_call_hunter_is_available_but_experimental():
    metadata = HunterRegistry.default().metadata_for("evm_external_call")

    assert metadata.vulnerability_class == "CWE-841"
    assert metadata.rule_families == ("evm_external_call",)
    assert metadata.default_enabled is False
    assert metadata.experimental is True
    assert metadata.promotion_status == "experimental"
    assert metadata.promotion_skip_reason is not None
    assert metadata.supported_languages == ("solidity",)


def test_evm_external_call_hunter_reports_solidity_fixture_paths(engine):
    repo = "tests/benchmarks/cases/research/evm_external_call"
    engine.codebase_path = repo
    engine._config.codebase_path = repo

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("evm_external_call",), rebuild=True),
    )

    by_symbol = {}
    for item in result.generated:
        by_symbol.setdefault(item.locations[0].symbol, []).append(item)
    assert {
        item.status for item in by_symbol["withdraw"]
    } == {HypothesisStatus.PROVEN}
    assert {
        item.status for item in by_symbol["withdrawSafe"]
    } == {HypothesisStatus.KILLED}
