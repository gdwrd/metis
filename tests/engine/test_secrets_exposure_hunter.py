# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HunterRegistry, HypothesisStatus, ResearchOptions


def test_secrets_exposure_hunter_is_available_but_experimental():
    metadata = HunterRegistry.default().metadata_for("secrets_exposure")

    assert metadata.vulnerability_class == "CWE-798"
    assert metadata.rule_families == ("secrets_exposure",)
    assert metadata.default_enabled is False
    assert metadata.experimental is True
    assert metadata.promotion_status == "experimental"
    assert metadata.promotion_skip_reason is not None
    assert "terraform" in metadata.supported_languages


def test_secrets_exposure_hunter_reports_config_fixture_paths(engine):
    repo = "tests/benchmarks/cases/research/secrets_exposure"
    engine.codebase_path = repo
    engine._config.codebase_path = repo

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("secrets_exposure",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["aws_ssm_parameter.secret_token"].status == HypothesisStatus.PROVEN
    assert by_symbol["aws_ssm_parameter.vaulted_token"].status == HypothesisStatus.KILLED
    assert by_symbol["secrets.json"].status == HypothesisStatus.PROVEN
    assert by_symbol["safe-secrets.json"].status == HypothesisStatus.KILLED
