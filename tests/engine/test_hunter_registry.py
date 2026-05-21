# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.research.hunters import AuthzOutlierHunter, HunterRegistry


def test_hunter_registry_exposes_research_hunters():
    registry = HunterRegistry.default()

    assert registry.available_names() == (
        "authz_outlier",
        "code_injection",
        "command_injection",
        "crypto_misuse",
        "deserialization",
        "evm_external_call",
        "hardware_security",
        "iac_exposure",
        "injection_path",
        "memory_lifetime",
        "nosql_injection",
        "path_traversal",
        "secrets_exposure",
        "sql_injection",
        "ssrf",
        "template_injection",
        "xss",
        "xxe",
    )
    metadata = registry.metadata_for("injection_path")
    assert metadata.name == "injection_path"
    assert metadata.vulnerability_class == "CWE-74"
    assert metadata.evidence_obligations == (
        "source",
        "reachability",
        "sink",
        "missing_sanitizer",
        "impact",
    )
    sql_metadata = registry.metadata_for("sql_injection")
    assert sql_metadata.vulnerability_class == "CWE-89"
    assert sql_metadata.evidence_obligations == (
        "source",
        "reachability",
        "sql_sink",
        "missing_parameterization",
        "impact",
    )
    command_metadata = registry.metadata_for("command_injection")
    assert command_metadata.vulnerability_class == "CWE-78"
    assert command_metadata.rule_families == ("command_injection",)
    assert command_metadata.default_enabled is True
    assert command_metadata.experimental is False
    assert "python" in command_metadata.supported_languages

    promoted_metadata = registry.metadata_for("xss")
    assert promoted_metadata.default_enabled is True
    assert promoted_metadata.experimental is False
    assert promoted_metadata.promotion_status == "promoted"
    assert promoted_metadata.promotion_criteria == (
        "at least two language fixtures",
        "at least one killed or sanitized fixture",
        "class-specific SARIF rule ID",
        "acceptable quick-benchmark false-positive rate",
    )

    secrets_metadata = registry.metadata_for("secrets_exposure")
    assert secrets_metadata.default_enabled is False
    assert secrets_metadata.experimental is True
    assert secrets_metadata.promotion_status == "experimental"
    assert secrets_metadata.promotion_skip_reason is not None

    authz_metadata = registry.metadata_for("authz_outlier")
    assert authz_metadata.default_enabled is True

    memory_metadata = registry.metadata_for("memory_lifetime")
    assert memory_metadata.default_enabled is True
    assert memory_metadata.rule_families == ("memory_lifetime",)

    hardware_metadata = registry.metadata_for("hardware_security")
    assert hardware_metadata.default_enabled is True
    assert hardware_metadata.rule_families == ("hardware_security",)


def test_hunter_registry_selects_requested_hunters_in_request_order():
    registry = HunterRegistry.default()

    selected = registry.select(("ssrf", "authz_outlier"))

    assert [hunter.name for hunter in selected] == ["ssrf", "authz_outlier"]


def test_hunter_registry_rejects_unknown_hunter():
    registry = HunterRegistry.default()

    with pytest.raises(ValueError, match="Unknown research hunter: missing"):
        registry.select(("missing",))


def test_hunter_registry_rejects_duplicate_names():
    with pytest.raises(ValueError, match="Duplicate research hunter: authz_outlier"):
        HunterRegistry((AuthzOutlierHunter(), AuthzOutlierHunter()))
