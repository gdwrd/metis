# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.research.hunters import AuthzOutlierHunter, HunterRegistry


def test_hunter_registry_exposes_default_phase3_hunters():
    registry = HunterRegistry.default()

    assert registry.available_names() == (
        "authz_outlier",
        "deserialization",
        "hardware_security",
        "injection_path",
        "memory_lifetime",
        "path_traversal",
        "sql_injection",
        "ssrf",
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
