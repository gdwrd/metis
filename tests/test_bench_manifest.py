# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.bench.manifest import load_manifest


def test_load_manifest_selects_quick_cases():
    manifest = load_manifest("tests/benchmarks/manifest.yaml")

    assert manifest.line_tolerance == 1
    assert [case.id for case in manifest.selected_cases(quick=True)] == [
        "internal-cwe121-001"
    ]
    assert manifest.cases[0].expected_findings[0].cwe == "CWE-121"
    assert manifest.cases[0].expected_hypotheses == ()


def test_load_manifest_parses_expected_hypotheses(tmp_path):
    path = tmp_path / "manifest.yaml"
    path.write_text(
        """
cases:
  - id: authz-001
    source: internal
    cwe: CWE-862
    language: python
    path: app
    quick: true
    expected_findings: []
    expected_hypotheses:
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: proven
        sarif_rule_id: CWE-862
        file: app.py
        symbol: update_project_settings
        line_range: [20, 22]
""",
        encoding="utf-8",
    )

    manifest = load_manifest(path)

    hypothesis = manifest.cases[0].expected_hypotheses[0]
    assert hypothesis.hunter == "authz_outlier"
    assert hypothesis.vulnerability_class == "CWE-862"
    assert hypothesis.status == "proven"
    assert hypothesis.sarif_rule_id == "CWE-862"
    assert hypothesis.line_range == (20, 22)


def test_load_manifest_parses_variant_sources(tmp_path):
    path = tmp_path / "manifest.yaml"
    path.write_text(
        """
cases:
  - id: variant-authz
    source: internal
    cwe: CWE-862
    language: python
    path: variant
    quick: true
    expected_findings: []
    variant_sources:
      from_fix: fix_get_project.patch
    expected_hypotheses:
      - hunter: variant_patch
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: update_project_settings
        line_range: [23, 23]
""",
        encoding="utf-8",
    )

    manifest = load_manifest(path)

    assert manifest.cases[0].variant_sources is not None
    assert manifest.cases[0].variant_sources.from_fix == "fix_get_project.patch"
    assert manifest.cases[0].variant_sources.from_sarif is None


def test_load_research_manifest_covers_phase6_statuses():
    manifest = load_manifest("tests/benchmarks/research-manifest.yaml")

    assert len(manifest.coverage_matrix) == 26
    assert manifest.coverage_matrix[0].language == "python"
    assert manifest.coverage_matrix[0].parser_runtime == "python"
    assert manifest.coverage_matrix[0].graph_mode == "ast"
    assert manifest.coverage_matrix[0].source_coverage == "http_route_params"
    assert manifest.coverage_matrix[0].sink_coverage == (
        "object_access_without_owner_check"
    )
    assert manifest.coverage_matrix[0].mitigation_coverage == (
        "positive_negative_unresolved"
    )
    assert manifest.coverage_matrix[0].fixture_status == "present"
    assert manifest.coverage_matrix[0].default_status == "default"
    assert manifest.coverage_matrix[0].experimental_status == "stable"
    assert [case.id for case in manifest.selected_cases(quick=True)] == [
        "internal-authz-outlier-001",
        "internal-injection-path-001",
        "internal-command-injection-001",
        "internal-command-injection-js-001",
        "internal-command-injection-php-001",
        "internal-command-injection-java-csharp-001",
        "internal-command-injection-go-ruby-bash-001",
        "internal-code-injection-001",
        "internal-code-injection-js-php-ruby-001",
        "internal-sql-injection-js-ts-001",
        "internal-sql-injection-php-001",
        "internal-sql-injection-java-csharp-001",
        "internal-sql-injection-go-ruby-001",
        "internal-nosql-injection-001",
        "internal-xxe-001",
        "internal-xss-001",
        "internal-secrets-exposure-001",
        "internal-crypto-misuse-001",
        "internal-evm-external-call-001",
        "internal-template-injection-001",
        "internal-path-traversal-001",
        "internal-ssrf-001",
        "internal-deserialization-001",
        "internal-iac-exposure-001",
        "internal-memory-lifetime-001",
        "internal-hardware-security-001",
    ]
    assert {
        hypothesis.hunter
        for case in manifest.selected_cases(quick=True)
        for hypothesis in case.expected_hypotheses
    } == {
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
    }
    assert [
        hypothesis.status for hypothesis in manifest.cases[0].expected_hypotheses
    ] == ["proven", "killed", "unresolved"]
    assert [
        hypothesis.status for hypothesis in manifest.cases[1].expected_hypotheses
    ].count("proven") == 5
    assert [
        hypothesis.hunter for hypothesis in manifest.cases[-2].expected_hypotheses
    ] == ["memory_lifetime", "memory_lifetime", "memory_lifetime"]
    assert [
        hypothesis.hunter for hypothesis in manifest.cases[-1].expected_hypotheses
    ] == ["hardware_security", "hardware_security", "hardware_security"]


def test_load_manifest_rejects_missing_cases(tmp_path):
    path = tmp_path / "manifest.yaml"
    path.write_text("cases: []\n", encoding="utf-8")

    with pytest.raises(ValueError, match="at least one case"):
        load_manifest(path)


def test_load_manifest_parses_coverage_matrix(tmp_path):
    path = tmp_path / "manifest.yaml"
    path.write_text(
        """
coverage_matrix:
  - language: python
    parser_runtime: python
    graph_mode: ast
    vulnerability_class: CWE-89
    hunter: sql_injection
    source_coverage: request_input
    sink_coverage: sql_execution
    mitigation_coverage: parameterized_query
    fixture_status: missing
    default_status: default
    experimental_status: stable
cases:
  - id: sql-001
    source: internal
    cwe: CWE-89
    language: python
    path: app
    quick: true
    expected_findings: []
""",
        encoding="utf-8",
    )

    manifest = load_manifest(path)

    assert manifest.coverage_matrix[0].hunter == "sql_injection"
    assert manifest.coverage_matrix[0].fixture_status == "missing"
