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


def test_load_manifest_rejects_missing_cases(tmp_path):
    path = tmp_path / "manifest.yaml"
    path.write_text("cases: []\n", encoding="utf-8")

    with pytest.raises(ValueError, match="at least one case"):
        load_manifest(path)
