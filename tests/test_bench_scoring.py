# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.bench.manifest import load_manifest
from metis.bench.scoring import (
    NOT_APPLICABLE,
    compare_perf_observations,
    compare_perf_to_baseline,
    compare_to_baseline,
    score_sarif,
)


def test_score_review_sarif_counts_tp_fp_fn_and_marks_inconclusive_not_applicable():
    manifest = load_manifest("tests/benchmarks/manifest.yaml")
    payload = _sarif(
        [
            _result("cases/internal/cwe121/001/vuln.c", 7, "CWE-121"),
            _result("cases/internal/cwe121/001/vuln.c", 2, "CWE-999"),
        ]
    )

    score = score_sarif(payload, manifest, triage_enabled=False)

    assert score["totals"]["tp"] == 1
    assert score["totals"]["fp"] == 1
    assert score["totals"]["fn"] == 0
    assert score["totals"]["inconclusive"] == NOT_APPLICABLE
    assert score["by_language"]["c"]["fp"] == 1
    assert score["cases"]["internal-cwe121-001"]["fp"] == 1
    assert score["finding_counts"]["unmapped_fp"] == 0


def test_score_triage_statuses_have_deterministic_active_semantics():
    manifest = load_manifest("tests/benchmarks/manifest.yaml")
    payload = _sarif(
        [
            _result("cases/internal/cwe121/001/vuln.c", 7, "CWE-121", status="invalid"),
            _result("cases/internal/cwe121/001/vuln.c", 2, "CWE-999", status="invalid"),
            _result(
                "cases/internal/cwe121/001/vuln.c", 3, "CWE-998", status="inconclusive"
            ),
            _result("cases/internal/cwe121/001/vuln.c", 4, "CWE-997"),
        ]
    )

    score = score_sarif(payload, manifest, triage_enabled=True)

    assert score["totals"]["tp"] == 0
    assert score["totals"]["fp"] == 1
    assert score["totals"]["fn"] == 1
    assert score["totals"]["inconclusive"] == 1
    assert score["finding_counts"]["suppressed"] == 2


def test_compare_to_baseline_reports_per_cwe_recall_drop():
    current = {
        "mode": "review",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-cwe121-001"],
        "by_cwe": {"CWE-121": {"recall": 0.80}},
    }
    baseline = {
        "mode": "review",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-cwe121-001"],
        "by_cwe": {"CWE-121": {"recall": 0.90}},
    }

    regressions = compare_to_baseline(current, baseline, recall_tolerance=0.05)

    assert regressions == [
        {
            "scope": "cwe",
            "cwe": "CWE-121",
            "baseline_recall": 0.90,
            "current_recall": 0.80,
            "drop": 0.09999999999999998,
            "tolerance": 0.05,
        }
    ]


def test_compare_to_baseline_rejects_case_identity_mismatch():
    current = {
        "mode": "review",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-cwe121-001"],
        "by_cwe": {"CWE-121": {"recall": 1.0}},
    }
    baseline = {
        "mode": "review",
        "quick": False,
        "case_count": 2,
        "case_ids": ["other"],
        "by_cwe": {"CWE-121": {"recall": 1.0}},
    }

    regressions = compare_to_baseline(current, baseline, recall_tolerance=0.05)

    assert [item["scope"] for item in regressions] == [
        "quick",
        "case_count",
        "case_ids",
    ]


def test_compare_perf_to_baseline_reports_wallclock_regression():
    current = {
        "mode": "review",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-cwe121-001"],
        "commands": {
            "review_code": {
                "wallclock_seconds": 13.0,
                "total_tokens": 100,
            }
        },
    }
    baseline = {
        "mode": "review",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-cwe121-001"],
        "commands": {
            "review_code": {
                "wallclock_seconds": 10.0,
                "total_tokens": 50,
            }
        },
    }

    regressions = compare_perf_to_baseline(current, baseline, wallclock_tolerance=0.20)

    assert regressions == [
        {
            "scope": "perf",
            "command": "review_code",
            "metric": "wallclock_seconds",
            "baseline": 10.0,
            "current": 13.0,
            "tolerance": 0.20,
            "limit": 12.0,
        }
    ]


def test_compare_perf_observations_reports_token_delta_without_hard_gate():
    current = {
        "mode": "review",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-cwe121-001"],
        "commands": {
            "review_code": {
                "wallclock_seconds": 11.0,
                "total_tokens": 100,
            }
        },
    }
    baseline = {
        "mode": "review",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-cwe121-001"],
        "commands": {
            "review_code": {
                "wallclock_seconds": 10.0,
                "total_tokens": 50,
            }
        },
    }

    regressions = compare_perf_to_baseline(current, baseline, wallclock_tolerance=0.20)
    observations = compare_perf_observations(current, baseline)

    assert regressions == []
    assert observations == [
        {
            "scope": "perf",
            "command": "review_code",
            "metric": "total_tokens",
            "baseline": 50,
            "current": 100,
            "delta": 50,
        }
    ]


def _sarif(results):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Metis"}}, "results": results}],
    }


def _result(path, line, cwe, *, status=None):
    properties = {"cwe": cwe, "severity": "HIGH"}
    if status:
        properties["metisTriageStatus"] = status
    return {
        "ruleId": "AI001",
        "message": {"text": cwe},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }
        ],
        "properties": properties,
    }
