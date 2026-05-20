# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.bench.manifest import load_manifest
from metis.bench.scoring import (
    NOT_APPLICABLE,
    compare_perf_observations,
    compare_perf_to_baseline,
    compare_to_baseline,
    score_hypotheses,
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


def test_score_hypotheses_counts_statuses_and_proven_quality_metrics(tmp_path):
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        """
cases:
  - id: authz-001
    source: internal
    cwe: CWE-862
    language: python
    path: app
    expected_findings: []
    expected_hypotheses:
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: update_project_settings
        line_range: [20, 22]
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: killed
        file: app.py
        symbol: get_project
        line_range: [16, 16]
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: unresolved
        file: app.py
        symbol: status
        line_range: [26, 26]
""",
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    hypotheses = [
        _hypothesis(
            "proven",
            "app/app.py",
            21,
            "update_project_settings",
            lesson_refs=("lesson-guard",),
        ),
        _hypothesis("killed", "app/app.py", 16, "get_project"),
        _hypothesis("unresolved", "app/app.py", 26, "status"),
    ]

    score = score_hypotheses(
        hypotheses,
        manifest,
        research_metrics={"lessons": {"lesson_refs": ["lesson-suppressed"]}},
    )

    assert score["generated"] == 3
    assert score["proven"] == 1
    assert score["killed"] == 1
    assert score["unresolved"] == 1
    assert score["proven_tp"] == 1
    assert score["proven_fp"] == 0
    assert score["proven_fn"] == 0
    assert score["killed_tp"] == 1
    assert score["killed_fp"] == 0
    assert score["killed_fn"] == 0
    assert score["unresolved_tp"] == 1
    assert score["unresolved_fp"] == 0
    assert score["unresolved_fn"] == 0
    assert score["lessons_reused"] == 2
    assert score["by_status"]["killed"]["recall"] == 1.0
    assert score["proven_recall_by_class"] == {"CWE-862": 1.0}
    assert score["false_positive_rate_by_class"] == {"CWE-862": 0.0}
    assert score["cases"]["authz-001"]["generated"] == 3
    assert score["cases"]["authz-001"]["killed_tp"] == 1
    assert score["cases"]["authz-001"]["lessons_reused"] == 2


def test_score_hypotheses_reports_web_and_native_hardware_domains(tmp_path):
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        """
cases:
  - id: mixed-001
    source: internal
    cwe: CWE-Mixed
    language: mixed
    path: app
    expected_findings: []
    expected_hypotheses:
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: update_project_settings
        line_range: [20, 20]
      - hunter: memory_lifetime
        vulnerability_class: CWE-416
        status: proven
        file: native.c
        symbol: finish_request_callback
        line_range: [7, 7]
""",
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    hypotheses = [
        _hypothesis("proven", "app/app.py", 20, "update_project_settings"),
        _hypothesis(
            "proven",
            "app/native.c",
            7,
            "finish_request_callback",
            hunter="memory_lifetime",
            vulnerability_class="CWE-416",
        ),
    ]

    score = score_hypotheses(hypotheses, manifest)

    assert score["by_domain"]["web_app"]["generated"] == 1
    assert score["by_domain"]["web_app"]["proven_tp"] == 1
    assert score["by_domain"]["native_hardware"]["generated"] == 1
    assert score["by_domain"]["native_hardware"]["proven_tp"] == 1


def test_score_hypotheses_reports_phase10_quality_metrics(tmp_path):
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        """
cases:
  - id: authz-001
    source: internal
    cwe: CWE-862
    language: python
    path: app
    expected_findings: []
    expected_hypotheses:
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: update_project_settings
        line_range: [20, 20]
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: unresolved
        file: app.py
        symbol: status
        line_range: [26, 26]
""",
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    hypotheses = [
        _hypothesis(
            "proven",
            "app/app.py",
            20,
            "update_project_settings",
            proof_artifact=True,
        ),
        _hypothesis(
            "unresolved",
            "app/app.py",
            26,
            "status",
            evidence_complete=False,
        ),
    ]

    score = score_hypotheses(
        hypotheses,
        manifest,
        research_metrics={
            "research_command": {
                "total_tokens": 2000,
                "wallclock_seconds": 4.0,
            },
            "research_budget": "quick",
        },
    )

    assert score["evidence_completeness_rate"] == 0.75
    assert score["evidence_completeness_rate_by_class"] == {"CWE-862": 0.75}
    assert score["average_tokens_per_proven_finding"] == 2000.0
    assert score["average_wallclock_seconds_per_proven_finding"] == 4.0
    assert score["findings_with_local_proof_artifacts"] == 1
    assert score["analysis_budget"] == {
        "research_budgets": ("quick",),
        "total_tokens": 2000,
        "wallclock_seconds": 4.0,
    }
    assert score["proven_vulnerabilities_per_analysis_budget"] == {
        "per_1000_tokens": 0.5,
        "per_wallclock_second": 0.25,
    }


def test_compare_to_baseline_reports_hypothesis_regressions():
    current = {
        "mode": "review+research",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-authz-outlier-001"],
        "by_cwe": {},
        "hypotheses": {
            "proven_recall_by_class": {"CWE-862": 0.5},
            "false_positive_rate_by_class": {"CWE-862": 0.4},
        },
    }
    baseline = {
        "mode": "review+research",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-authz-outlier-001"],
        "by_cwe": {},
        "hypotheses": {
            "proven_recall_by_class": {"CWE-862": 1.0},
            "false_positive_rate_by_class": {"CWE-862": 0.0},
        },
    }

    regressions = compare_to_baseline(current, baseline, recall_tolerance=0.05)

    assert regressions == [
        {
            "scope": "hypothesis_recall",
            "vulnerability_class": "CWE-862",
            "baseline_recall": 1.0,
            "current_recall": 0.5,
            "drop": 0.5,
            "tolerance": 0.05,
        },
        {
            "scope": "hypothesis_false_positive_rate",
            "vulnerability_class": "CWE-862",
            "baseline_rate": 0.0,
            "current_rate": 0.4,
            "increase": 0.4,
            "tolerance": 0.05,
        },
    ]


def test_compare_to_baseline_reports_hypothesis_evidence_regressions():
    current = {
        "mode": "review+research",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-authz-outlier-001"],
        "by_cwe": {},
        "hypotheses": {
            "evidence_completeness_rate": 0.80,
            "evidence_completeness_rate_by_class": {"CWE-862": 0.70},
        },
    }
    baseline = {
        "mode": "review+research",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-authz-outlier-001"],
        "by_cwe": {},
        "hypotheses": {
            "evidence_completeness_rate": 1.0,
            "evidence_completeness_rate_by_class": {"CWE-862": 1.0},
        },
    }

    regressions = compare_to_baseline(current, baseline, recall_tolerance=0.05)

    assert regressions == [
        {
            "scope": "hypothesis_evidence_completeness",
            "baseline_rate": 1.0,
            "current_rate": 0.8,
            "drop": 0.19999999999999996,
            "tolerance": 0.05,
        },
        {
            "scope": "hypothesis_evidence_completeness_by_class",
            "vulnerability_class": "CWE-862",
            "baseline_rate": 1.0,
            "current_rate": 0.7,
            "drop": 0.30000000000000004,
            "tolerance": 0.05,
        },
    ]


def test_compare_to_baseline_reports_new_hypothesis_fp_class():
    current = {
        "mode": "review+research",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-authz-outlier-001"],
        "by_cwe": {},
        "hypotheses": {
            "proven_recall_by_class": {"CWE-862": 1.0},
            "false_positive_rate_by_class": {"CWE-862": 0.0, "CWE-89": 1.0},
        },
    }
    baseline = {
        "mode": "review+research",
        "quick": True,
        "case_count": 1,
        "case_ids": ["internal-authz-outlier-001"],
        "by_cwe": {},
        "hypotheses": {
            "proven_recall_by_class": {"CWE-862": 1.0},
            "false_positive_rate_by_class": {"CWE-862": 0.0},
        },
    }

    regressions = compare_to_baseline(current, baseline, recall_tolerance=0.05)

    assert regressions == [
        {
            "scope": "hypothesis_false_positive_rate",
            "vulnerability_class": "CWE-89",
            "baseline_rate": 0.0,
            "current_rate": 1.0,
            "increase": 1.0,
            "tolerance": 0.05,
        }
    ]


def test_score_hypotheses_requires_case_identity_for_multi_case_relative_paths(
    tmp_path,
):
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        """
cases:
  - id: authz-a
    source: internal
    cwe: CWE-862
    language: python
    path: case-a
    expected_findings: []
    expected_hypotheses:
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: risky
        line_range: [5, 5]
  - id: authz-b
    source: internal
    cwe: CWE-862
    language: python
    path: case-b
    expected_findings: []
    expected_hypotheses:
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: risky
        line_range: [5, 5]
""",
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)

    unscoped = score_hypotheses(
        [_hypothesis("proven", "app.py", 5, "risky")],
        manifest,
    )
    scoped = score_hypotheses(
        [_hypothesis("proven", "app.py", 5, "risky", case_id="authz-b")],
        manifest,
    )

    assert unscoped["proven_tp"] == 0
    assert unscoped["proven_fp"] == 1
    assert unscoped["proven_fn"] == 2
    assert unscoped["cases"]["authz-a"]["generated"] == 0
    assert unscoped["cases"]["authz-a"]["proven_fp"] == 0
    assert unscoped["cases"]["authz-b"]["generated"] == 0
    assert unscoped["cases"]["authz-b"]["proven_fp"] == 0
    assert scoped["proven_tp"] == 1
    assert scoped["proven_fp"] == 0
    assert scoped["proven_fn"] == 1
    assert scoped["cases"]["authz-b"]["generated"] == 1
    assert scoped["cases"]["authz-b"]["proven_tp"] == 1


def _sarif(results):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Metis"}}, "results": results}],
    }


def _hypothesis(
    status,
    path,
    line,
    symbol,
    *,
    case_id=None,
    hunter="authz_outlier",
    vulnerability_class="CWE-862",
    lesson_refs=(),
    evidence_complete=True,
    proof_artifact=False,
):
    hypothesis_id = f"hyp-{symbol}"
    payload = {
        "id": hypothesis_id,
        "hunter": hunter,
        "vulnerability_class": vulnerability_class,
        "status": status,
        "locations": [
            {
                "file": path,
                "line": line,
                "symbol": symbol,
                "role": "entrypoint",
            }
        ],
        "lesson_refs": list(lesson_refs),
        "evidence_obligations": [
            {"name": "source", "required": True},
            {"name": "impact", "required": True},
        ],
        "evidence": [
            {
                "hypothesis_id": hypothesis_id,
                "obligation": "source",
                "status": "satisfied",
                "kind": "definition",
                "claim": "source evidence",
            },
            {
                "hypothesis_id": hypothesis_id,
                "obligation": "impact",
                "status": "satisfied" if evidence_complete else "missing",
                "kind": "negative_evidence",
                "claim": "impact evidence",
            },
        ],
    }
    if proof_artifact:
        payload["evidence"].append(
            {
                "hypothesis_id": hypothesis_id,
                "obligation": "proof_artifact",
                "status": "satisfied",
                "kind": "proof_artifact",
                "claim": "local proof generated",
            }
        )
    if case_id is not None:
        payload["case_id"] = case_id
    return payload


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
