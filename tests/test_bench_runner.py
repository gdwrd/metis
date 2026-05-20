# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from pathlib import Path
import shutil
import time

import pytest

from metis.bench.runner import (
    BenchmarkOptions,
    BenchmarkRegressionError,
    run_benchmark,
)
from metis.engine.options import ReviewAgenticOptions, ReviewOptions, TriageOptions
from metis.sarif.triage import METIS_TRIAGE_STATUS_KEY


def test_run_benchmark_uses_review_injection_without_credentials():
    calls = []
    engine = SimpleNamespace(usage_totals=lambda: {"total_tokens": 0})

    def review_file(path, options=None):
        calls.append((path, options))
        return {
            "file": path,
            "file_path": path,
            "reviews": [
                {
                    "issue": "stack overflow",
                    "line_number": 5,
                    "cwe": "CWE-121",
                    "severity": "HIGH",
                }
            ],
        }

    result = run_benchmark(
        engine,
        BenchmarkOptions(quick=True),
        review_file_func=review_file,
    )

    assert result["mode"] == "review"
    assert result["totals"]["tp"] == 1
    assert calls
    assert isinstance(calls[0][1], ReviewOptions)
    assert calls[0][1].use_retrieval_context is False


def test_run_benchmark_passes_agentic_review_mode_to_reviews():
    calls = []
    engine = SimpleNamespace(usage_totals=lambda: {"total_tokens": 0})
    agentic_options = ReviewAgenticOptions(max_tool_calls=1)

    def review_file(path, options=None):
        calls.append((path, options))
        return {"file": path, "file_path": path, "reviews": []}

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            quick=True,
            review_mode="agentic",
            agentic_options=agentic_options,
        ),
        review_file_func=review_file,
    )

    assert result["review_mode"] == "agentic"
    assert calls[0][1].review_mode == "agentic"
    assert calls[0][1].agentic == agentic_options


def test_run_benchmark_triage_uses_public_boundary():
    engine = SimpleNamespace(usage_totals=lambda: {"total_tokens": 0})
    triage_calls = []

    def review_file(path, options=None):
        return {
            "file": path,
            "file_path": path,
            "reviews": [
                {
                    "issue": "stack overflow",
                    "line_number": 5,
                    "cwe": "CWE-121",
                    "severity": "HIGH",
                }
            ],
        }

    def triage(payload, options=None):
        triage_calls.append(options)
        payload["runs"][0]["results"][0].setdefault("properties", {})[
            METIS_TRIAGE_STATUS_KEY
        ] = "valid"
        return payload

    result = run_benchmark(
        engine,
        BenchmarkOptions(quick=True, triage=True),
        review_file_func=review_file,
        triage_func=triage,
    )

    assert result["mode"] == "review+triage"
    assert result["totals"]["tp"] == 1
    assert isinstance(triage_calls[0], TriageOptions)
    assert triage_calls[0].use_retrieval_context is False


def test_run_benchmark_scores_research_hypotheses(engine, tmp_path):
    shutil.copytree("tests/fixtures/research/authz_outlier_app", tmp_path / "authz")
    shutil.copytree(
        "tests/fixtures/research/memory_lifetime_app",
        tmp_path / "memory",
    )
    shutil.copytree(
        "tests/fixtures/research/hardware_security_app",
        tmp_path / "hardware",
    )
    manifest = tmp_path / "research-manifest.yaml"
    manifest.write_text(
        """
line_tolerance: 1
cases:
  - id: internal-authz-outlier-001
    source: internal
    cwe: CWE-862
    language: python
    path: authz
    quick: true
    expected_findings: []
    expected_hypotheses:
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: update_project_settings
        line_range: [23, 23]
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: killed
        file: app.py
        symbol: get_project
        line_range: [18, 18]
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: unresolved
        file: app.py
        symbol: status
        line_range: [28, 28]
  - id: internal-memory-lifetime-001
    source: internal
    cwe: CWE-416
    language: c
    path: memory
    quick: true
    expected_findings: []
    expected_hypotheses:
      - hunter: memory_lifetime
        vulnerability_class: CWE-416
        status: proven
        file: lifetime.c
        symbol: finish_request_callback
        line_range: [7, 7]
      - hunter: memory_lifetime
        vulnerability_class: CWE-416
        status: killed
        file: lifetime.c
        symbol: finish_request_safe
        line_range: [12, 12]
      - hunter: memory_lifetime
        vulnerability_class: CWE-416
        status: unresolved
        file: lifetime.c
        symbol: cleanup_cache
        line_range: [17, 17]
  - id: internal-hardware-security-001
    source: internal
    cwe: CWE-1262
    language: systemverilog
    path: hardware
    quick: true
    expected_findings: []
    expected_hypotheses:
      - hunter: hardware_security
        vulnerability_class: CWE-1262
        status: proven
        file: secure_regs.sv
        symbol: insecure_key_regs
        line_range: [1, 1]
      - hunter: hardware_security
        vulnerability_class: CWE-1262
        status: killed
        file: secure_regs.sv
        symbol: secure_key_regs
        line_range: [13, 13]
      - hunter: hardware_security
        vulnerability_class: CWE-1262
        status: unresolved
        file: secure_regs.sv
        symbol: boot_key_shadow
        line_range: [27, 27]
""",
        encoding="utf-8",
    )
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    def review_file(path, options=None):
        return {"file": path, "file_path": path, "reviews": []}

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            manifest_path=str(manifest),
            quick=True,
            research=True,
        ),
        review_file_func=review_file,
    )

    assert result["mode"] == "review+research"
    assert result["totals"]["fp"] == 0
    assert result["finding_counts"]["reported"] == 0
    assert result["hypotheses"]["generated"] == 9
    assert result["hypotheses"]["proven"] == 3
    assert result["hypotheses"]["killed"] == 3
    assert result["hypotheses"]["unresolved"] == 3
    assert result["hypotheses"]["proven_tp"] == 3
    assert result["hypotheses"]["killed_tp"] == 3
    assert result["hypotheses"]["unresolved_tp"] == 3
    assert result["hypotheses"]["proven_recall_by_class"] == {
        "CWE-1262": 1.0,
        "CWE-416": 1.0,
        "CWE-862": 1.0,
    }
    assert result["hypotheses"]["by_domain"]["web_app"]["generated"] == 3
    assert result["hypotheses"]["by_domain"]["native_hardware"]["generated"] == 6
    assert "evidence_completeness_rate" in result["hypotheses"]
    assert "proven_vulnerabilities_per_analysis_budget" in result["hypotheses"]


def test_run_benchmark_research_quick_manifest_covers_all_hunters(engine):
    repo_root = Path.cwd()
    engine.codebase_path = str(repo_root)
    engine._config.codebase_path = str(repo_root)
    review_calls = []

    def review_file(path, options=None):
        review_calls.append(path)
        return {"file": path, "file_path": path, "reviews": []}

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            manifest_path="tests/benchmarks/research-manifest.yaml",
            quick=True,
            research=True,
        ),
        review_file_func=review_file,
    )

    assert review_calls == []
    assert result["mode"] == "review+research"
    assert result["case_count"] == 7
    assert result["case_ids"] == [
        "internal-authz-outlier-001",
        "internal-injection-path-001",
        "internal-path-traversal-001",
        "internal-ssrf-001",
        "internal-deserialization-001",
        "internal-memory-lifetime-001",
        "internal-hardware-security-001",
    ]
    assert result["hypotheses"]["generated"] == 28
    assert result["hypotheses"]["proven"] == 11
    assert result["hypotheses"]["killed"] == 10
    assert result["hypotheses"]["unresolved"] == 7
    assert result["hypotheses"]["proven_recall_by_class"] == {
        "CWE-1262": 1.0,
        "CWE-22": 1.0,
        "CWE-416": 1.0,
        "CWE-502": 1.0,
        "CWE-74": 1.0,
        "CWE-862": 1.0,
        "CWE-918": 1.0,
    }
    assert result["hypotheses"]["false_positive_rate"] == 0.0
    assert result["hypotheses"]["evidence_completeness_rate"] < 1.0


def test_run_benchmark_scopes_research_hypotheses_by_case(tmp_path):
    case_a = tmp_path / "case-a"
    case_b = tmp_path / "case-b"
    case_a.mkdir()
    case_b.mkdir()
    (case_a / "app.py").write_text("def risky():\n    pass\n", encoding="utf-8")
    (case_b / "app.py").write_text("def risky():\n    pass\n", encoding="utf-8")
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        """
cases:
  - id: authz-a
    source: internal
    cwe: CWE-862
    language: python
    path: case-a
    quick: true
    expected_findings: []
    expected_hypotheses: []
  - id: authz-b
    source: internal
    cwe: CWE-862
    language: python
    path: case-b
    quick: true
    expected_findings: []
    expected_hypotheses:
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: risky
        line_range: [1, 1]
""",
        encoding="utf-8",
    )
    engine = SimpleNamespace(usage_totals=lambda: {"total_tokens": 0})

    def review_file(path, options=None):
        return {"file": path, "file_path": path, "reviews": []}

    def research(root):
        if root.endswith("case-a"):
            return [_hypothesis("proven", "app.py", 1, "risky")]
        return []

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            manifest_path=str(manifest),
            quick=True,
            research=True,
        ),
        review_file_func=review_file,
        research_func=research,
    )

    assert result["hypotheses"]["proven_tp"] == 0
    assert result["hypotheses"]["proven_fp"] == 1
    assert result["hypotheses"]["proven_fn"] == 1
    assert result["hypotheses"]["cases"]["authz-a"]["proven_fp"] == 1
    assert result["hypotheses"]["cases"]["authz-b"]["proven_fn"] == 1


def test_run_benchmark_counts_case_scoped_research_lesson_metrics(tmp_path):
    case_a = tmp_path / "case-a"
    case_b = tmp_path / "case-b"
    case_a.mkdir()
    case_b.mkdir()
    (case_a / "app.py").write_text("def safe():\n    pass\n", encoding="utf-8")
    (case_b / "app.py").write_text("def risky():\n    pass\n", encoding="utf-8")
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        """
cases:
  - id: authz-a
    source: internal
    cwe: CWE-862
    language: python
    path: case-a
    quick: true
    expected_findings: []
    expected_hypotheses: []
  - id: authz-b
    source: internal
    cwe: CWE-862
    language: python
    path: case-b
    quick: true
    expected_findings: []
    expected_hypotheses:
      - hunter: authz_outlier
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: risky
        line_range: [1, 1]
""",
        encoding="utf-8",
    )
    engine = SimpleNamespace(usage_totals=lambda: {"total_tokens": 0})

    def review_file(path, options=None):
        return {"file": path, "file_path": path, "reviews": []}

    def research(root):
        if root.endswith("case-a"):
            return {
                "generated": [],
                "metric_summary": {
                    "lessons": {"lesson_refs": ["lesson-suppressed-a"]}
                },
            }
        return {
            "generated": [
                _hypothesis(
                    "proven",
                    "app.py",
                    1,
                    "risky",
                )
            ],
            "metric_summary": {
                "lessons": {"lesson_refs": ["lesson-suppressed-b"]}
            },
        }

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            manifest_path=str(manifest),
            quick=True,
            research=True,
        ),
        review_file_func=review_file,
        research_func=research,
    )

    assert result["hypotheses"]["lessons_reused"] == 2
    assert result["hypotheses"]["cases"]["authz-a"]["lessons_reused"] == 1
    assert result["hypotheses"]["cases"]["authz-b"]["lessons_reused"] == 1


def test_run_benchmark_scores_variant_hypothesis_recall_and_false_positives(
    tmp_path,
):
    case_dir = tmp_path / "variant"
    case_dir.mkdir()
    (case_dir / "app.py").write_text(
        "def get_project():\n"
        "    pass\n"
        "def update_project_settings():\n"
        "    pass\n"
        "def delete_project():\n"
        "    pass\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        """
cases:
  - id: variant-authz
    source: internal
    cwe: CWE-862
    language: python
    path: variant
    quick: true
    expected_findings: []
    expected_hypotheses:
      - hunter: variant_patch
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: update_project_settings
        line_range: [3, 3]
      - hunter: variant_patch
        vulnerability_class: CWE-862
        status: killed
        file: app.py
        symbol: get_project
        line_range: [1, 1]
""",
        encoding="utf-8",
    )
    engine = SimpleNamespace(usage_totals=lambda: {"total_tokens": 0})

    def review_file(path, options=None):
        return {"file": path, "file_path": path, "reviews": []}

    def research(root):
        return [
            _hypothesis(
                "proven",
                "app.py",
                3,
                "update_project_settings",
                hunter="variant_patch",
            ),
            _hypothesis("killed", "app.py", 1, "get_project", hunter="variant_patch"),
            _hypothesis(
                "proven",
                "app.py",
                5,
                "delete_project",
                hunter="variant_patch",
            ),
        ]

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            manifest_path=str(manifest),
            quick=True,
            research=True,
        ),
        review_file_func=review_file,
        research_func=research,
    )

    assert result["hypotheses"]["generated"] == 3
    assert result["hypotheses"]["proven_tp"] == 1
    assert result["hypotheses"]["proven_fp"] == 1
    assert result["hypotheses"]["killed_tp"] == 1
    assert result["hypotheses"]["by_domain"]["web_app"]["generated"] == 3
    assert result["hypotheses"]["by_class"]["CWE-862"]["false_positive_rate"] == 0.5


def test_run_benchmark_runs_variant_sources_through_engine(engine, tmp_path):
    shutil.copytree("tests/fixtures/research/variant_authz_app", tmp_path / "variant")
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        """
line_tolerance: 1
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
      - hunter: variant_patch
        vulnerability_class: CWE-862
        status: killed
        file: app.py
        symbol: get_project
        line_range: [18, 18]
""",
        encoding="utf-8",
    )
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    def review_file(path, options=None):
        return {"file": path, "file_path": path, "reviews": []}

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            manifest_path=str(manifest),
            quick=True,
            research=True,
        ),
        review_file_func=review_file,
    )

    assert result["hypotheses"]["generated"] == 2
    assert result["hypotheses"]["proven_tp"] == 1
    assert result["hypotheses"]["killed_tp"] == 1
    assert result["hypotheses"]["by_domain"]["web_app"]["generated"] == 2


def test_run_benchmark_requires_variant_sources_for_variant_patch(tmp_path):
    case_dir = tmp_path / "variant"
    case_dir.mkdir()
    (case_dir / "app.py").write_text("def risky():\n    pass\n", encoding="utf-8")
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        """
cases:
  - id: variant-authz
    source: internal
    cwe: CWE-862
    language: python
    path: variant
    quick: true
    expected_findings: []
    expected_hypotheses:
      - hunter: variant_patch
        vulnerability_class: CWE-862
        status: proven
        file: app.py
        symbol: risky
        line_range: [1, 1]
""",
        encoding="utf-8",
    )
    engine = SimpleNamespace(
        usage_totals=lambda: {"total_tokens": 0},
        research=SimpleNamespace(run=lambda *_args, **_kwargs: []),
    )

    def review_file(path, options=None):
        return {"file": path, "file_path": path, "reviews": []}

    with pytest.raises(ValueError, match="missing variant_sources"):
        run_benchmark(
            engine,
            BenchmarkOptions(
                manifest_path=str(manifest),
                quick=True,
                research=True,
            ),
            review_file_func=review_file,
        )


def test_run_benchmark_raises_regression_error(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        '{"mode":"review","by_cwe":{"CWE-121":{"recall":1.0}}}',
        encoding="utf-8",
    )
    engine = SimpleNamespace(usage_totals=lambda: {"total_tokens": 0})

    def review_file(path, options=None):
        time.sleep(0.001)
        return {"file": path, "file_path": path, "reviews": []}

    with pytest.raises(BenchmarkRegressionError) as exc:
        run_benchmark(
            engine,
            BenchmarkOptions(quick=True, baseline_path=str(baseline)),
            review_file_func=review_file,
        )

    assert exc.value.result is not None
    assert exc.value.result["regression_failed"] is True


def test_run_benchmark_perf_records_command_metrics(tmp_path):
    baseline = tmp_path / "perf-baseline.json"
    baseline.write_text(
        """
{
  "mode": "review",
  "quick": true,
  "case_count": 1,
  "case_ids": ["internal-cwe121-001"],
  "commands": {
    "review_code": {
      "wallclock_seconds": 999.0,
      "total_tokens": 0
    }
  }
}
""",
        encoding="utf-8",
    )
    engine = SimpleNamespace(usage_totals=lambda: {"total_tokens": 7})

    def review_file(path, options=None):
        return {
            "file": path,
            "file_path": path,
            "reviews": [
                {
                    "issue": "stack overflow",
                    "line_number": 5,
                    "cwe": "CWE-121",
                    "severity": "HIGH",
                }
            ],
        }

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            quick=True,
            perf=True,
            perf_baseline_path=str(baseline),
        ),
        review_file_func=review_file,
    )

    assert result["perf"] is True
    assert result["commands"]["review_code"]["wallclock_seconds"] >= 0
    assert result["commands"]["review_code"]["total_tokens"] == 0
    assert result["perf_observations"] == [
        {
            "scope": "perf",
            "command": "review_code",
            "metric": "total_tokens",
            "baseline": 0,
            "current": 0,
            "delta": 0,
        }
    ]
    assert result["perf_regression_failed"] is False


def test_run_benchmark_perf_regression_raises(tmp_path):
    baseline = tmp_path / "perf-baseline.json"
    baseline.write_text(
        """
{
  "mode": "review",
  "quick": true,
  "case_count": 1,
  "case_ids": ["internal-cwe121-001"],
  "commands": {
    "review_code": {
      "wallclock_seconds": 0.0,
      "total_tokens": 0
    }
  }
}
""",
        encoding="utf-8",
    )
    engine = SimpleNamespace(usage_totals=lambda: {"total_tokens": 0})

    def review_file(path, options=None):
        return {"file": path, "file_path": path, "reviews": []}

    with pytest.raises(BenchmarkRegressionError) as exc:
        run_benchmark(
            engine,
            BenchmarkOptions(
                quick=True,
                perf=True,
                perf_baseline_path=str(baseline),
            ),
            review_file_func=review_file,
        )

    assert exc.value.result is not None
    assert exc.value.result["perf_regression_failed"] is True


def _hypothesis(status, path, line, symbol, *, hunter="authz_outlier"):
    return {
        "id": f"hyp-{symbol}",
        "hunter": hunter,
        "vulnerability_class": "CWE-862",
        "status": status,
        "locations": [
            {
                "file": path,
                "line": line,
                "symbol": symbol,
                "role": "entrypoint",
            }
        ],
    }
