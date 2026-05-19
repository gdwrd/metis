# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
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
