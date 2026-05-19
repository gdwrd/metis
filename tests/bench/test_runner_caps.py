# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

from metis.bench.runner import BenchmarkOptions, run_benchmark


class _UsageEngine:
    def __init__(self):
        self.total_tokens = 0

    def usage_totals(self):
        return {"total_tokens": self.total_tokens}


def _write_manifest(tmp_path: Path) -> Path:
    for case_id in ("one", "two"):
        case_dir = tmp_path / "cases" / case_id
        case_dir.mkdir(parents=True)
        (case_dir / "vuln.c").write_text("int main(void) { return 0; }\n")
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        """
line_tolerance: 1
cases:
  - id: one
    source: internal
    cwe: CWE-121
    language: c
    path: cases/one
    quick: true
    expected_findings:
      - file: vuln.c
        line_range: [1, 1]
        cwe: CWE-121
  - id: two
    source: internal
    cwe: CWE-121
    language: c
    path: cases/two
    quick: true
    expected_findings:
      - file: vuln.c
        line_range: [1, 1]
        cwe: CWE-121
""",
        encoding="utf-8",
    )
    return manifest


def test_run_benchmark_stops_after_cost_cap_and_marks_partial(tmp_path):
    manifest = _write_manifest(tmp_path)
    engine = _UsageEngine()
    calls = []

    def review_file(path, options=None):
        calls.append((path, options))
        engine.total_tokens += 1_000_001
        return {
            "file": path,
            "file_path": path,
            "reviews": [
                {
                    "issue": "stack overflow",
                    "line_number": 1,
                    "cwe": "CWE-121",
                    "severity": "HIGH",
                }
            ],
        }

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            manifest_path=str(manifest),
            quick=True,
            max_cost_usd=1.0,
        ),
        review_file_func=review_file,
    )

    assert len(calls) == 1
    assert calls[0][1].skip_test_files is False
    assert result["partial"] is True
    assert "estimated_cost_usd" in result["partial_reason"]
    assert result["case_count"] == 1
    assert result["case_ids"] == ["one"]
    assert result["requested_case_count"] == 2
    assert result["regression_failed"] is False


def test_run_benchmark_stops_after_wallclock_cap_and_marks_partial(tmp_path):
    manifest = _write_manifest(tmp_path)
    engine = _UsageEngine()
    calls = []

    def review_file(path, options=None):
        calls.append(path)
        return {"file": path, "file_path": path, "reviews": []}

    result = run_benchmark(
        engine,
        BenchmarkOptions(
            manifest_path=str(manifest),
            quick=True,
            max_wallclock_seconds=0.0,
        ),
        review_file_func=review_file,
    )

    assert len(calls) == 1
    assert result["partial"] is True
    assert "wallclock_seconds" in result["partial_reason"]
    assert result["case_ids"] == ["one"]
