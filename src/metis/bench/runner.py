# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Callable
from uuid import uuid4

from metis.engine.options import ReviewAgenticOptions, ReviewOptions, TriageOptions
from metis.sarif.writer import generate_sarif
from metis.usage import usage_operation

from .manifest import BenchmarkCase, BenchmarkManifest, load_manifest
from .scoring import (
    compare_perf_observations,
    compare_perf_to_baseline,
    compare_to_baseline,
    score_sarif,
)


class BenchmarkRegressionError(RuntimeError):
    def __init__(
        self,
        regressions: list[dict[str, Any]],
        result: dict[str, Any] | None = None,
    ):
        super().__init__("Benchmark regression exceeded tolerance")
        self.regressions = regressions
        self.result = result


@dataclass(frozen=True)
class BenchmarkOptions:
    manifest_path: str = "tests/benchmarks/manifest.yaml"
    quick: bool = False
    triage: bool = False
    baseline_path: str | None = None
    recall_tolerance: float = 0.05
    update_baseline: bool = False
    review_mode: str = "standard"
    agentic_options: ReviewAgenticOptions | None = None
    max_cost_usd: float | None = None
    max_wallclock_seconds: float | None = None
    perf: bool = False
    perf_baseline_path: str | None = None
    perf_wallclock_tolerance: float = 0.20


def run_benchmark(
    engine,
    options: BenchmarkOptions,
    *,
    review_file_func: Callable[..., dict[str, Any] | None] | None = None,
    triage_func: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    manifest = load_manifest(options.manifest_path)
    selected_cases = manifest.selected_cases(quick=options.quick)
    if not selected_cases:
        raise ValueError("No benchmark cases selected")

    reviews: list[dict[str, Any]] = []
    completed_cases: list[BenchmarkCase] = []
    partial_reason = None
    commands: dict[str, dict[str, Any]] = {}
    review_started = time.monotonic()
    review_usage_before = _usage_totals(engine)
    for case in selected_cases:
        reviews.extend(
            _collect_case_reviews(engine, manifest, case, review_file_func, options)
        )
        completed_cases.append(case)
        partial_reason = _cap_stop_reason(
            options,
            started_at=started,
            usage=_usage_totals(engine),
        )
        if partial_reason:
            break
    commands["review_code"] = _command_metrics(
        started_at=review_started,
        usage_before=review_usage_before,
        usage_after=_usage_totals(engine),
    )

    cases = tuple(completed_cases)
    review_results = {"reviews": reviews}
    sarif_payload = generate_sarif(
        review_results,
        automation_id=f"metis-bench-{uuid4()}",
    )
    if options.triage:
        triage_callable = triage_func or engine.triage_sarif_payload
        triage_started = time.monotonic()
        triage_usage_before = _usage_totals(engine)
        with usage_operation("triage"):
            sarif_payload = triage_callable(
                sarif_payload,
                options=TriageOptions(
                    use_retrieval_context=False,
                    skip_test_files=False,
                ),
            )
        commands["triage"] = _command_metrics(
            started_at=triage_started,
            usage_before=triage_usage_before,
            usage_after=_usage_totals(engine),
        )
        partial_reason = partial_reason or _cap_stop_reason(
            options,
            started_at=started,
            usage=_usage_totals(engine),
        )

    tokens = _usage_totals(engine)
    result = {
        "run_id": str(uuid4()),
        "mode": "review+triage" if options.triage else "review",
        "review_mode": options.review_mode,
        "model": _model_name(engine),
        "git_sha": _git_sha(),
        "manifest": str(Path(options.manifest_path)),
        "quick": options.quick,
        "case_count": len(cases),
        "case_ids": [case.id for case in cases],
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "wallclock_seconds": time.monotonic() - started,
        **score_sarif(
            sarif_payload,
            manifest,
            cases=cases,
            triage_enabled=options.triage,
        ),
        "tokens": tokens,
    }
    if options.perf:
        result["perf"] = True
        result["commands"] = commands
    if options.max_cost_usd is not None:
        result["estimated_cost_usd"] = _estimate_usage_cost_usd(tokens)
        result["max_cost_usd"] = options.max_cost_usd
    if options.max_wallclock_seconds is not None:
        result["max_wallclock_seconds"] = options.max_wallclock_seconds
    if partial_reason:
        result["partial"] = True
        result["partial_reason"] = partial_reason
        result["requested_case_count"] = len(selected_cases)
        result["requested_case_ids"] = [case.id for case in selected_cases]

    regressions: list[dict[str, Any]] = []
    if options.baseline_path:
        baseline_path = Path(options.baseline_path)
        if baseline_path.exists() and not partial_reason:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            regressions = compare_to_baseline(
                result,
                baseline,
                recall_tolerance=options.recall_tolerance,
            )
        if options.update_baseline and not partial_reason:
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if options.perf and options.perf_baseline_path:
        perf_baseline_path = Path(options.perf_baseline_path)
        perf_regressions: list[dict[str, Any]] = []
        perf_observations: list[dict[str, Any]] = []
        if perf_baseline_path.exists() and not partial_reason:
            perf_baseline = json.loads(perf_baseline_path.read_text(encoding="utf-8"))
            perf_regressions = compare_perf_to_baseline(
                result,
                perf_baseline,
                wallclock_tolerance=options.perf_wallclock_tolerance,
            )
            perf_observations = compare_perf_observations(result, perf_baseline)
            regressions.extend(perf_regressions)
        if options.update_baseline and not partial_reason:
            perf_baseline_path.parent.mkdir(parents=True, exist_ok=True)
            perf_baseline_path.write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
        result["perf_regressions"] = perf_regressions
        result["perf_observations"] = perf_observations
        result["perf_regression_failed"] = bool(perf_regressions)
    result["regressions"] = regressions
    result["regression_failed"] = bool(regressions)
    if regressions and not options.update_baseline:
        raise BenchmarkRegressionError(regressions, result)
    return result


def _collect_reviews(
    engine,
    manifest: BenchmarkManifest,
    cases: tuple[BenchmarkCase, ...],
    review_file_func: Callable[..., dict[str, Any] | None] | None,
    options: BenchmarkOptions,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        results.extend(
            _collect_case_reviews(engine, manifest, case, review_file_func, options)
        )
    return results


def _collect_case_reviews(
    engine,
    manifest: BenchmarkManifest,
    case: BenchmarkCase,
    review_file_func: Callable[..., dict[str, Any] | None] | None,
    options: BenchmarkOptions,
) -> list[dict[str, Any]]:
    review_callable = review_file_func or engine.review.review_file
    results: list[dict[str, Any]] = []
    for source_file in _case_source_files(case, manifest):
        with usage_operation("review_code"):
            result = review_callable(
                str(source_file),
                options=ReviewOptions(
                    use_retrieval_context=False,
                    review_mode=options.review_mode,
                    agentic=options.agentic_options or ReviewAgenticOptions(),
                    skip_test_files=False,
                ),
            )
        if result:
            results.append(result)
    return results


def _case_source_files(case: BenchmarkCase, manifest: BenchmarkManifest) -> list[Path]:
    root = case.case_path(manifest.root)
    if root.is_file():
        return [root]
    if not root.exists():
        raise ValueError(f"Benchmark case path does not exist: {root}")
    return sorted(path for path in root.rglob("*") if path.is_file())


def _usage_totals(engine) -> dict[str, Any]:
    usage_totals = getattr(engine, "usage_totals", None)
    if callable(usage_totals):
        snapshot = usage_totals()
        if isinstance(snapshot, dict):
            return snapshot
    usage_runtime = getattr(engine, "usage_runtime", None)
    snapshot_total = getattr(usage_runtime, "snapshot_total", None)
    if callable(snapshot_total):
        snapshot = snapshot_total()
        if isinstance(snapshot, dict):
            return snapshot
    return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


def _command_metrics(
    *,
    started_at: float,
    usage_before: dict[str, Any],
    usage_after: dict[str, Any],
) -> dict[str, Any]:
    return {
        "wallclock_seconds": time.monotonic() - started_at,
        "total_tokens": max(
            0,
            _usage_token_count(usage_after) - _usage_token_count(usage_before),
        ),
    }


def _usage_token_count(usage: dict[str, Any]) -> int:
    value = usage.get("total_tokens")
    if value is None:
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _cap_stop_reason(
    options: BenchmarkOptions,
    *,
    started_at: float,
    usage: dict[str, Any],
) -> str | None:
    if options.max_cost_usd is not None:
        estimated_cost = _estimate_usage_cost_usd(usage)
        if estimated_cost > options.max_cost_usd:
            return (
                f"estimated_cost_usd {estimated_cost:.6f} exceeded "
                f"max_cost_usd {options.max_cost_usd:.6f}"
            )
    if options.max_wallclock_seconds is not None:
        elapsed = time.monotonic() - started_at
        if elapsed > options.max_wallclock_seconds:
            return (
                f"wallclock_seconds {elapsed:.3f} exceeded "
                f"max_wallclock_seconds {options.max_wallclock_seconds:.3f}"
            )
    return None


def _estimate_usage_cost_usd(usage: dict[str, Any]) -> float:
    direct = _coerce_float(
        usage.get("estimated_cost_usd")
        or usage.get("cost_usd")
        or usage.get("total_cost_usd")
    )
    if direct is not None:
        return direct

    by_model = usage.get("by_model")
    if isinstance(by_model, dict):
        model_cost = 0.0
        has_model_cost = False
        for summary in by_model.values():
            if not isinstance(summary, dict):
                continue
            cost = _coerce_float(
                summary.get("estimated_cost_usd")
                or summary.get("cost_usd")
                or summary.get("total_cost_usd")
            )
            if cost is None:
                continue
            model_cost += cost
            has_model_cost = True
        if has_model_cost:
            return model_cost

    total_tokens = _coerce_float(usage.get("total_tokens")) or 0.0
    return total_tokens * _fallback_cost_usd_per_token()


def _fallback_cost_usd_per_token() -> float:
    raw = os.environ.get("METIS_BENCH_FALLBACK_USD_PER_MILLION_TOKENS", "1.0")
    value = _coerce_float(raw)
    if value is None or value < 0:
        value = 1.0
    return value / 1_000_000.0


def _coerce_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _model_name(engine) -> str:
    provider = getattr(engine, "llm_provider", None)
    if provider is not None:
        name = getattr(provider, "model", None) or getattr(provider, "model_name", None)
        if name:
            return str(name)
    return "unknown"


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"
