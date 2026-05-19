# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from metis.sarif.triage import METIS_TRIAGE_STATUS_KEY

from .manifest import BenchmarkCase, BenchmarkManifest, ExpectedFinding

NOT_APPLICABLE = "not_applicable"
_SEVERITY_ORDER = {
    "low": 1,
    "note": 1,
    "medium": 2,
    "warning": 2,
    "high": 3,
    "critical": 4,
    "error": 3,
}


@dataclass(frozen=True)
class ReportedFinding:
    file: str
    line: int
    cwe: str
    severity: str | None
    triage_status: str | None
    message: str


@dataclass(frozen=True)
class ExpectedRecord:
    case: BenchmarkCase
    finding: ExpectedFinding
    file: str


def score_sarif(
    payload: dict[str, Any],
    manifest: BenchmarkManifest,
    *,
    cases: tuple[BenchmarkCase, ...] | None = None,
    triage_enabled: bool = False,
) -> dict[str, Any]:
    selected_cases = cases or manifest.cases
    expected = _expected_records(manifest, selected_cases)
    reported = _extract_reported_findings(payload)
    active, inconclusive_count = _active_findings(
        reported,
        triage_enabled=triage_enabled,
    )
    matched_report_indices: set[int] = set()
    matched_expected_indices: set[int] = set()

    for expected_index, record in enumerate(expected):
        for report_index, finding in enumerate(active):
            if report_index in matched_report_indices:
                continue
            if _matches(record, finding, manifest):
                matched_expected_indices.add(expected_index)
                matched_report_indices.add(report_index)
                break

    tp_records = [expected[idx] for idx in sorted(matched_expected_indices)]
    fn_records = [
        record
        for idx, record in enumerate(expected)
        if idx not in matched_expected_indices
    ]
    fp_findings = [
        finding
        for idx, finding in enumerate(active)
        if idx not in matched_report_indices
    ]
    case_fp_counts, unmapped_fp_count = _case_fp_counts(fp_findings, selected_cases)

    totals = _metric_bucket(len(tp_records), len(fp_findings), len(fn_records))
    if triage_enabled:
        totals["inconclusive"] = inconclusive_count
        denominator = len(active) + inconclusive_count
        totals["inconclusive_rate"] = (
            inconclusive_count / denominator if denominator else 0.0
        )
    else:
        totals["inconclusive"] = NOT_APPLICABLE
        totals["inconclusive_rate"] = NOT_APPLICABLE

    return {
        "totals": totals,
        "by_cwe": _grouped_metrics(
            tp_records,
            fp_findings,
            fn_records,
            lambda expected_record: expected_record.finding.cwe,
            lambda finding: finding.cwe,
        ),
        "by_language": _grouped_metrics(
            tp_records,
            fp_findings,
            fn_records,
            lambda expected_record: expected_record.case.language,
            lambda finding: _language_for_reported_finding(finding, selected_cases),
        ),
        "cases": _case_metrics(
            selected_cases,
            tp_records,
            fn_records,
            case_fp_counts,
        ),
        "finding_counts": {
            "reported": len(reported),
            "active": len(active),
            "suppressed": len(reported) - len(active) - inconclusive_count,
            "unmapped_fp": unmapped_fp_count,
        },
    }


def compare_to_baseline(
    current: dict[str, Any],
    baseline: dict[str, Any],
    *,
    recall_tolerance: float,
) -> list[dict[str, Any]]:
    regressions: list[dict[str, Any]] = []
    if baseline.get("mode") and current.get("mode") != baseline.get("mode"):
        regressions.append(
            {
                "scope": "mode",
                "baseline": baseline.get("mode"),
                "current": current.get("mode"),
                "drop": NOT_APPLICABLE,
            }
        )
        return regressions
    for field in ("quick", "case_count", "case_ids"):
        if field in baseline and current.get(field) != baseline.get(field):
            regressions.append(
                {
                    "scope": field,
                    "baseline": baseline.get(field),
                    "current": current.get(field),
                    "drop": NOT_APPLICABLE,
                }
            )
    if regressions:
        return regressions

    for cwe, baseline_metrics in (baseline.get("by_cwe") or {}).items():
        if not isinstance(baseline_metrics, dict):
            continue
        baseline_recall = baseline_metrics.get("recall")
        current_recall = (current.get("by_cwe") or {}).get(cwe, {}).get("recall", 0.0)
        if not isinstance(baseline_recall, int | float):
            continue
        drop = float(baseline_recall) - float(current_recall)
        if drop > recall_tolerance:
            regressions.append(
                {
                    "scope": "cwe",
                    "cwe": cwe,
                    "baseline_recall": float(baseline_recall),
                    "current_recall": float(current_recall),
                    "drop": drop,
                    "tolerance": recall_tolerance,
                }
            )
    return regressions


def compare_perf_to_baseline(
    current: dict[str, Any],
    baseline: dict[str, Any],
    *,
    wallclock_tolerance: float = 0.20,
) -> list[dict[str, Any]]:
    regressions: list[dict[str, Any]] = []
    identity_regressions = _baseline_identity_regressions(current, baseline)
    if identity_regressions:
        return identity_regressions

    current_commands = current.get("commands") or {}
    baseline_commands = baseline.get("commands") or {}
    if not isinstance(current_commands, dict) or not isinstance(
        baseline_commands, dict
    ):
        return regressions

    for command, baseline_metrics in baseline_commands.items():
        if not isinstance(baseline_metrics, dict):
            continue
        current_metrics = current_commands.get(command)
        if not isinstance(current_metrics, dict):
            continue
        baseline_wallclock = _nonnegative_float(
            baseline_metrics.get("wallclock_seconds")
        )
        current_wallclock = _nonnegative_float(current_metrics.get("wallclock_seconds"))
        if baseline_wallclock is None or current_wallclock is None:
            continue
        limit = baseline_wallclock * (1.0 + wallclock_tolerance)
        if current_wallclock > limit:
            regressions.append(
                {
                    "scope": "perf",
                    "command": command,
                    "metric": "wallclock_seconds",
                    "baseline": baseline_wallclock,
                    "current": current_wallclock,
                    "tolerance": wallclock_tolerance,
                    "limit": limit,
                }
            )
    return regressions


def compare_perf_observations(
    current: dict[str, Any],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    if _baseline_identity_regressions(current, baseline):
        return []

    observations: list[dict[str, Any]] = []
    current_commands = current.get("commands") or {}
    baseline_commands = baseline.get("commands") or {}
    if not isinstance(current_commands, dict) or not isinstance(
        baseline_commands, dict
    ):
        return observations

    for command, baseline_metrics in baseline_commands.items():
        if not isinstance(baseline_metrics, dict):
            continue
        current_metrics = current_commands.get(command)
        if not isinstance(current_metrics, dict):
            continue
        baseline_tokens = _nonnegative_int(baseline_metrics.get("total_tokens"))
        current_tokens = _nonnegative_int(current_metrics.get("total_tokens"))
        if baseline_tokens is None or current_tokens is None:
            continue
        observations.append(
            {
                "scope": "perf",
                "command": command,
                "metric": "total_tokens",
                "baseline": baseline_tokens,
                "current": current_tokens,
                "delta": current_tokens - baseline_tokens,
            }
        )
    return observations


def _baseline_identity_regressions(
    current: dict[str, Any], baseline: dict[str, Any]
) -> list[dict[str, Any]]:
    regressions: list[dict[str, Any]] = []
    if baseline.get("mode") and current.get("mode") != baseline.get("mode"):
        regressions.append(
            {
                "scope": "mode",
                "baseline": baseline.get("mode"),
                "current": current.get("mode"),
                "drop": NOT_APPLICABLE,
            }
        )
        return regressions
    for field in ("quick", "case_count", "case_ids"):
        if field in baseline and current.get(field) != baseline.get(field):
            regressions.append(
                {
                    "scope": field,
                    "baseline": baseline.get(field),
                    "current": current.get(field),
                    "drop": NOT_APPLICABLE,
                }
            )
    return regressions


def _nonnegative_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _nonnegative_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _expected_records(
    manifest: BenchmarkManifest, cases: tuple[BenchmarkCase, ...]
) -> list[ExpectedRecord]:
    records: list[ExpectedRecord] = []
    for case in cases:
        for finding in case.expected_findings:
            records.append(
                ExpectedRecord(
                    case=case,
                    finding=finding,
                    file=_normalise_path(str(Path(case.path) / finding.file)),
                )
            )
    return records


def _extract_reported_findings(payload: dict[str, Any]) -> list[ReportedFinding]:
    findings: list[ReportedFinding] = []
    runs = payload.get("runs")
    if not isinstance(runs, list):
        return findings
    for run in runs:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            findings.append(_reported_from_result(result))
    return findings


def _reported_from_result(result: dict[str, Any]) -> ReportedFinding:
    properties_raw = result.get("properties")
    properties: dict[str, Any] = (
        properties_raw if isinstance(properties_raw, dict) else {}
    )
    locations = result.get("locations")
    first_location = locations[0] if isinstance(locations, list) and locations else {}
    if not isinstance(first_location, dict):
        first_location = {}
    location = first_location.get("physicalLocation")
    location_dict: dict[str, Any] = location if isinstance(location, dict) else {}
    artifact_raw = location_dict.get("artifactLocation")
    artifact: dict[str, Any] = artifact_raw if isinstance(artifact_raw, dict) else {}
    region_raw = location_dict.get("region")
    region: dict[str, Any] = region_raw if isinstance(region_raw, dict) else {}
    message = result.get("message") or {}
    cwe = properties.get("cwe") or result.get("ruleId") or "CWE-Unknown"
    return ReportedFinding(
        file=_normalise_path(str(artifact.get("uri") or "")),
        line=_positive_int(region.get("startLine"), default=1),
        cwe=str(cwe),
        severity=str(properties.get("severity") or result.get("level") or "") or None,
        triage_status=_normalise_status(
            properties.get(METIS_TRIAGE_STATUS_KEY) or properties.get("triage_status")
        ),
        message=str(message.get("text") if isinstance(message, dict) else message),
    )


def _active_findings(
    findings: list[ReportedFinding], *, triage_enabled: bool
) -> tuple[list[ReportedFinding], int]:
    if not triage_enabled:
        return findings, 0
    active: list[ReportedFinding] = []
    inconclusive = 0
    for finding in findings:
        if finding.triage_status == "invalid":
            continue
        if finding.triage_status == "inconclusive":
            inconclusive += 1
            continue
        active.append(finding)
    return active, inconclusive


def _matches(
    expected: ExpectedRecord,
    reported: ReportedFinding,
    manifest: BenchmarkManifest,
) -> bool:
    return (
        _path_matches(expected.file, reported.file)
        and _cwe_matches(expected.finding.cwe, reported.cwe, manifest)
        and _line_matches(
            expected.finding.line_range, reported.line, manifest.line_tolerance
        )
        and _severity_matches(expected.finding.severity_min, reported.severity)
    )


def _path_matches(expected: str, reported: str) -> bool:
    expected_norm = _normalise_path(expected)
    reported_norm = _normalise_path(reported)
    if expected_norm == reported_norm:
        return True
    return reported_norm.endswith(f"/{expected_norm}") or expected_norm.endswith(
        f"/{reported_norm}"
    )


def _language_for_reported_finding(
    finding: ReportedFinding, cases: tuple[BenchmarkCase, ...]
) -> str:
    case = _case_for_reported_finding(finding, cases)
    return case.language if case else "unknown"


def _case_for_reported_finding(
    finding: ReportedFinding, cases: tuple[BenchmarkCase, ...]
) -> BenchmarkCase | None:
    reported = _normalise_path(finding.file)
    for case in cases:
        case_path = _normalise_path(case.path)
        if (
            reported == case_path
            or reported.startswith(f"{case_path}/")
            or reported.endswith(f"/{case_path}")
            or f"/{case_path}/" in reported
        ):
            return case
    return None


def _cwe_matches(expected: str, reported: str, manifest: BenchmarkManifest) -> bool:
    if expected == reported:
        return True
    expected_group = manifest.cwe_equivalence.get(expected, (expected,))
    reported_group = manifest.cwe_equivalence.get(reported, (reported,))
    return bool(set(expected_group) & set(reported_group))


def _line_matches(line_range: tuple[int, int], line: int, tolerance: int) -> bool:
    start, end = line_range
    return start - tolerance <= line <= end + tolerance


def _severity_matches(expected_min: str | None, reported: str | None) -> bool:
    if not expected_min:
        return True
    if not reported:
        return False
    return _severity_value(reported) >= _severity_value(expected_min)


def _severity_value(value: str) -> int:
    return _SEVERITY_ORDER.get(str(value).strip().lower(), 0)


def _metric_bucket(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _grouped_metrics(
    tp_records: list[ExpectedRecord],
    fp_findings: list[ReportedFinding],
    fn_records: list[ExpectedRecord],
    expected_key,
    reported_key,
) -> dict[str, dict[str, Any]]:
    keys = {
        *(expected_key(record) for record in tp_records),
        *(expected_key(record) for record in fn_records),
        *(reported_key(finding) for finding in fp_findings),
    }
    grouped: dict[str, dict[str, Any]] = {}
    for key in sorted(str(item) for item in keys if item):
        grouped[key] = _metric_bucket(
            sum(1 for record in tp_records if str(expected_key(record)) == key),
            sum(1 for finding in fp_findings if str(reported_key(finding)) == key),
            sum(1 for record in fn_records if str(expected_key(record)) == key),
        )
    return grouped


def _case_metrics(
    cases: tuple[BenchmarkCase, ...],
    tp_records: list[ExpectedRecord],
    fn_records: list[ExpectedRecord],
    fp_counts: dict[str, int],
) -> dict[str, dict[str, Any]]:
    return {
        case.id: _metric_bucket(
            sum(1 for record in tp_records if record.case.id == case.id),
            fp_counts.get(case.id, 0),
            sum(1 for record in fn_records if record.case.id == case.id),
        )
        for case in cases
    }


def _case_fp_counts(
    fp_findings: list[ReportedFinding], cases: tuple[BenchmarkCase, ...]
) -> tuple[dict[str, int], int]:
    counts: dict[str, int] = {}
    unmapped = 0
    for finding in fp_findings:
        case = _case_for_reported_finding(finding, cases)
        if case is None:
            unmapped += 1
            continue
        counts[case.id] = counts.get(case.id, 0) + 1
    return counts, unmapped


def _normalise_status(value: Any) -> str | None:
    if value is None:
        return None
    status = str(value).strip().lower()
    if status in {"valid", "true_positive", "true-positive"}:
        return "valid"
    if status in {"invalid", "false_positive", "false-positive"}:
        return "invalid"
    if status == "inconclusive":
        return "inconclusive"
    return status or None


def _positive_int(value: Any, *, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return parsed if parsed > 0 else default


def _normalise_path(value: str) -> str:
    return value.replace("\\", "/").strip("./")
