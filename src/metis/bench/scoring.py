# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from metis.sarif.triage import METIS_TRIAGE_STATUS_KEY

from .manifest import (
    BenchmarkCase,
    BenchmarkManifest,
    ExpectedFinding,
    ExpectedHypothesis,
)

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
_HYPOTHESIS_STATUSES = ("proven", "killed", "unresolved")
_NATIVE_HARDWARE_HUNTERS = {"hardware_security", "memory_lifetime"}
_WEB_APP_HUNTERS = {
    "authz_outlier",
    "deserialization",
    "injection_path",
    "path_traversal",
    "ssrf",
    "variant_patch",
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


@dataclass(frozen=True)
class ReportedHypothesis:
    case_id: str | None
    id: str | None
    hunter: str
    vulnerability_class: str
    status: str
    file: str
    line: int | None
    symbol: str | None
    lesson_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExpectedHypothesisRecord:
    case: BenchmarkCase
    hypothesis: ExpectedHypothesis
    file: str | None


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


def score_hypotheses(
    hypotheses: list[Any],
    manifest: BenchmarkManifest,
    *,
    cases: tuple[BenchmarkCase, ...] | None = None,
    research_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selected_cases = cases or manifest.cases
    expected = _expected_hypothesis_records(manifest, selected_cases)
    reported = _extract_reported_hypotheses(hypotheses)
    matched_report_indices: set[int] = set()
    matched_expected_indices: set[int] = set()

    for expected_index, record in enumerate(expected):
        for report_index, hypothesis in enumerate(reported):
            if report_index in matched_report_indices:
                continue
            if _hypothesis_matches(
                record,
                hypothesis,
                manifest,
                require_case_id=len(selected_cases) > 1,
            ):
                matched_expected_indices.add(expected_index)
                matched_report_indices.add(report_index)
                break

    status_metrics = _hypothesis_status_metrics(
        expected,
        matched_expected_indices,
        reported,
        matched_report_indices,
    )
    expected_proven = _expected_hypotheses_with_status(expected, "proven")
    matched_expected_proven = [
        expected[idx]
        for idx in sorted(matched_expected_indices)
        if _normalized_hypothesis_status(expected[idx].hypothesis.status) == "proven"
    ]
    reported_proven = _reported_hypotheses_with_status(reported, "proven")
    matched_reported_proven = [
        reported[idx]
        for idx in sorted(matched_report_indices)
        if reported[idx].status == "proven"
    ]
    quality_metrics = _research_quality_metrics(
        hypotheses,
        proven_count=len(reported_proven),
        research_metrics=research_metrics,
    )

    return {
        "generated": len(reported),
        "proven": sum(1 for item in reported if item.status == "proven"),
        "killed": sum(1 for item in reported if item.status == "killed"),
        "unresolved": sum(1 for item in reported if item.status == "unresolved"),
        "lessons_reused": _lessons_reused(
            reported,
            _research_metric_lesson_refs(research_metrics),
        ),
        **quality_metrics,
        "expected": len(expected),
        **_hypothesis_status_summary(status_metrics),
        "false_positive_rate": status_metrics["proven"]["false_positive_rate"],
        "proven_recall_by_class": _hypothesis_recall_by_class(
            expected_proven,
            matched_expected_proven,
        ),
        "false_positive_rate_by_class": _hypothesis_fpr_by_class(
            reported_proven,
            matched_reported_proven,
        ),
        "by_class": _hypothesis_metrics_by_class(
            expected,
            matched_expected_indices,
            reported,
            matched_report_indices,
        ),
        "by_domain": _hypothesis_metrics_by_domain(
            expected,
            matched_expected_indices,
            reported,
            matched_report_indices,
        ),
        "by_status": status_metrics,
        "cases": _hypothesis_case_metrics(
            selected_cases,
            expected,
            matched_expected_indices,
            reported,
            matched_report_indices,
            research_metrics,
        ),
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
    regressions.extend(
        _hypothesis_baseline_regressions(
            current.get("hypotheses"),
            baseline.get("hypotheses"),
            recall_tolerance=recall_tolerance,
        )
    )
    return regressions


def _hypothesis_baseline_regressions(
    current: Any,
    baseline: Any,
    *,
    recall_tolerance: float,
) -> list[dict[str, Any]]:
    if not isinstance(current, dict) or not isinstance(baseline, dict):
        return []
    regressions: list[dict[str, Any]] = []
    for vulnerability_class, baseline_recall in (
        baseline.get("proven_recall_by_class") or {}
    ).items():
        if not isinstance(baseline_recall, int | float):
            continue
        current_recall = (current.get("proven_recall_by_class") or {}).get(
            vulnerability_class,
            0.0,
        )
        drop = float(baseline_recall) - float(current_recall)
        if drop > recall_tolerance:
            regressions.append(
                {
                    "scope": "hypothesis_recall",
                    "vulnerability_class": vulnerability_class,
                    "baseline_recall": float(baseline_recall),
                    "current_recall": float(current_recall),
                    "drop": drop,
                    "tolerance": recall_tolerance,
                }
            )

    baseline_rates = baseline.get("false_positive_rate_by_class") or {}
    current_rates = current.get("false_positive_rate_by_class") or {}
    if not isinstance(baseline_rates, dict):
        baseline_rates = {}
    if not isinstance(current_rates, dict):
        current_rates = {}
    for vulnerability_class in sorted(
        {str(key) for key in (*baseline_rates.keys(), *current_rates.keys())}
    ):
        baseline_rate = baseline_rates.get(vulnerability_class, 0.0)
        if not isinstance(baseline_rate, int | float):
            continue
        current_rate = current_rates.get(vulnerability_class, 0.0)
        increase = float(current_rate) - float(baseline_rate)
        if increase > recall_tolerance:
            regressions.append(
                {
                    "scope": "hypothesis_false_positive_rate",
                    "vulnerability_class": vulnerability_class,
                    "baseline_rate": float(baseline_rate),
                    "current_rate": float(current_rate),
                    "increase": increase,
                    "tolerance": recall_tolerance,
                }
            )
    baseline_evidence = baseline.get("evidence_completeness_rate")
    current_evidence = current.get("evidence_completeness_rate")
    if isinstance(baseline_evidence, int | float) and isinstance(
        current_evidence,
        int | float,
    ):
        drop = float(baseline_evidence) - float(current_evidence)
        if drop > recall_tolerance:
            regressions.append(
                {
                    "scope": "hypothesis_evidence_completeness",
                    "baseline_rate": float(baseline_evidence),
                    "current_rate": float(current_evidence),
                    "drop": drop,
                    "tolerance": recall_tolerance,
                }
            )
    baseline_evidence_by_class = baseline.get("evidence_completeness_rate_by_class")
    current_evidence_by_class = current.get("evidence_completeness_rate_by_class")
    if not isinstance(baseline_evidence_by_class, dict):
        baseline_evidence_by_class = {}
    if not isinstance(current_evidence_by_class, dict):
        current_evidence_by_class = {}
    for vulnerability_class in sorted(
        {
            str(key)
            for key in (
                *baseline_evidence_by_class.keys(),
                *current_evidence_by_class.keys(),
            )
        }
    ):
        baseline_rate = baseline_evidence_by_class.get(vulnerability_class)
        current_rate = current_evidence_by_class.get(vulnerability_class)
        if not isinstance(baseline_rate, int | float) or not isinstance(
            current_rate,
            int | float,
        ):
            continue
        drop = float(baseline_rate) - float(current_rate)
        if drop > recall_tolerance:
            regressions.append(
                {
                    "scope": "hypothesis_evidence_completeness_by_class",
                    "vulnerability_class": vulnerability_class,
                    "baseline_rate": float(baseline_rate),
                    "current_rate": float(current_rate),
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


def _expected_hypothesis_records(
    manifest: BenchmarkManifest, cases: tuple[BenchmarkCase, ...]
) -> list[ExpectedHypothesisRecord]:
    records: list[ExpectedHypothesisRecord] = []
    for case in cases:
        for hypothesis in case.expected_hypotheses:
            file_path = None
            if hypothesis.file:
                file_path = _normalise_path(str(Path(case.path) / hypothesis.file))
            records.append(
                ExpectedHypothesisRecord(
                    case=case,
                    hypothesis=hypothesis,
                    file=file_path,
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


def _extract_reported_hypotheses(hypotheses: list[Any]) -> list[ReportedHypothesis]:
    reported: list[ReportedHypothesis] = []
    for raw in hypotheses:
        payload = _hypothesis_payload(raw)
        if not isinstance(payload, dict):
            continue
        location = _primary_hypothesis_location(payload)
        reported.append(
            ReportedHypothesis(
                case_id=(
                    str(payload["case_id"]).strip() if payload.get("case_id") else None
                ),
                id=str(payload["id"]).strip() if payload.get("id") else None,
                hunter=str(payload.get("hunter") or ""),
                vulnerability_class=str(
                    payload.get("vulnerability_class") or payload.get("cwe") or ""
                ),
                status=_normalized_hypothesis_status(payload.get("status")),
                file=str(location.get("file") or ""),
                line=_positive_int_or_none(location.get("line")),
                symbol=(
                    str(location["symbol"]).strip() if location.get("symbol") else None
                ),
                lesson_refs=_lesson_refs(payload.get("lesson_refs")),
            )
        )
    return reported


def _hypothesis_payload(raw: Any) -> dict[str, Any] | None:
    dump = getattr(raw, "model_dump", None)
    if callable(dump):
        payload = dump(mode="json")
        return payload if isinstance(payload, dict) else None
    return raw if isinstance(raw, dict) else None


def _lesson_refs(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, list | tuple | set):
        return ()
    return tuple(sorted({str(ref).strip() for ref in raw if str(ref).strip()}))


def _lessons_reused(
    hypotheses: list[ReportedHypothesis],
    extra_lesson_refs: set[str] | None = None,
) -> int:
    refs = {ref for hypothesis in hypotheses for ref in hypothesis.lesson_refs}
    if extra_lesson_refs:
        refs.update(extra_lesson_refs)
    return len(refs)


def _research_metric_lesson_refs(research_metrics: dict[str, Any] | None) -> set[str]:
    if not isinstance(research_metrics, dict):
        return set()
    refs = set(_lesson_refs_from_metric_summary(research_metrics))
    cases = research_metrics.get("cases")
    if isinstance(cases, dict):
        for case_metrics in cases.values():
            refs.update(_lesson_refs_from_metric_summary(case_metrics))
    return refs


def _research_quality_metrics(
    hypotheses: list[Any],
    *,
    proven_count: int,
    research_metrics: dict[str, Any] | None,
) -> dict[str, Any]:
    analysis_budget = _analysis_budget_summary(research_metrics)
    total_tokens = int(analysis_budget["total_tokens"])
    wallclock_seconds = float(analysis_budget["wallclock_seconds"])
    return {
        "evidence_completeness_rate": _evidence_completeness_rate(hypotheses),
        "evidence_completeness_rate_by_class": (
            _evidence_completeness_rate_by_class(hypotheses)
        ),
        "average_tokens_per_proven_finding": (
            total_tokens / proven_count if proven_count else 0.0
        ),
        "average_wallclock_seconds_per_proven_finding": (
            wallclock_seconds / proven_count if proven_count else 0.0
        ),
        "findings_with_local_proof_artifacts": (
            _findings_with_local_proof_artifacts(hypotheses)
        ),
        "analysis_budget": analysis_budget,
        "proven_vulnerabilities_per_analysis_budget": {
            "per_1000_tokens": (
                proven_count / (total_tokens / 1000.0)
                if total_tokens > 0
                else NOT_APPLICABLE
            ),
            "per_wallclock_second": (
                proven_count / wallclock_seconds
                if wallclock_seconds > 0
                else NOT_APPLICABLE
            ),
        },
    }


def _analysis_budget_summary(
    research_metrics: dict[str, Any] | None,
) -> dict[str, Any]:
    command = _research_command_metrics(research_metrics)
    tokens = _nonnegative_int(command.get("total_tokens")) or 0
    wallclock = _nonnegative_float(command.get("wallclock_seconds")) or 0.0
    return {
        "research_budgets": _research_budget_labels(research_metrics),
        "total_tokens": tokens,
        "wallclock_seconds": wallclock,
    }


def _research_command_metrics(research_metrics: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(research_metrics, dict):
        return {}
    command = research_metrics.get("research_command")
    if isinstance(command, dict):
        return command
    commands = research_metrics.get("commands")
    if isinstance(commands, dict) and isinstance(commands.get("research"), dict):
        return commands["research"]
    return {}


def _research_budget_labels(
    research_metrics: dict[str, Any] | None,
) -> tuple[str, ...]:
    if not isinstance(research_metrics, dict):
        return ()
    labels: set[str] = set()
    direct = research_metrics.get("research_budget")
    if direct:
        labels.add(str(direct))
    _collect_budget_label(labels, research_metrics)
    cases = research_metrics.get("cases")
    if isinstance(cases, dict):
        for case_metrics in cases.values():
            _collect_budget_label(labels, case_metrics)
    return tuple(sorted(labels))


def _collect_budget_label(labels: set[str], metrics: Any) -> None:
    if not isinstance(metrics, dict):
        return
    value = metrics.get("research_budget")
    if value:
        labels.add(str(value))
    budget = metrics.get("analysis_budget")
    if isinstance(budget, dict):
        budget_value = budget.get("research_budget") or budget.get("label")
        if budget_value:
            labels.add(str(budget_value))


def _evidence_completeness_rate(hypotheses: list[Any]) -> float:
    completed, required = _evidence_completeness_counts(hypotheses)
    return completed / required if required else 0.0


def _evidence_completeness_rate_by_class(hypotheses: list[Any]) -> dict[str, float]:
    by_class: dict[str, tuple[int, int]] = {}
    for payload in _hypothesis_payloads(hypotheses):
        vulnerability_class = str(
            payload.get("vulnerability_class") or payload.get("cwe") or ""
        ).strip()
        if not vulnerability_class:
            continue
        completed, required = _evidence_completeness_counts([payload])
        current_completed, current_required = by_class.get(vulnerability_class, (0, 0))
        by_class[vulnerability_class] = (
            current_completed + completed,
            current_required + required,
        )
    return {
        vulnerability_class: completed / required if required else 0.0
        for vulnerability_class, (completed, required) in sorted(by_class.items())
    }


def _evidence_completeness_counts(hypotheses: list[Any]) -> tuple[int, int]:
    completed = 0
    required = 0
    for payload in _hypothesis_payloads(hypotheses):
        required_obligations = _required_obligation_names(payload)
        if not required_obligations:
            continue
        evidence_statuses = _evidence_statuses_by_obligation(payload)
        for obligation in required_obligations:
            required += 1
            statuses = evidence_statuses.get(obligation, set())
            if statuses & {"satisfied", "failed", "not_applicable"}:
                completed += 1
    return completed, required


def _hypothesis_payloads(hypotheses: list[Any]) -> list[dict[str, Any]]:
    return [
        payload
        for payload in (_hypothesis_payload(item) for item in hypotheses)
        if isinstance(payload, dict)
    ]


def _required_obligation_names(payload: dict[str, Any]) -> tuple[str, ...]:
    obligations = payload.get("evidence_obligations")
    if not isinstance(obligations, list | tuple):
        return ()
    names: list[str] = []
    for raw in obligations:
        if not isinstance(raw, dict):
            continue
        if raw.get("required", True) is False:
            continue
        name = str(raw.get("name") or "").strip()
        if name:
            names.append(name)
    return tuple(sorted(set(names)))


def _evidence_statuses_by_obligation(
    payload: dict[str, Any],
) -> dict[str, set[str]]:
    entries = payload.get("evidence")
    if not isinstance(entries, list | tuple):
        return {}
    statuses: dict[str, set[str]] = {}
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        obligation = str(raw.get("obligation") or "").strip()
        if not obligation:
            continue
        status = str(raw.get("status") or "").strip().lower()
        if status:
            statuses.setdefault(obligation, set()).add(status)
    return statuses


def _findings_with_local_proof_artifacts(hypotheses: list[Any]) -> int:
    count = 0
    for payload in _hypothesis_payloads(hypotheses):
        if _normalized_hypothesis_status(payload.get("status")) != "proven":
            continue
        if _has_local_proof_artifact(payload):
            count += 1
    return count


def _has_local_proof_artifact(payload: dict[str, Any]) -> bool:
    entries = payload.get("evidence")
    if not isinstance(entries, list | tuple):
        return False
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("kind") or "").strip().lower() == "proof_artifact":
            return True
        if str(raw.get("obligation") or "").strip().lower() == "proof_artifact":
            return True
    return False


def _case_research_metric_lesson_refs(
    research_metrics: dict[str, Any] | None,
    case: BenchmarkCase,
    cases: tuple[BenchmarkCase, ...],
) -> set[str]:
    if not isinstance(research_metrics, dict):
        return set()
    case_metrics_by_id = research_metrics.get("cases")
    if isinstance(case_metrics_by_id, dict):
        return set(_lesson_refs_from_metric_summary(case_metrics_by_id.get(case.id)))
    if len(cases) == 1:
        return set(_lesson_refs_from_metric_summary(research_metrics))
    return set()


def _lesson_refs_from_metric_summary(metric_summary: Any) -> tuple[str, ...]:
    if not isinstance(metric_summary, dict):
        return ()
    refs: set[str] = set(_lesson_refs(metric_summary.get("lesson_refs")))
    lessons = metric_summary.get("lessons")
    if isinstance(lessons, dict):
        refs.update(_lesson_refs(lessons.get("lesson_refs")))
    return tuple(sorted(refs))


def _primary_hypothesis_location(payload: dict[str, Any]) -> dict[str, Any]:
    for key in ("locations", "path"):
        values = payload.get(key)
        if isinstance(values, list) and values and isinstance(values[0], dict):
            return values[0]
    return {}


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


def _hypothesis_matches(
    expected: ExpectedHypothesisRecord,
    reported: ReportedHypothesis,
    manifest: BenchmarkManifest,
    *,
    require_case_id: bool = False,
) -> bool:
    item = expected.hypothesis
    if reported.case_id is not None and reported.case_id != expected.case.id:
        return False
    if reported.case_id is None and require_case_id:
        return False
    if item.id and item.id != reported.id:
        return False
    if item.hunter and item.hunter != reported.hunter:
        return False
    if not _cwe_matches(
        item.vulnerability_class, reported.vulnerability_class, manifest
    ):
        return False
    if _normalized_hypothesis_status(item.status) != reported.status:
        return False
    if expected.file and not _path_matches(expected.file, reported.file):
        return False
    if item.symbol and item.symbol != reported.symbol:
        return False
    if item.line_range is not None:
        if reported.line is None:
            return False
        if not _line_matches(item.line_range, reported.line, manifest.line_tolerance):
            return False
    return True


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


def _hypothesis_recall_by_class(
    expected_proven: list[ExpectedHypothesisRecord],
    matched_expected_proven: list[ExpectedHypothesisRecord],
) -> dict[str, float]:
    classes = {
        record.hypothesis.vulnerability_class
        for record in (*expected_proven, *matched_expected_proven)
    }
    recall: dict[str, float] = {}
    for vulnerability_class in sorted(classes):
        expected_count = sum(
            1
            for record in expected_proven
            if record.hypothesis.vulnerability_class == vulnerability_class
        )
        matched_count = sum(
            1
            for record in matched_expected_proven
            if record.hypothesis.vulnerability_class == vulnerability_class
        )
        recall[vulnerability_class] = (
            matched_count / expected_count if expected_count else 0.0
        )
    return recall


def _hypothesis_fpr_by_class(
    reported_proven: list[ReportedHypothesis],
    matched_reported_proven: list[ReportedHypothesis],
) -> dict[str, float]:
    classes = {
        item.vulnerability_class
        for item in (*reported_proven, *matched_reported_proven)
    }
    rates: dict[str, float] = {}
    for vulnerability_class in sorted(classes):
        reported_count = sum(
            1
            for item in reported_proven
            if item.vulnerability_class == vulnerability_class
        )
        matched_count = sum(
            1
            for item in matched_reported_proven
            if item.vulnerability_class == vulnerability_class
        )
        fp_count = max(0, reported_count - matched_count)
        rates[vulnerability_class] = (
            fp_count / reported_count if reported_count else 0.0
        )
    return rates


def _expected_hypotheses_with_status(
    expected: list[ExpectedHypothesisRecord],
    status: str,
) -> list[ExpectedHypothesisRecord]:
    return [
        record
        for record in expected
        if _normalized_hypothesis_status(record.hypothesis.status) == status
    ]


def _reported_hypotheses_with_status(
    reported: list[ReportedHypothesis],
    status: str,
) -> list[ReportedHypothesis]:
    return [hypothesis for hypothesis in reported if hypothesis.status == status]


def _hypothesis_status_metrics(
    expected: list[ExpectedHypothesisRecord],
    matched_expected_indices: set[int],
    reported: list[ReportedHypothesis],
    matched_report_indices: set[int],
) -> dict[str, dict[str, Any]]:
    statuses = {
        *_HYPOTHESIS_STATUSES,
        *(
            _normalized_hypothesis_status(record.hypothesis.status)
            for record in expected
        ),
        *(hypothesis.status for hypothesis in reported),
    }
    metrics: dict[str, dict[str, Any]] = {}
    for status in sorted(item for item in statuses if item):
        expected_indices = [
            idx
            for idx, record in enumerate(expected)
            if _normalized_hypothesis_status(record.hypothesis.status) == status
        ]
        reported_indices = [
            idx
            for idx, hypothesis in enumerate(reported)
            if hypothesis.status == status
        ]
        tp = len([idx for idx in expected_indices if idx in matched_expected_indices])
        fp = len([idx for idx in reported_indices if idx not in matched_report_indices])
        fn = len(
            [idx for idx in expected_indices if idx not in matched_expected_indices]
        )
        bucket = _metric_bucket(tp, fp, fn)
        bucket["expected"] = len(expected_indices)
        bucket["reported"] = len(reported_indices)
        bucket["false_positive_rate"] = (
            fp / len(reported_indices) if reported_indices else 0.0
        )
        metrics[status] = bucket
    return metrics


def _hypothesis_status_summary(
    status_metrics: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for status in _HYPOTHESIS_STATUSES:
        metrics = status_metrics.get(status) or _metric_bucket(0, 0, 0)
        summary[f"expected_{status}"] = int(metrics.get("expected", 0))
        summary[f"{status}_tp"] = int(metrics.get("tp", 0))
        summary[f"{status}_fp"] = int(metrics.get("fp", 0))
        summary[f"{status}_fn"] = int(metrics.get("fn", 0))
        summary[f"{status}_recall"] = float(metrics.get("recall", 0.0))
    return summary


def _hypothesis_metrics_by_class(
    expected: list[ExpectedHypothesisRecord],
    matched_expected_indices: set[int],
    reported: list[ReportedHypothesis],
    matched_report_indices: set[int],
) -> dict[str, dict[str, Any]]:
    classes = {
        *(record.hypothesis.vulnerability_class for record in expected),
        *(item.vulnerability_class for item in reported),
    }
    metrics: dict[str, dict[str, Any]] = {}
    for vulnerability_class in sorted(item for item in classes if item):
        generated = [
            item for item in reported if item.vulnerability_class == vulnerability_class
        ]
        proven = [item for item in generated if item.status == "proven"]
        class_metrics: dict[str, Any] = {
            "generated": len(generated),
            "proven": len(proven),
            "killed": sum(1 for item in generated if item.status == "killed"),
            "unresolved": sum(1 for item in generated if item.status == "unresolved"),
        }
        for status in _HYPOTHESIS_STATUSES:
            expected_indices = [
                idx
                for idx, record in enumerate(expected)
                if record.hypothesis.vulnerability_class == vulnerability_class
                and _normalized_hypothesis_status(record.hypothesis.status) == status
            ]
            reported_indices = [
                idx
                for idx, hypothesis in enumerate(reported)
                if hypothesis.vulnerability_class == vulnerability_class
                and hypothesis.status == status
            ]
            tp = len(
                [idx for idx in expected_indices if idx in matched_expected_indices]
            )
            fp = len(
                [idx for idx in reported_indices if idx not in matched_report_indices]
            )
            fn = len(
                [idx for idx in expected_indices if idx not in matched_expected_indices]
            )
            class_metrics[f"{status}_tp"] = tp
            class_metrics[f"{status}_fp"] = fp
            class_metrics[f"{status}_fn"] = fn
            class_metrics[f"{status}_recall"] = tp / (tp + fn) if tp + fn else 0.0
            if status == "proven":
                class_metrics["false_positive_rate"] = (
                    fp / len(reported_indices) if reported_indices else 0.0
                )
        metrics[vulnerability_class] = class_metrics
    return metrics


def _hypothesis_metrics_by_domain(
    expected: list[ExpectedHypothesisRecord],
    matched_expected_indices: set[int],
    reported: list[ReportedHypothesis],
    matched_report_indices: set[int],
) -> dict[str, dict[str, Any]]:
    domains = {
        *(_hypothesis_domain(record.hypothesis.hunter) for record in expected),
        *(_hypothesis_domain(item.hunter) for item in reported),
    }
    metrics: dict[str, dict[str, Any]] = {}
    for domain in sorted(item for item in domains if item):
        generated = [
            item for item in reported if _hypothesis_domain(item.hunter) == domain
        ]
        domain_metrics: dict[str, Any] = {
            "generated": len(generated),
            "proven": sum(1 for item in generated if item.status == "proven"),
            "killed": sum(1 for item in generated if item.status == "killed"),
            "unresolved": sum(1 for item in generated if item.status == "unresolved"),
        }
        for status in _HYPOTHESIS_STATUSES:
            expected_indices = [
                idx
                for idx, record in enumerate(expected)
                if _hypothesis_domain(record.hypothesis.hunter) == domain
                and _normalized_hypothesis_status(record.hypothesis.status) == status
            ]
            reported_indices = [
                idx
                for idx, hypothesis in enumerate(reported)
                if _hypothesis_domain(hypothesis.hunter) == domain
                and hypothesis.status == status
            ]
            tp = len(
                [idx for idx in expected_indices if idx in matched_expected_indices]
            )
            fp = len(
                [idx for idx in reported_indices if idx not in matched_report_indices]
            )
            fn = len(
                [idx for idx in expected_indices if idx not in matched_expected_indices]
            )
            domain_metrics[f"{status}_tp"] = tp
            domain_metrics[f"{status}_fp"] = fp
            domain_metrics[f"{status}_fn"] = fn
            domain_metrics[f"{status}_recall"] = tp / (tp + fn) if tp + fn else 0.0
            if status == "proven":
                domain_metrics["false_positive_rate"] = (
                    fp / len(reported_indices) if reported_indices else 0.0
                )
        metrics[domain] = domain_metrics
    return metrics


def _hypothesis_domain(hunter: str) -> str:
    normalized = str(hunter or "").strip()
    if normalized in _NATIVE_HARDWARE_HUNTERS:
        return "native_hardware"
    if normalized in _WEB_APP_HUNTERS:
        return "web_app"
    return "other"


def _hypothesis_case_metrics(
    cases: tuple[BenchmarkCase, ...],
    expected: list[ExpectedHypothesisRecord],
    matched_expected_indices: set[int],
    reported: list[ReportedHypothesis],
    matched_report_indices: set[int],
    research_metrics: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    metrics: dict[str, dict[str, Any]] = {}
    require_case_id = len(cases) > 1
    for case in cases:
        case_expected_indices = [
            idx for idx, record in enumerate(expected) if record.case.id == case.id
        ]
        case_report_indices = [
            idx
            for idx, hypothesis in enumerate(reported)
            if _case_for_reported_hypothesis(
                hypothesis,
                cases,
                require_case_id=require_case_id,
            )
            == case
        ]
        case_metrics: dict[str, Any] = {
            "generated": len(case_report_indices),
            "proven": sum(
                1 for idx in case_report_indices if reported[idx].status == "proven"
            ),
            "killed": sum(
                1 for idx in case_report_indices if reported[idx].status == "killed"
            ),
            "unresolved": sum(
                1 for idx in case_report_indices if reported[idx].status == "unresolved"
            ),
            "lessons_reused": _lessons_reused(
                [reported[idx] for idx in case_report_indices],
                _case_research_metric_lesson_refs(research_metrics, case, cases),
            ),
        }
        for status in _HYPOTHESIS_STATUSES:
            expected_indices = [
                idx
                for idx in case_expected_indices
                if _normalized_hypothesis_status(expected[idx].hypothesis.status)
                == status
            ]
            reported_indices = [
                idx for idx in case_report_indices if reported[idx].status == status
            ]
            tp = len(
                [idx for idx in expected_indices if idx in matched_expected_indices]
            )
            fp = len(
                [idx for idx in reported_indices if idx not in matched_report_indices]
            )
            fn = len(
                [idx for idx in expected_indices if idx not in matched_expected_indices]
            )
            case_metrics[f"{status}_tp"] = tp
            case_metrics[f"{status}_fp"] = fp
            case_metrics[f"{status}_fn"] = fn
            case_metrics[f"{status}_recall"] = tp / (tp + fn) if tp + fn else 0.0
            if status == "proven":
                case_metrics["false_positive_rate"] = (
                    fp / len(reported_indices) if reported_indices else 0.0
                )
        metrics[case.id] = case_metrics
    return metrics


def _case_for_reported_hypothesis(
    hypothesis: ReportedHypothesis,
    cases: tuple[BenchmarkCase, ...],
    *,
    require_case_id: bool = False,
) -> BenchmarkCase | None:
    if hypothesis.case_id is not None:
        for case in cases:
            if case.id == hypothesis.case_id:
                return case
        return None
    if require_case_id:
        return None
    reported = _normalise_path(hypothesis.file)
    for case in cases:
        case_path = _normalise_path(case.path)
        if (
            reported == case_path
            or reported.startswith(f"{case_path}/")
            or reported.endswith(f"/{case_path}")
            or f"/{case_path}/" in reported
        ):
            return case
        for expected in case.expected_hypotheses:
            if expected.file and _path_matches(expected.file, reported):
                return case
    return None


def _normalized_hypothesis_status(value: Any) -> str:
    return str(value or "").strip().lower()


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


def _positive_int_or_none(value: Any) -> int | None:
    try:
        parsed = int(value)
    except Exception:
        return None
    return parsed if parsed > 0 else None


def _normalise_path(value: str) -> str:
    return value.replace("\\", "/").strip("./")
