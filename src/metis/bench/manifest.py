# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


@dataclass(frozen=True)
class ExpectedFinding:
    file: str
    line_range: tuple[int, int]
    cwe: str
    severity_min: str | None = None


@dataclass(frozen=True)
class ExpectedHypothesis:
    hunter: str
    vulnerability_class: str
    status: str
    sarif_rule_id: str | None = None
    file: str | None = None
    line_range: tuple[int, int] | None = None
    symbol: str | None = None
    id: str | None = None


@dataclass(frozen=True)
class VariantSources:
    from_fix: str | None = None
    from_sarif: str | None = None
    from_report: str | None = None

    def any(self) -> bool:
        return any((self.from_fix, self.from_sarif, self.from_report))


@dataclass(frozen=True)
class CoverageMatrixEntry:
    language: str
    parser_runtime: str
    graph_mode: str
    vulnerability_class: str
    hunter: str
    source_coverage: str
    sink_coverage: str
    mitigation_coverage: str
    fixture_status: str
    default_status: str
    experimental_status: str


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    source: str
    cwe: str
    language: str
    path: str
    expected_findings: tuple[ExpectedFinding, ...]
    expected_hypotheses: tuple[ExpectedHypothesis, ...] = ()
    variant_sources: VariantSources | None = None
    quick: bool = False

    def case_path(self, manifest_dir: Path) -> Path:
        return (manifest_dir / self.path).resolve()


@dataclass(frozen=True)
class BenchmarkManifest:
    path: Path
    cases: tuple[BenchmarkCase, ...]
    line_tolerance: int = 0
    cwe_equivalence: dict[str, tuple[str, ...]] = field(default_factory=dict)
    coverage_matrix: tuple[CoverageMatrixEntry, ...] = ()

    @property
    def root(self) -> Path:
        return self.path.parent

    def selected_cases(self, *, quick: bool = False) -> tuple[BenchmarkCase, ...]:
        if not quick:
            return self.cases
        return tuple(case for case in self.cases if case.quick)


def load_manifest(path: str | Path) -> BenchmarkManifest:
    manifest_path = Path(path)
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    raw_cases: list[Any]
    settings: dict[str, Any]
    if isinstance(data, list):
        raw_cases = data
        settings = {}
    elif isinstance(data, dict):
        cases_value = data.get("cases")
        raw_cases = cases_value if isinstance(cases_value, list) else []
        settings = data
    else:
        raise ValueError("Benchmark manifest must be a list or mapping")

    if not raw_cases:
        raise ValueError("Benchmark manifest must contain at least one case")

    cases = tuple(_parse_case(item) for item in raw_cases)
    return BenchmarkManifest(
        path=manifest_path,
        cases=cases,
        line_tolerance=int(settings.get("line_tolerance", 0) or 0),
        cwe_equivalence=_parse_cwe_equivalence(settings.get("cwe_equivalence", {})),
        coverage_matrix=tuple(
            _parse_coverage_matrix_entry(raw)
            for raw in settings.get("coverage_matrix", []) or []
        ),
    )


def _parse_case(item: Any) -> BenchmarkCase:
    if not isinstance(item, dict):
        raise ValueError("Benchmark case entries must be mappings")
    expected = item.get("expected_findings")
    if not isinstance(expected, list):
        raise ValueError(
            f"Benchmark case {item.get('id', '<unknown>')} is missing expected_findings"
        )

    case_id = str(item.get("id") or "").strip()
    if not case_id:
        raise ValueError("Benchmark case id is required")

    return BenchmarkCase(
        id=case_id,
        source=str(item.get("source") or "internal"),
        cwe=str(item.get("cwe") or "CWE-Unknown"),
        language=str(item.get("language") or "unknown"),
        path=str(item.get("path") or "").strip(),
        expected_findings=tuple(_parse_expected(raw) for raw in expected),
        expected_hypotheses=tuple(
            _parse_expected_hypothesis(raw)
            for raw in item.get("expected_hypotheses", []) or []
        ),
        variant_sources=_parse_variant_sources(item.get("variant_sources")),
        quick=bool(item.get("quick", False)),
    )


def _parse_expected(item: Any) -> ExpectedFinding:
    if not isinstance(item, dict):
        raise ValueError("expected_findings entries must be mappings")
    line_range = item.get("line_range")
    if not isinstance(line_range, list | tuple) or len(line_range) != 2:
        raise ValueError("expected finding line_range must contain [start, end]")
    start, end = int(line_range[0]), int(line_range[1])
    if start <= 0 or end < start:
        raise ValueError("expected finding line_range must be positive and ordered")
    return ExpectedFinding(
        file=str(item.get("file") or "").strip(),
        line_range=(start, end),
        cwe=str(item.get("cwe") or "CWE-Unknown"),
        severity_min=(
            str(item["severity_min"]).strip() if item.get("severity_min") else None
        ),
    )


def _parse_expected_hypothesis(item: Any) -> ExpectedHypothesis:
    if not isinstance(item, dict):
        raise ValueError("expected_hypotheses entries must be mappings")
    line_range = item.get("line_range")
    parsed_range = None
    if line_range is not None:
        if not isinstance(line_range, list | tuple) or len(line_range) != 2:
            raise ValueError("expected hypothesis line_range must contain [start, end]")
        start, end = int(line_range[0]), int(line_range[1])
        if start <= 0 or end < start:
            raise ValueError(
                "expected hypothesis line_range must be positive and ordered"
            )
        parsed_range = (start, end)
    return ExpectedHypothesis(
        hunter=str(item.get("hunter") or "").strip(),
        vulnerability_class=str(
            item.get("vulnerability_class") or item.get("cwe") or "CWE-Unknown"
        ),
        status=str(item.get("status") or "proven").strip(),
        sarif_rule_id=(
            str(item["sarif_rule_id"]).strip() if item.get("sarif_rule_id") else None
        ),
        file=str(item["file"]).strip() if item.get("file") else None,
        line_range=parsed_range,
        symbol=str(item["symbol"]).strip() if item.get("symbol") else None,
        id=str(item["id"]).strip() if item.get("id") else None,
    )


def _parse_variant_sources(item: Any) -> VariantSources | None:
    if item is None:
        return None
    if not isinstance(item, dict):
        raise ValueError("variant_sources must be a mapping")
    sources = VariantSources(
        from_fix=str(item["from_fix"]).strip() if item.get("from_fix") else None,
        from_sarif=(
            str(item["from_sarif"]).strip() if item.get("from_sarif") else None
        ),
        from_report=(
            str(item["from_report"]).strip() if item.get("from_report") else None
        ),
    )
    if not sources.any():
        raise ValueError("variant_sources must contain at least one source")
    return sources


def _parse_coverage_matrix_entry(item: Any) -> CoverageMatrixEntry:
    if not isinstance(item, dict):
        raise ValueError("coverage_matrix entries must be mappings")
    return CoverageMatrixEntry(
        language=_required_coverage_value(item, "language"),
        parser_runtime=_required_coverage_value(item, "parser_runtime"),
        graph_mode=_required_coverage_value(item, "graph_mode"),
        vulnerability_class=_required_coverage_value(item, "vulnerability_class"),
        hunter=_required_coverage_value(item, "hunter"),
        source_coverage=_required_coverage_value(item, "source_coverage"),
        sink_coverage=_required_coverage_value(item, "sink_coverage"),
        mitigation_coverage=_required_coverage_value(item, "mitigation_coverage"),
        fixture_status=_required_coverage_value(item, "fixture_status"),
        default_status=_required_coverage_value(item, "default_status"),
        experimental_status=_required_coverage_value(item, "experimental_status"),
    )


def _required_coverage_value(item: dict[str, Any], key: str) -> str:
    value = str(item.get(key) or "").strip()
    if not value:
        raise ValueError(f"coverage_matrix entry is missing {key}")
    return value


def _parse_cwe_equivalence(raw: Any) -> dict[str, tuple[str, ...]]:
    if not isinstance(raw, dict):
        return {}
    parsed: dict[str, tuple[str, ...]] = {}
    for key, values in raw.items():
        members = [str(key)]
        if isinstance(values, list | tuple | set):
            members.extend(str(value) for value in values)
        group = tuple(sorted({member.strip() for member in members if member.strip()}))
        for member in group:
            parsed[member] = group
    return parsed
