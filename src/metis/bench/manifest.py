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
class BenchmarkCase:
    id: str
    source: str
    cwe: str
    language: str
    path: str
    expected_findings: tuple[ExpectedFinding, ...]
    quick: bool = False

    def case_path(self, manifest_dir: Path) -> Path:
        return (manifest_dir / self.path).resolve()


@dataclass(frozen=True)
class BenchmarkManifest:
    path: Path
    cases: tuple[BenchmarkCase, ...]
    line_tolerance: int = 0
    cwe_equivalence: dict[str, tuple[str, ...]] = field(default_factory=dict)

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
