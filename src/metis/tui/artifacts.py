# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .events import TuiEvent, utc_now_iso


@dataclass(frozen=True, slots=True)
class TuiArtifactPaths:
    run_dir: Path
    manifest: Path
    commands_dir: Path
    review_sarif: Path
    triage_sarif: Path
    security_report: Path
    security_report_findings: Path
    security_report_candidates: Path
    security_report_cross_batch_candidates: Path
    security_report_batch_notes: Path
    security_report_context: Path


class TuiArtifactStore:
    def __init__(
        self,
        *,
        run_id: str,
        codebase_path: str | Path,
        base_dir: str | Path = "results/tui",
    ):
        self.run_id = run_id
        self.codebase_path = str(codebase_path)
        run_dir = Path(base_dir) / run_id
        self.paths = TuiArtifactPaths(
            run_dir=run_dir,
            manifest=run_dir / "manifest.json",
            commands_dir=run_dir / "commands",
            review_sarif=run_dir / "review.sarif",
            triage_sarif=run_dir / "triage.sarif",
            security_report=run_dir / "security-report.md",
            security_report_findings=run_dir / "security-report-findings.json",
            security_report_candidates=run_dir / "security-report-candidates.json",
            security_report_cross_batch_candidates=(
                run_dir / "security-report-cross-batch-candidates.json"
            ),
            security_report_batch_notes=run_dir / "security-report-batch-notes.md",
            security_report_context=run_dir / "security-report-context.json",
        )
        self.paths.commands_dir.mkdir(parents=True, exist_ok=True)
        self._manifest: dict[str, Any] = {
            "run_id": run_id,
            "created_at": utc_now_iso(),
            "updated_at": utc_now_iso(),
            "status": "running",
            "codebase_path": self.codebase_path,
            "commands": [],
            "artifacts": {
                "review_sarif": str(self.paths.review_sarif),
                "triage_sarif": str(self.paths.triage_sarif),
                "security_report": str(self.paths.security_report),
                "security_report_findings": str(self.paths.security_report_findings),
                "security_report_candidates": str(
                    self.paths.security_report_candidates
                ),
                "security_report_cross_batch_candidates": str(
                    self.paths.security_report_cross_batch_candidates
                ),
                "security_report_batch_notes": str(
                    self.paths.security_report_batch_notes
                ),
                "security_report_context": str(self.paths.security_report_context),
            },
            "latest_review_sarif_source": None,
        }
        self.write_manifest()

    @property
    def manifest(self) -> dict[str, Any]:
        return dict(self._manifest)

    def command_log_path(self, command_number: int, command_name: str) -> Path:
        safe_name = command_name.replace("/", "_")
        return self.paths.commands_dir / f"{command_number:03d}-{safe_name}.jsonl"

    def record_command(
        self,
        *,
        command_id: str,
        command_name: str,
        raw: str,
        log_path: Path,
        status: str = "running",
    ) -> None:
        self._manifest["status"] = "running"
        self._manifest["commands"].append(
            {
                "command_id": command_id,
                "name": command_name,
                "raw": raw,
                "status": status,
                "started_at": utc_now_iso(),
                "finished_at": None,
                "log": str(log_path),
            }
        )
        self.write_manifest()

    def finish_command(self, command_id: str, status: str) -> None:
        for command in self._manifest["commands"]:
            if command["command_id"] == command_id:
                command["status"] = status
                command["finished_at"] = utc_now_iso()
                break
        self.write_manifest()

    def set_status(self, status: str) -> None:
        self._manifest["status"] = status
        self.write_manifest()

    def set_latest_review_sarif_source(self, source: str | None) -> None:
        self._manifest["latest_review_sarif_source"] = source
        self.write_manifest()

    def write_manifest(self) -> None:
        self._manifest["updated_at"] = utc_now_iso()
        self.paths.run_dir.mkdir(parents=True, exist_ok=True)
        self.paths.manifest.write_text(
            json.dumps(self._manifest, indent=2),
            encoding="utf-8",
        )

    def append_event(self, log_path: Path, event: TuiEvent) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        sanitized = event.sanitized()
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(sanitized.to_dict(), sort_keys=True, default=str) + "\n"
            )


def find_latest_review_sarif(
    base_dir: str | Path = "results/tui",
) -> tuple[Path, str] | None:
    manifests = Path(base_dir).glob("*/manifest.json")
    candidates: list[tuple[str, Path]] = []
    for manifest_path in manifests:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if manifest.get("status") != "succeeded":
            continue
        review_path = Path(manifest.get("artifacts", {}).get("review_sarif", ""))
        if review_path.is_file():
            candidates.append((str(manifest.get("updated_at") or ""), review_path))
    if not candidates:
        return None
    _updated_at, path = max(candidates, key=lambda item: item[0])
    return path, "manifest-scan"


def find_latest_triage_sarif(
    base_dir: str | Path = "results/tui",
) -> tuple[Path, str] | None:
    manifests = Path(base_dir).glob("*/manifest.json")
    candidates: list[tuple[str, Path]] = []
    for manifest_path in manifests:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if manifest.get("status") != "succeeded":
            continue
        triage_path = Path(manifest.get("artifacts", {}).get("triage_sarif", ""))
        if triage_path.is_file():
            candidates.append((str(manifest.get("updated_at") or ""), triage_path))
    if not candidates:
        return None
    _updated_at, path = max(candidates, key=lambda item: item[0])
    return path, "manifest-scan"
