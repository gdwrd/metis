# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, TypeVar

from pydantic import BaseModel

from .models import EvidenceLedgerEntry, Hypothesis

ModelT = TypeVar("ModelT", bound=BaseModel)


class ResearchJsonlStore:
    def __init__(
        self,
        *,
        hypotheses_path: str | Path,
        evidence_path: str | Path,
    ) -> None:
        self.hypotheses_path = Path(hypotheses_path)
        self.evidence_path = Path(evidence_path)

    def append_hypothesis(self, hypothesis: Hypothesis) -> None:
        _append_model(self.hypotheses_path, hypothesis)

    def append_hypotheses(self, hypotheses: Iterable[Hypothesis]) -> None:
        for hypothesis in hypotheses:
            self.append_hypothesis(hypothesis)

    def read_hypotheses(self) -> list[Hypothesis]:
        return _read_models(self.hypotheses_path, Hypothesis)

    def append_evidence(self, entry: EvidenceLedgerEntry) -> None:
        _append_model(self.evidence_path, entry)

    def append_evidence_entries(self, entries: Iterable[EvidenceLedgerEntry]) -> None:
        for entry in entries:
            self.append_evidence(entry)

    def read_evidence(self) -> list[EvidenceLedgerEntry]:
        return _read_models(self.evidence_path, EvidenceLedgerEntry)


def _append_model(path: Path, model: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = model.model_dump(mode="json")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def _read_models(path: Path, model_type: type[ModelT]) -> list[ModelT]:
    if not path.exists():
        return []
    models: list[ModelT] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}") from exc
            models.append(model_type.model_validate(payload))
    return models
