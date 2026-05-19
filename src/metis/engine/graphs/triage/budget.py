# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvidenceBudget:
    name: str
    max_sections: int
    max_chars: int
    max_symbol_terms: int
    max_followup_hits: int
    max_symbol_hops: int


SIMPLE = EvidenceBudget("simple", 16, 8000, 2, 6, 1)
STANDARD = EvidenceBudget("standard", 28, 14000, 4, 12, 2)
DEEP = EvidenceBudget("deep", 48, 24000, 8, 24, 3)

_BUDGETS = {
    SIMPLE.name: SIMPLE,
    STANDARD.name: STANDARD,
    DEEP.name: DEEP,
}


def coerce_evidence_budget(value: Any) -> EvidenceBudget:
    if isinstance(value, EvidenceBudget):
        return value
    if value is None:
        return STANDARD
    name = str(value or "").strip().lower()
    return _BUDGETS.get(name, STANDARD)
