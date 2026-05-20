# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass

from .models import DEFAULT_RESEARCH_HUNTERS


@dataclass(frozen=True)
class ResearchOptions:
    hunters: tuple[str, ...] = DEFAULT_RESEARCH_HUNTERS
    persist: bool = False
    rebuild: bool = False
    research_budget: str = "standard"
    emit_killed: bool = False
    emit_unresolved: bool = False
    proof_artifacts: bool = False
    evidence_policy: str = "triage_evidence"
    hypotheses_path: str | None = None
    evidence_ledger_path: str | None = None
    sarif_path: str | None = None
    research_report_path: str | None = None

    def sarif_statuses(self):
        from .models import HypothesisStatus

        statuses = [HypothesisStatus.PROVEN]
        if self.emit_killed:
            statuses.append(HypothesisStatus.KILLED)
        if self.emit_unresolved:
            statuses.append(HypothesisStatus.UNRESOLVED)
        return tuple(statuses)
