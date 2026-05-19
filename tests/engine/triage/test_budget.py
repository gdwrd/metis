# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.graphs.triage import constants
from metis.engine.graphs.triage.budget import DEEP, SIMPLE, STANDARD, EvidenceBudget


def test_evidence_budget_presets_match_roadmap_contract():
    assert SIMPLE == EvidenceBudget("simple", 16, 8000, 2, 6, 1)
    assert STANDARD == EvidenceBudget("standard", 28, 14000, 4, 12, 2)
    assert DEEP == EvidenceBudget("deep", 48, 24000, 8, 24, 3)


def test_standard_budget_keeps_legacy_constant_values():
    assert constants.MAX_SECTIONS == STANDARD.max_sections
    assert constants.MAX_SYMBOL_TERMS_METIS == STANDARD.max_symbol_terms
    assert constants.DEFAULT_MAX_FOLLOWUP_HITS == STANDARD.max_followup_hits
    assert constants.EVIDENCE_PACK_MAX_CHARS == STANDARD.max_chars
