# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters.graph_pattern import GraphPatternSpec
from metis.engine.research.models import ResearchPriority
from metis.engine.research.rules import normalized_markers_for, rule_for_family


PROMOTION_CRITERIA = (
    "at least two language fixtures",
    "at least one killed or sanitized fixture",
    "class-specific SARIF rule ID",
    "acceptable quick-benchmark false-positive rate",
)


def rule_graph_spec(
    *,
    name: str,
    family: str,
    title: str,
    sink_obligation: str,
    missing_mitigation_obligation: str,
    mitigation_label: str,
    impact: str,
    default_enabled: bool = False,
    experimental: bool = False,
    promotion_status: str = "unassessed",
    promotion_skip_reason: str | None = None,
    priority: ResearchPriority = ResearchPriority.HIGH,
) -> GraphPatternSpec:
    rule = rule_for_family(family)
    return GraphPatternSpec(
        name=name,
        vulnerability_class=rule.cwe,
        title=title,
        sink_obligation=sink_obligation,
        missing_mitigation_obligation=missing_mitigation_obligation,
        mitigation_label=mitigation_label,
        sink_markers=normalized_markers_for("sink", families=(family,)),
        mitigation_markers=normalized_markers_for("sanitizer", families=(family,)),
        impact=impact,
        supported_languages=rule.languages or ("python",),
        priority=priority,
        rule_families=(rule.family,),
        default_enabled=default_enabled,
        experimental=experimental,
        promotion_criteria=PROMOTION_CRITERIA,
        promotion_status=promotion_status,
        promotion_skip_reason=promotion_skip_reason,
    )
