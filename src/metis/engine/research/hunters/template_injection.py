# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class TemplateInjectionHunter(GraphPatternHunter):
    name = "template_injection"
    vulnerability_class = "CWE-1336"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="template_injection",
                title="Template injection",
                sink_obligation="template_interpreter_sink",
                missing_mitigation_obligation="missing_template_sanitizer",
                mitigation_label="template escaping or input allowlist",
                impact=(
                    "Attacker-controlled input may reach a server-side template "
                    "interpreter without escaping or allowlisting."
                ),
                default_enabled=True,
            )
        )
