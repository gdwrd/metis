# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class CodeInjectionHunter(GraphPatternHunter):
    name = "code_injection"
    vulnerability_class = "CWE-94"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="code_injection",
                title="Code injection",
                sink_obligation="code_execution_sink",
                missing_mitigation_obligation="missing_code_input_validation",
                mitigation_label="code input validation or allowlist",
                impact=(
                    "Attacker-controlled input may reach a dynamic-code "
                    "interpreter without strict validation or allowlisting."
                ),
                default_enabled=True,
            )
        )
