# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class CommandInjectionHunter(GraphPatternHunter):
    name = "command_injection"
    vulnerability_class = "CWE-78"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="command_injection",
                title="Command injection",
                sink_obligation="command_sink",
                missing_mitigation_obligation="missing_command_sanitizer",
                mitigation_label="command sanitizer or allowlist",
                impact=(
                    "Attacker-controlled input may reach an operating-system "
                    "command boundary without shell escaping or allowlisting."
                ),
                default_enabled=True,
            )
        )
