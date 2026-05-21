# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class XssHunter(GraphPatternHunter):
    name = "xss"
    vulnerability_class = "CWE-79"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="xss",
                title="Cross-site scripting",
                sink_obligation="html_sink",
                missing_mitigation_obligation="missing_output_encoding",
                mitigation_label="output encoding or HTML sanitizer",
                impact=(
                    "Attacker-controlled input may reach an HTML/DOM sink "
                    "without output encoding or sanitization."
                ),
                default_enabled=True,
                promotion_status="promoted",
            )
        )
