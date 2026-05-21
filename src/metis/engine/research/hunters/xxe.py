# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class XxeHunter(GraphPatternHunter):
    name = "xxe"
    vulnerability_class = "CWE-611"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="xxe",
                title="XXE parser exposure",
                sink_obligation="xml_parser_sink",
                missing_mitigation_obligation="missing_xxe_parser_hardening",
                mitigation_label="external-entity disabling or safe XML parser",
                impact=(
                    "Attacker-controlled XML may reach a parser that can resolve "
                    "external entities without explicit hardening."
                ),
                default_enabled=True,
                promotion_status="promoted",
            )
        )
