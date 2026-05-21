# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class NoSqlInjectionHunter(GraphPatternHunter):
    name = "nosql_injection"
    vulnerability_class = "CWE-943"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="nosql_injection",
                title="NoSQL injection",
                sink_obligation="nosql_sink",
                missing_mitigation_obligation="missing_query_schema_validation",
                mitigation_label="query schema validation or allowlist",
                impact=(
                    "Attacker-controlled input may reach a NoSQL query builder "
                    "without schema validation or allowlisting."
                ),
                default_enabled=True,
                promotion_status="promoted",
            )
        )
