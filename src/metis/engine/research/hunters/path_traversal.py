# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class PathTraversalHunter(GraphPatternHunter):
    name = "path_traversal"
    vulnerability_class = "CWE-22"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="path_traversal",
                title="Path traversal",
                sink_obligation="filesystem_sink",
                missing_mitigation_obligation="missing_canonicalization",
                mitigation_label="canonicalization or root confinement",
                impact=(
                    "Attacker-controlled path input may reach a filesystem sink "
                    "without canonicalization or root confinement."
                ),
                default_enabled=True,
            )
        )
