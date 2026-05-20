# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters.graph_pattern import (
    GraphPatternHunter,
    GraphPatternSpec,
)


class PathTraversalHunter(GraphPatternHunter):
    name = "path_traversal"
    vulnerability_class = "CWE-22"

    def __init__(self) -> None:
        super().__init__(
            GraphPatternSpec(
                name=self.name,
                vulnerability_class=self.vulnerability_class,
                title="Path traversal",
                sink_obligation="filesystem_sink",
                missing_mitigation_obligation="missing_canonicalization",
                mitigation_label="canonicalization or root confinement",
                sink_markers=("open", "fopen", "readfile", "send_file"),
                mitigation_markers=(
                    "safe_join",
                    "canonical",
                    "normalize",
                    "validate",
                    "allowlist",
                ),
                impact=(
                    "Attacker-controlled path input may reach a filesystem sink "
                    "without canonicalization or root confinement."
                ),
            )
        )
