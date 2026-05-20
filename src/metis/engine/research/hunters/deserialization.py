# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters.graph_pattern import (
    GraphPatternHunter,
    GraphPatternSpec,
)


class DeserializationHunter(GraphPatternHunter):
    name = "deserialization"
    vulnerability_class = "CWE-502"

    def __init__(self) -> None:
        super().__init__(
            GraphPatternSpec(
                name=self.name,
                vulnerability_class=self.vulnerability_class,
                title="Unsafe deserialization path",
                sink_obligation="deserialization_sink",
                missing_mitigation_obligation="missing_type_or_integrity_guard",
                mitigation_label="type allowlist or integrity guard",
                sink_markers=(
                    "pickle.loads",
                    "yaml.load",
                    "marshal.load",
                    "loads",
                    "deserialize",
                    "unserialize",
                ),
                mitigation_markers=(
                    "allowlist",
                    "validate",
                    "signature",
                    "integrity",
                ),
                impact=(
                    "Attacker-controlled serialized data may reach an unsafe "
                    "deserialization sink without type or integrity checks."
                ),
            )
        )
