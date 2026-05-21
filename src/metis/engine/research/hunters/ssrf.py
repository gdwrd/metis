# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class SsrfHunter(GraphPatternHunter):
    name = "ssrf"
    vulnerability_class = "CWE-918"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="ssrf",
                title="SSRF path",
                sink_obligation="network_sink",
                missing_mitigation_obligation="missing_network_allowlist",
                mitigation_label="network allowlist",
                impact=(
                    "Attacker-controlled URL input may reach a network fetch sink "
                    "without scheme, host, redirect, metadata-IP, or proxy controls."
                ),
                default_enabled=True,
            )
        )
