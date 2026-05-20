# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters.graph_pattern import (
    GraphPatternHunter,
    GraphPatternSpec,
)


class SsrfHunter(GraphPatternHunter):
    name = "ssrf"
    vulnerability_class = "CWE-918"

    def __init__(self) -> None:
        super().__init__(
            GraphPatternSpec(
                name=self.name,
                vulnerability_class=self.vulnerability_class,
                title="SSRF path",
                sink_obligation="network_sink",
                missing_mitigation_obligation="missing_network_allowlist",
                mitigation_label="network allowlist",
                sink_markers=(
                    "urlopen",
                    "requests.get",
                    "requests.post",
                    "fetch",
                    "http.get",
                    "http.post",
                    "axios.get",
                    "axios.post",
                ),
                mitigation_markers=(
                    "allowlist",
                    "validate",
                    "scheme",
                    "hostname",
                    "proxy",
                ),
                impact=(
                    "Attacker-controlled URL input may reach a network fetch sink "
                    "without scheme, host, redirect, metadata-IP, or proxy controls."
                ),
            )
        )
