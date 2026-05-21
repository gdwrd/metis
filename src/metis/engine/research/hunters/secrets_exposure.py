# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class SecretsExposureHunter(GraphPatternHunter):
    name = "secrets_exposure"
    vulnerability_class = "CWE-798"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="secrets_exposure",
                title="Secrets exposure",
                sink_obligation="secret_material",
                missing_mitigation_obligation="missing_secret_management",
                mitigation_label="secret manager, redaction, or KMS control",
                impact=(
                    "Secret-like material may be present in code or config without "
                    "redaction, vaulting, or key-management controls."
                ),
                experimental=True,
                promotion_status="experimental",
                promotion_skip_reason=(
                    "fixture evidence remains config-heavy and needs stronger "
                    "source reachability before default promotion"
                ),
            )
        )
