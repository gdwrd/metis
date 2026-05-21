# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class CryptoMisuseHunter(GraphPatternHunter):
    name = "crypto_misuse"
    vulnerability_class = "CWE-327"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="crypto_misuse",
                title="Crypto misuse",
                sink_obligation="weak_crypto_sink",
                missing_mitigation_obligation="missing_strong_crypto_control",
                mitigation_label="strong cryptographic primitive or CSPRNG",
                impact=(
                    "Weak cryptographic primitives or randomness may protect "
                    "security-sensitive data without a strong replacement."
                ),
                default_enabled=True,
                promotion_status="promoted",
            )
        )
