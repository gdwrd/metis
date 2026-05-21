# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class EvmExternalCallHunter(GraphPatternHunter):
    name = "evm_external_call"
    vulnerability_class = "CWE-841"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="evm_external_call",
                title="Unsafe EVM external call",
                sink_obligation="external_call_sink",
                missing_mitigation_obligation="missing_reentrancy_or_authorization_guard",
                mitigation_label="reentrancy guard or authorization check",
                impact=(
                    "Externally influenced Solidity control flow may reach an "
                    "external call without reentrancy or authorization controls."
                ),
                experimental=True,
                promotion_status="experimental",
                promotion_skip_reason=(
                    "promotion requires a second language/runtime fixture; "
                    "current coverage is Solidity-only"
                ),
            )
        )
