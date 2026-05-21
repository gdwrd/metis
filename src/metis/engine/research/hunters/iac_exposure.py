# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters._rule_graph import rule_graph_spec
from metis.engine.research.hunters.graph_pattern import GraphPatternHunter


class IacExposureHunter(GraphPatternHunter):
    name = "iac_exposure"
    vulnerability_class = "CWE-284"

    def __init__(self) -> None:
        super().__init__(
            rule_graph_spec(
                name=self.name,
                family="iac_exposure",
                title="IaC exposure",
                sink_obligation="exposed_resource",
                missing_mitigation_obligation="missing_least_privilege_or_private_scope",
                mitigation_label="least privilege, private scope, or encryption",
                impact=(
                    "Infrastructure or deployment configuration may expose "
                    "privileged resources, public access, or broad principals."
                ),
                default_enabled=True,
            )
        )
