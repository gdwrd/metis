# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters.graph_pattern import (
    GraphPatternHunter,
    GraphPatternSpec,
)
from metis.engine.research.rules import markers_for


class InjectionPathHunter(GraphPatternHunter):
    name = "injection_path"
    vulnerability_class = "CWE-74"

    def __init__(self) -> None:
        super().__init__(
            GraphPatternSpec(
                name=self.name,
                vulnerability_class=self.vulnerability_class,
                title="Injection path",
                sink_obligation="sink",
                missing_mitigation_obligation="missing_sanitizer",
                mitigation_label="sanitizer or parameterization",
                sink_markers=markers_for(
                    "sink",
                    families=(
                        "command_injection",
                        "code_injection",
                        "template_injection",
                    ),
                ),
                mitigation_markers=markers_for(
                    "sanitizer",
                    families=(
                        "command_injection",
                        "code_injection",
                        "template_injection",
                        "sql_injection",
                    ),
                ),
                impact=(
                    "Attacker-controlled input may cross an interpreter or command "
                    "boundary without sanitization or parameterization."
                ),
                supported_languages=(
                    "python",
                    "javascript",
                    "typescript",
                    "php",
                    "perl",
                    "ruby",
                    "go",
                    "rust",
                    "lua",
                ),
                rule_families=(
                    "command_injection",
                    "code_injection",
                    "template_injection",
                ),
                default_enabled=False,
            )
        )
