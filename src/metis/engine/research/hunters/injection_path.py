# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters.graph_pattern import (
    GraphPatternHunter,
    GraphPatternSpec,
)


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
                sink_markers=(
                    "execute",
                    "executemany",
                    "raw",
                    "system",
                    "check_output",
                    "popen",
                    "spawn",
                    "spawn_sync",
                    "child_process",
                    "eval",
                    "exec",
                    "execsync",
                    "shell_exec",
                    "passthru",
                    "proc_open",
                    "function",
                ),
                mitigation_markers=(
                    "sanitize",
                    "validate",
                    "escape",
                    "escapeshellarg",
                    "escapeshellcmd",
                    "allowlist",
                    "parameterize",
                ),
                impact=(
                    "Attacker-controlled input may cross an interpreter or command "
                    "boundary without sanitization or parameterization."
                ),
            )
        )
