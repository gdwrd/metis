# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from metis.engine.research.models import (
    ProjectSecurityModel,
    ResearchLesson,
    ResearchRunResult,
    SecurityGraph,
)


@dataclass(frozen=True)
class HunterMetadata:
    name: str
    vulnerability_class: str
    supported_languages: tuple[str, ...] = ()
    supported_model_tags: tuple[str, ...] = ()
    required_graph_fields: tuple[str, ...] = ()
    evidence_obligations: tuple[str, ...] = ()
    benchmark_classes: tuple[str, ...] = ()


class Hunter(Protocol):
    name: str
    metadata: HunterMetadata

    def hunt(
        self,
        root: str | Path,
        *,
        security_model: ProjectSecurityModel | None = None,
        security_graph: SecurityGraph | None = None,
        lessons: tuple[ResearchLesson, ...] = (),
    ) -> ResearchRunResult:
        """Return generated, proven, killed, and unresolved hypotheses."""
