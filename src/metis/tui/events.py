# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from .sanitize import sanitize_text, sanitize_value

EventLevel = Literal["debug", "info", "warning", "error"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class TuiEvent:
    run_id: str
    command_id: str
    sequence: int
    type: str
    timestamp: str
    level: EventLevel
    message: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return sanitize_value(asdict(self))

    def sanitized(self) -> "TuiEvent":
        return TuiEvent(
            run_id=self.run_id,
            command_id=self.command_id,
            sequence=self.sequence,
            type=self.type,
            timestamp=self.timestamp,
            level=self.level,
            message=sanitize_text(self.message),
            payload=sanitize_value(self.payload),
        )
