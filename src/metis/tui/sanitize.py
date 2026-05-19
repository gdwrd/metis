# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from typing import Any


_ASSIGNMENT_SECRET = re.compile(
    r"(?i)(api[_ -]?key|authorization|bearer|token|secret)(\s*[:=]\s*)([^\s,;]+)"
)
_QUOTED_SECRET = re.compile(
    r"(?i)(['\"](?:api[_ -]?key|authorization|bearer|token|secret|x-api-key|default_headers?|headers?)['\"]\s*[:=]\s*['\"])([^'\"]+)(['\"])",
)
_BEARER_SECRET = re.compile(r"(?i)bearer\s+[a-z0-9._\-]+")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b")
_HEADER_SECRET = re.compile(
    r"(?i)(x-api-key|default_headers?|headers?)(['\"]?\s*[:=]\s*)([^,}\]\s]+)"
)


def sanitize_text(value: Any) -> str:
    text = str(value or "").strip()
    text = _BEARER_SECRET.sub("<redacted>", text)
    text = _QUOTED_SECRET.sub(r"\1<redacted>\3", text)
    text = _ASSIGNMENT_SECRET.sub(r"\1\2<redacted>", text)
    text = _HEADER_SECRET.sub(r"\1\2<redacted>", text)
    text = _OPENAI_KEY.sub("<redacted>", text)
    return text


def sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        sanitized: dict[Any, Any] = {}
        for key, item in value.items():
            safe_key = sanitize_text(key) if isinstance(key, str) else key
            if isinstance(key, str) and any(
                marker in key.lower()
                for marker in ("api_key", "api key", "x-api-key", "authorization", "token", "secret", "header")
            ):
                sanitized[safe_key] = "<redacted>"
            else:
                sanitized[safe_key] = sanitize_value(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_value(item) for item in value)
    return value
