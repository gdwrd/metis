# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from metis.usage.context import current_operation, current_scope

from .sanitize import sanitize_text


def _message_text(value: Any) -> str:
    if value is None:
        return ""
    content = getattr(value, "content", value)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or ""))
            else:
                parts.append(str(item))
        return "".join(parts)
    return str(content)


def _safe(value: Any) -> str:
    return sanitize_text(value)


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    provider_name: str
    model: str
    base_url: str
    timeout: int
    max_retries: int
    ready: bool = False
    disabled_reason: str = ""


@dataclass(frozen=True, slots=True)
class ProviderCheck:
    ready: bool
    message: str


class TuiChatModelAdapter:
    def __init__(
        self,
        engine: Any,
        *,
        timeout: int = 30,
        max_retries: int = 1,
        max_tokens: int | None = None,
    ):
        self.engine = engine
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_tokens = max_tokens

    @property
    def provider(self) -> Any:
        provider = getattr(self.engine, "llm_provider", None)
        if provider is None:
            raise ValueError("TUI chat requires an engine with llm_provider")
        return provider

    def metadata(
        self, *, ready: bool = False, disabled_reason: str = ""
    ) -> ProviderMetadata:
        provider = self.provider
        return ProviderMetadata(
            provider_name=_safe(provider.__class__.__name__),
            model=_safe(
                getattr(provider, "query_model", "")
                or getattr(provider, "engine", "")
                or getattr(provider, "chat_deployment_model", "")
            ),
            base_url=_safe(
                getattr(provider, "base_url", "")
                or getattr(provider, "azure_endpoint", "")
                or ""
            ),
            timeout=self.timeout,
            max_retries=self.max_retries,
            ready=ready,
            disabled_reason=_safe(disabled_reason),
        )

    def build_model(self) -> Any:
        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "response_format": None,
        }
        if self.max_tokens is not None:
            kwargs["max_tokens"] = self.max_tokens
        return self.provider.get_chat_model(**kwargs)

    def stream(self, messages: list[tuple[str, str]]) -> Iterable[str]:
        model = self.build_model()
        stream = getattr(model, "stream", None)
        if callable(stream):
            yielded = False
            output_parts: list[str] = []
            for chunk in stream(messages):
                text = _message_text(chunk)
                if text:
                    yielded = True
                    output_parts.append(text)
                    yield text
            if yielded:
                self._record_estimated_usage(messages, "".join(output_parts))
                return
        yield self.invoke(messages)

    def invoke(self, messages: list[tuple[str, str]]) -> str:
        model = self.build_model()
        invoke = getattr(model, "invoke", None)
        if callable(invoke):
            text = _message_text(invoke(messages))
            self._record_estimated_usage(messages, text)
            return text
        call = getattr(model, "__call__", None)
        if callable(call):
            text = _message_text(call(messages))
            self._record_estimated_usage(messages, text)
            return text
        raise TypeError("Configured chat model does not support stream or invoke")

    def _record_estimated_usage(
        self, messages: list[tuple[str, str]], output_text: str
    ) -> None:
        engine = getattr(self, "engine", None)
        if engine is None:
            return
        runtime = getattr(engine, "usage_runtime", None)
        collector = getattr(runtime, "collector", None)
        if collector is None:
            return
        collector.record(
            scope_id=current_scope(),
            operation=current_operation() or "tui_chat",
            model=self.metadata().model or "unknown",
            input_tokens=self._estimate_message_tokens(messages),
            output_tokens=self._estimate_tokens(output_text),
        )

    def _estimate_message_tokens(self, messages: list[tuple[str, str]]) -> int:
        return sum(
            self._estimate_tokens(role) + self._estimate_tokens(text)
            for role, text in messages
        )

    def _estimate_tokens(self, text: str) -> int:
        if not text:
            return 0
        return max(1, len(text) // 4)


class ProviderVerifier:
    def __init__(self, adapter: TuiChatModelAdapter):
        self.adapter = adapter

    def verify(self) -> ProviderCheck:
        try:
            text = self.adapter.invoke(
                [
                    (
                        "system",
                        "You are Metis. Reply with a short readiness acknowledgement.",
                    ),
                    ("human", "Say ready."),
                ]
            ).strip()
        except Exception as exc:
            return ProviderCheck(False, _safe(exc))
        if not text:
            return ProviderCheck(False, "Provider returned an empty response")
        return ProviderCheck(True, "Provider readiness check succeeded")
