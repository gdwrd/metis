# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from .sanitize import sanitize_text

ProviderStatus = Literal["checking", "ready", "failed", "unavailable"]


@dataclass(frozen=True, slots=True)
class TuiStartupState:
    stage: str
    chat_enabled: bool
    message: str
    hint: str = ""
    provider_name: str = ""
    model: str = ""
    base_url: str = ""
    provider_ready: bool = False
    provider_status: ProviderStatus = "unavailable"
    context_status: str = "unknown"
    disabled_reason: str = ""

    @classmethod
    def ready(cls, engine: Any, runtime: dict[str, Any] | None = None) -> "TuiStartupState":
        runtime = runtime or {}
        provider = getattr(engine, "llm_provider", None)
        provider_name = ""
        if provider is not None:
            provider_name = str(
                runtime.get("llm_provider_name")
                or getattr(provider, "provider_name", "")
                or provider.__class__.__name__
            )
        model = str(
            runtime.get("llama_query_model")
            or runtime.get("model")
            or getattr(provider, "query_model", "")
            or getattr(provider, "engine", "")
            or ""
        )
        base_url = str(
            runtime.get("openai_api_base")
            or runtime.get("azure_endpoint")
            or getattr(provider, "base_url", "")
            or getattr(provider, "azure_endpoint", "")
            or ""
        )
        return cls(
            stage="ready",
            chat_enabled=True,
            message="Provider configured; readiness check pending",
            hint="",
            provider_name=sanitize_text(provider_name),
            model=sanitize_text(model),
            base_url=sanitize_text(base_url),
            provider_ready=False,
            provider_status="checking",
            context_status="unknown",
            disabled_reason="",
        )

    @classmethod
    def failed(
        cls,
        *,
        stage: str,
        error: BaseException,
        runtime: dict[str, Any] | None = None,
    ) -> "TuiStartupState":
        runtime = runtime or {}
        provider_name = str(runtime.get("llm_provider_name") or "")
        model = str(runtime.get("llama_query_model") or runtime.get("model") or "")
        base_url = str(
            runtime.get("openai_api_base") or runtime.get("azure_endpoint") or ""
        )
        message = sanitize_text(error)
        return cls(
            stage=stage,
            chat_enabled=False,
            message=message,
            hint=_hint_for_stage(stage, message),
            provider_name=sanitize_text(provider_name),
            model=sanitize_text(model),
            base_url=sanitize_text(base_url),
            provider_ready=False,
            provider_status="unavailable",
            context_status="unknown",
            disabled_reason=message,
        )


@dataclass(frozen=True, slots=True)
class TuiBootstrapSession:
    engine: Any | None
    vector_backend: Any | None
    startup_state: TuiStartupState
    runtime: dict[str, Any] = field(default_factory=dict)


def _hint_for_stage(stage: str, message: str) -> str:
    lowered = message.lower()
    if "api_key" in lowered or "environment variable" in lowered:
        return "Set the provider API key environment variable and restart metis tui."
    if "embedding" in lowered or stage == "embedding":
        return "Check code/docs embedding model configuration."
    if "base" in lowered or "endpoint" in lowered or "connect" in lowered:
        return "Check the configured provider endpoint or OPENAI_BASE_URL."
    return "Fix the startup error and restart metis tui."


def bootstrap_tui_session(
    args: Any,
    *,
    load_runtime_config: Callable[..., dict[str, Any]],
    build_engine: Callable[[Any, dict[str, Any]], tuple[Any, Any]],
) -> TuiBootstrapSession:
    runtime: dict[str, Any] = {}
    try:
        runtime = load_runtime_config(enable_psql=(args.backend == "postgres"))
    except Exception as exc:
        return TuiBootstrapSession(
            engine=None,
            vector_backend=None,
            startup_state=TuiStartupState.failed(stage="config", error=exc),
            runtime={},
        )
    try:
        engine, vector_backend = build_engine(args, runtime)
    except Exception as exc:
        return TuiBootstrapSession(
            engine=None,
            vector_backend=None,
            startup_state=TuiStartupState.failed(
                stage="engine", error=exc, runtime=runtime
            ),
            runtime=dict(runtime),
        )
    return TuiBootstrapSession(
        engine=engine,
        vector_backend=vector_backend,
        startup_state=TuiStartupState.ready(engine, runtime),
        runtime=dict(runtime),
    )
