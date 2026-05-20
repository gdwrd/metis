# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

from metis.tui.bootstrap import bootstrap_tui_session


def _args():
    return SimpleNamespace(backend="chroma")


def test_bootstrap_tui_captures_config_failure_without_building_engine():
    calls = []

    def _load(**_kwargs):
        raise RuntimeError("OPENAI_API_KEY missing")

    def _build(*_args):
        calls.append("build")

    session = bootstrap_tui_session(
        _args(), load_runtime_config=_load, build_engine=_build
    )

    assert session.engine is None
    assert session.startup_state.chat_enabled is False
    assert session.startup_state.stage == "config"
    assert session.runtime == {}
    assert calls == []


def test_bootstrap_tui_captures_engine_failure_with_provider_metadata():
    runtime = {
        "llm_provider_name": "openai",
        "llama_query_model": "gpt-test",
        "openai_api_base": "https://example.test/v1",
    }

    def _build(*_args):
        raise ValueError("Missing code_embedding_model")

    session = bootstrap_tui_session(
        _args(), load_runtime_config=lambda **_kwargs: runtime, build_engine=_build
    )

    assert session.startup_state.chat_enabled is False
    assert session.startup_state.provider_name == "openai"
    assert session.startup_state.model == "gpt-test"
    assert session.startup_state.base_url == "https://example.test/v1"
    assert session.runtime == runtime


def test_bootstrap_tui_preserves_runtime_defaults_for_domain_runner():
    runtime = {
        "research_hunters": "ssrf",
        "research_budget": "quick",
    }
    engine = object()
    vector_backend = object()

    session = bootstrap_tui_session(
        _args(),
        load_runtime_config=lambda **_kwargs: runtime,
        build_engine=lambda *_args: (engine, vector_backend),
    )

    assert session.engine is engine
    assert session.vector_backend is vector_backend
    assert session.runtime == runtime
