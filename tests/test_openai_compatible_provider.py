# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

from langchain_openai import ChatOpenAI

from metis.providers import openai_compatible
from metis.providers.openai_compatible import OpenAICompatibleProvider


def _config(**overrides):
    config = {
        "llm_api_key": "test-key",
        "model": "gpt-test",
        "llama_query_model": "gpt-test",
        "llama_query_temperature": 0.0,
        "llama_query_max_tokens": 256,
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-large",
    }
    config.update(overrides)
    return config


def test_chat_model_uses_configured_reasoning_effort():
    provider = OpenAICompatibleProvider(_config(llama_query_reasoning_effort="high"))

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatOpenAI)
    assert llm.reasoning_effort == "high"


def test_query_model_kwargs_include_configured_reasoning_effort():
    provider = OpenAICompatibleProvider(_config(llama_query_reasoning_effort="low"))

    params = provider.get_query_model_kwargs()

    assert params["reasoning_effort"] == "low"


def test_reasoning_effort_is_omitted_when_unconfigured():
    provider = OpenAICompatibleProvider(_config())

    params = provider.get_query_model_kwargs()

    assert "reasoning_effort" not in params


def test_provider_sets_default_ssl_cert_file_when_unset(monkeypatch, tmp_path):
    cert_file = tmp_path / "cert.pem"
    cert_file.write_text("test cert", encoding="utf-8")
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.setattr(
        openai_compatible.ssl,
        "get_default_verify_paths",
        lambda: SimpleNamespace(cafile=str(cert_file)),
    )

    OpenAICompatibleProvider(_config())

    assert openai_compatible.os.environ["SSL_CERT_FILE"] == str(cert_file)


def test_embedding_model_defaults_to_bounded_batch_size(monkeypatch):
    class FakeEmbedding:
        def __init__(self, **params):
            self.params = params
            self.model_name = params["model"]

    monkeypatch.setattr(openai_compatible, "OpenAIEmbedding", FakeEmbedding)
    provider = OpenAICompatibleProvider(_config())

    embeddings = provider.get_embed_model_code()

    assert (
        embeddings.params["embed_batch_size"]
        == openai_compatible.DEFAULT_EMBED_BATCH_SIZE
    )


def test_embedding_extra_kwargs_can_override_batch_size(monkeypatch):
    class FakeEmbedding:
        def __init__(self, **params):
            self.params = params
            self.model_name = params["model"]

    monkeypatch.setattr(openai_compatible, "OpenAIEmbedding", FakeEmbedding)
    provider = OpenAICompatibleProvider(
        _config(code_embedding_extra_kwargs={"embed_batch_size": 7})
    )

    embeddings = provider.get_embed_model_code()

    assert embeddings.params["embed_batch_size"] == 7
