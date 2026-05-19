# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import asyncio

from langchain_openai import AzureChatOpenAI
from llama_index.core.callbacks import CallbackManager
from llama_index.llms.langchain import LangChainLLM
from langchain_core.callbacks.base import BaseCallbackHandler
from unittest.mock import Mock

from metis.providers.azure_openai import (
    DEFAULT_EMBED_BATCH_SIZE,
    AzureOpenAIEmbeddingAdapter,
    AzureOpenAIProvider,
)


def _config():
    return {
        "llm_api_key": "test-key",
        "azure_endpoint": "https://example.openai.azure.com/",
        "azure_api_version": "2024-02-01",
        "engine": "chat-deployment",
        "chat_deployment_model": "gpt-4o-mini",
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-small",
    }


def test_query_engine_uses_langchain_adapter():
    provider = AzureOpenAIProvider(_config())

    assert provider.get_query_engine_class() is LangChainLLM

    llm = provider.get_query_model_kwargs()["llm"]
    assert isinstance(llm, AzureChatOpenAI)
    assert llm.deployment_name == "chat-deployment"
    assert llm.model_name == "gpt-4o-mini"


def test_embedding_adapter_preserves_azure_config():
    provider = AzureOpenAIProvider(_config())

    code_embeddings = provider.get_embed_model_code()
    docs_embeddings = provider.get_embed_model_docs()

    assert code_embeddings.model_name == "text-embedding-3-large"
    assert docs_embeddings.model_name == "text-embedding-3-small"
    assert code_embeddings._client.model == "text-embedding-3-large"
    assert docs_embeddings._client.model == "text-embedding-3-small"


def test_provider_accepts_callback_manager_for_query_and_embeddings():
    provider = AzureOpenAIProvider(_config())
    callback_manager = CallbackManager([])
    callback = Mock(spec=BaseCallbackHandler)

    query_kwargs = provider.get_query_model_kwargs(
        callback_manager=callback_manager,
        callbacks=[callback],
    )
    embeddings = provider.get_embed_model_code(callback_manager=callback_manager)

    assert query_kwargs["callback_manager"] is callback_manager
    assert query_kwargs["llm"].callbacks == [callback]
    assert embeddings.callback_manager is callback_manager


def test_provider_uses_explicit_callbacks_without_mutation():
    provider = AzureOpenAIProvider(_config())
    callback_manager = Mock(name="callback_manager")
    callback = Mock(spec=BaseCallbackHandler)

    query_kwargs = provider.get_query_model_kwargs(
        callback_manager=callback_manager,
        callbacks=[callback],
    )
    code_embeddings = provider.get_embed_model_code()

    assert query_kwargs["llm"].callbacks == [callback]
    assert query_kwargs["callback_manager"] is callback_manager
    assert code_embeddings.callback_manager is not callback_manager


def test_provider_passes_reasoning_effort_to_chat_model():
    config = _config()
    config["llama_query_reasoning_effort"] = "medium"
    provider = AzureOpenAIProvider(config)

    llm = provider.get_chat_model()

    assert llm.reasoning_effort == "medium"


def test_embedding_adapter_batches_document_embeddings():
    class FakeClient:
        model = "text-embedding-3-large"

        def __init__(self):
            self.calls = []

        def embed_documents(self, texts):
            self.calls.append(list(texts))
            return [[float(len(self.calls))] for _ in texts]

    client = FakeClient()
    adapter = AzureOpenAIEmbeddingAdapter(client)
    texts = [f"text-{index}" for index in range(DEFAULT_EMBED_BATCH_SIZE + 3)]

    embeddings = adapter._get_text_embeddings(texts)

    assert len(embeddings) == len(texts)
    assert [len(call) for call in client.calls] == [DEFAULT_EMBED_BATCH_SIZE, 3]


def test_embedding_adapter_batches_async_document_embeddings():
    class FakeClient:
        model = "text-embedding-3-large"

        def __init__(self):
            self.calls = []

        async def aembed_documents(self, texts):
            self.calls.append(list(texts))
            return [[float(len(self.calls))] for _ in texts]

    async def run_test():
        client = FakeClient()
        adapter = AzureOpenAIEmbeddingAdapter(client)
        texts = [f"text-{index}" for index in range(DEFAULT_EMBED_BATCH_SIZE + 3)]

        embeddings = await adapter._aget_text_embeddings(texts)

        assert len(embeddings) == len(texts)
        assert [len(call) for call in client.calls] == [DEFAULT_EMBED_BATCH_SIZE, 3]

    asyncio.run(run_test())


def test_embedding_adapter_uses_configured_batch_size():
    class FakeClient:
        model = "text-embedding-3-large"

        def __init__(self):
            self.calls = []

        def embed_documents(self, texts):
            self.calls.append(list(texts))
            return [[float(len(self.calls))] for _ in texts]

    client = FakeClient()
    adapter = AzureOpenAIEmbeddingAdapter(client, embed_batch_size=3)

    adapter._get_text_embeddings(["a", "b", "c", "d"])

    assert [len(call) for call in client.calls] == [3, 1]
