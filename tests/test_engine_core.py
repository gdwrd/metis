# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
import tempfile
import threading
import time
from unittest.mock import Mock
from metis.engine import MetisEngine
from metis.engine.embed_cache import CachedEmbedModel
from metis.engine.retrieval_cache import RetrievalCache
from metis.exceptions import PluginNotFoundError, QueryEngineInitError
from metis.usage import UsageRuntime


def test_supported_languages():
    langs = MetisEngine.supported_languages()
    assert "c" in langs
    assert "python" in langs
    assert "rust" in langs
    assert "typescript" in langs


def test_get_existing_plugin(engine):
    plugin = engine.get_plugin_from_name("c")
    assert plugin.get_name().lower() == "c"


def test_get_missing_plugin_raises(engine):
    with pytest.raises(PluginNotFoundError):
        engine.get_plugin_from_name("nonexistent")


def test_init_and_get_query_engines_raises_on_missing_backend():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=(None, None))
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    with pytest.raises(QueryEngineInitError):
        engine._init_and_get_query_engines()


def test_init_and_get_default_unavailable_metisignore():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=(None, None))
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        metisignore_file=".metisignore_file",
    )
    assert engine.metisignore_file == ".metisignore_file"
    assert engine.repository.load_metisignore() is None


def test_init_and_get_default_available_metisignore():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=(None, None))
    engine = None
    with tempfile.NamedTemporaryFile(
        mode="w+t", encoding="utf-8", suffix=".yaml"
    ) as temp_file:
        engine = MetisEngine(
            vector_backend=bad_backend,
            llm_provider=Mock(),
            max_workers=2,
            max_token_length=2048,
            llama_query_model="gpt-test",
            similarity_top_k=3,
            response_mode="compact",
            metisignore_file=temp_file.name,
        )
        assert engine.repository.load_metisignore() is not None
        assert engine.metisignore_file == temp_file.name
    assert engine is not None


def test_init_and_get_query_engines_is_thread_safe():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        max_workers=4,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    results = []

    def _worker():
        results.append(engine._init_and_get_query_engines())

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results == [("code-qe", "docs-qe")] * 8
    backend.init.assert_called_once()
    backend.get_query_engines.assert_called_once()


def test_engine_passes_usage_callback_manager_to_embed_models():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    assert llm_provider.get_embed_model_code.call_args.kwargs == {
        "callback_manager": engine.usage_runtime.hooks.callback_manager
    }
    assert llm_provider.get_embed_model_docs.call_args.kwargs == {
        "callback_manager": engine.usage_runtime.hooks.callback_manager
    }


def test_create_query_engines_passes_usage_callback_manager():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine._create_query_engines(5)

    assert (
        backend.get_query_engines.call_args.kwargs["callback_manager"]
        is engine.usage_runtime.hooks.callback_manager
    )
    assert (
        backend.get_query_engines.call_args.kwargs["callbacks"]
        == engine.usage_runtime.hooks.callbacks
    )


def test_review_graph_uses_usage_callbacks():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()
    llm_provider.get_chat_model.return_value = Mock(with_structured_output=Mock())

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine._get_review_graph()

    assert (
        llm_provider.get_chat_model.call_args.kwargs["callbacks"]
        == engine.usage_runtime.hooks.callbacks
    )


def test_engine_reuses_injected_runtime_and_backend_embed_models(tmp_path):
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    backend.embed_model_code = object()
    backend.embed_model_docs = object()
    llm_provider = Mock()
    runtime = UsageRuntime(tmp_path)

    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        usage_runtime=runtime,
    )

    assert engine.usage_runtime is runtime
    assert engine.get_embed_model_code() is backend.embed_model_code
    assert engine.get_embed_model_docs() is backend.embed_model_docs
    llm_provider.get_embed_model_code.assert_not_called()
    llm_provider.get_embed_model_docs.assert_not_called()


def test_engine_wraps_embed_models_when_disk_cache_enabled(tmp_path):
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    code_model = Mock()
    docs_model = Mock()
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = code_model
    llm_provider.get_embed_model_docs.return_value = docs_model

    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        embed_cache_enabled=True,
        embed_cache_path=str(tmp_path / "embed.sqlite"),
        embed_cache_max_mb=1,
        embed_dim=3,
    )

    assert isinstance(engine.get_embed_model_code(), CachedEmbedModel)
    assert isinstance(engine.get_embed_model_docs(), CachedEmbedModel)
    assert engine.get_embed_model_code().inner is code_model
    assert engine.get_embed_model_docs().inner is docs_model
    assert backend.embed_model_code is engine.get_embed_model_code()
    assert backend.embed_model_docs is engine.get_embed_model_docs()


def test_engine_exposes_focused_services_without_compat_aliases():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine.review.review_code = Mock(return_value=iter([{"file": "a.py"}]))
    engine.indexing.update_index = Mock()

    results = list(engine.review.review_code())

    assert engine.repository is not None
    assert engine.review is not None
    assert engine.indexing is not None
    assert not hasattr(engine, "review_service")
    assert not hasattr(engine, "indexing_service")
    assert results == [{"file": "a.py"}]
    engine.indexing.update_index("diff --git")
    engine.indexing.update_index.assert_called_once_with("diff --git")


def test_close_clears_query_cache_and_closes_backend():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    backend.close = Mock()
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    assert engine._init_and_get_query_engines() == ("code-qe", "docs-qe")
    assert backend.get_query_engines.call_count == 1

    engine.close()

    assert engine._state.qe_code is None
    assert engine._state.qe_docs is None
    backend.close.assert_called_once()

    assert engine._init_and_get_query_engines() == ("code-qe", "docs-qe")
    assert backend.get_query_engines.call_count == 2


def test_query_engine_retrievers_cache_repeated_queries_per_engine():
    class _Doc:
        def __init__(self, text):
            self.page_content = text

    class _CountingRetriever:
        def __init__(self, prefix):
            self.prefix = prefix
            self.calls = 0

        def get_relevant_documents(self, query):
            self.calls += 1
            return [_Doc(f"{self.prefix}:{query}:{self.calls}")]

    code = _CountingRetriever("code")
    docs = _CountingRetriever("docs")
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=(code, docs))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    qe_code, qe_docs = engine._init_and_get_query_engines()

    assert qe_code.get_relevant_documents("same")[0].page_content == "code:same:1"
    assert qe_code.get_relevant_documents("same")[0].page_content == "code:same:1"
    assert qe_docs.get_relevant_documents("same")[0].page_content == "docs:same:1"
    assert code.calls == 1
    assert docs.calls == 1

    engine.clear_retrieval_cache()

    assert qe_code.get_relevant_documents("same")[0].page_content == "code:same:2"
    assert code.calls == 2


def test_retrieval_cache_single_flights_concurrent_identical_queries():
    class _Doc:
        def __init__(self, text):
            self.page_content = text

    class _SlowRetriever:
        def __init__(self):
            self.calls = 0
            self.lock = threading.Lock()

        def get_relevant_documents(self, query):
            with self.lock:
                self.calls += 1
            time.sleep(0.05)
            return [_Doc(query)]

    retriever = _SlowRetriever()
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=(retriever, Mock()))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()
    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=4,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    qe_code, _qe_docs = engine._init_and_get_query_engines()
    barrier = threading.Barrier(8)
    results = []

    def _worker():
        barrier.wait()
        results.append(qe_code.get_relevant_documents("same")[0].page_content)

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results == ["same"] * 8
    assert retriever.calls == 1


def test_retrieval_cache_clear_does_not_store_inflight_result():
    cache = RetrievalCache()
    key = ("code", 3, "query")
    started = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    calls = 0
    results = []

    def _factory():
        nonlocal calls
        with lock:
            calls += 1
            value = calls
        started.set()
        release.wait(timeout=2)
        return [f"doc-{value}"]

    thread = threading.Thread(
        target=lambda: results.append(cache.get_or_set(key, _factory)[0])
    )
    thread.start()
    assert started.wait(timeout=2)

    cache.clear()
    release.set()
    thread.join(timeout=2)

    assert results == ["doc-1"]
    assert len(cache) == 0
    assert cache.get_or_set(key, _factory)[0] == "doc-2"
    assert calls == 2


def test_retrieval_cache_evicts_least_recently_used_entry():
    cache = RetrievalCache(max_entries=2)
    calls: dict[tuple[str, int, str], int] = {}

    def _factory(key):
        calls[key] = calls.get(key, 0) + 1
        return [f"{key[2]}:{calls[key]}"]

    key_a = ("code", 3, "a")
    key_b = ("code", 3, "b")
    key_c = ("code", 3, "c")

    assert cache.get_or_set(key_a, lambda: _factory(key_a)) == ["a:1"]
    assert cache.get_or_set(key_b, lambda: _factory(key_b)) == ["b:1"]
    assert cache.get_or_set(key_a, lambda: _factory(key_a)) == ["a:1"]
    assert cache.get_or_set(key_c, lambda: _factory(key_c)) == ["c:1"]

    assert len(cache) == 2
    assert cache.get_or_set(key_b, lambda: _factory(key_b)) == ["b:2"]


def test_metis_engine_passes_configured_retrieval_cache_bound():
    class _Doc:
        def __init__(self, text):
            self.page_content = text

    class _Retriever:
        def __init__(self):
            self.calls: list[str] = []

        def get_relevant_documents(self, query):
            self.calls.append(query)
            return [_Doc(f"{query}:{len(self.calls)}")]

    retriever = _Retriever()
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=(retriever, Mock()))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()
    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        retrieval_cache_max_entries=1,
    )
    qe_code, _qe_docs = engine._init_and_get_query_engines()

    assert qe_code.get_relevant_documents("a")[0].page_content == "a:1"
    assert qe_code.get_relevant_documents("b")[0].page_content == "b:2"
    assert qe_code.get_relevant_documents("a")[0].page_content == "a:3"
