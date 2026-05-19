# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import asyncio

from metis.engine.embed_cache import CachedEmbedModel, DiskEmbedCache


class _EmbedModel:
    model_name = "fake-embed"
    embed_batch_size = 16

    def __init__(self):
        self.calls = []
        self.async_calls = []

    def get_text_embedding_batch(self, texts, **_kwargs):
        self.calls.append(list(texts))
        return [[float(len(text))] for text in texts]

    async def aget_text_embedding_batch(self, texts, **_kwargs):
        self.async_calls.append(list(texts))
        return [[float(len(text) + 10)] for text in texts]

    def get_query_embedding(self, query):
        return [float(len(query))]


def test_disk_embed_cache_serves_warm_batch_without_inner_call(tmp_path):
    inner = _EmbedModel()
    cache = DiskEmbedCache(tmp_path / "embed.sqlite", model_key="fake", max_mb=1)
    model = CachedEmbedModel(inner, cache)

    assert model.get_text_embedding_batch(["a", "bb"]) == [[1.0], [2.0]]
    assert model.get_text_embedding_batch(["a", "bb"]) == [[1.0], [2.0]]

    assert inner.calls == [["a", "bb"]]
    assert cache.stats() == {
        "cache_hits": 2,
        "cache_misses": 2,
        "cache_writes": 2,
    }


def test_disk_embed_cache_fetches_only_partial_misses(tmp_path):
    inner = _EmbedModel()
    cache = DiskEmbedCache(tmp_path / "embed.sqlite", model_key="fake", max_mb=1)
    model = CachedEmbedModel(inner, cache)

    assert model.get_text_embedding_batch(["a", "bb"]) == [[1.0], [2.0]]
    assert model.get_text_embedding_batch(["bb", "ccc", "a"]) == [
        [2.0],
        [3.0],
        [1.0],
    ]

    assert inner.calls == [["a", "bb"], ["ccc"]]


def test_disk_embed_cache_supports_async_misses_and_hits(tmp_path):
    async def _run():
        inner = _EmbedModel()
        cache = DiskEmbedCache(tmp_path / "embed.sqlite", model_key="fake", max_mb=1)
        model = CachedEmbedModel(inner, cache)

        assert await model.aget_text_embedding_batch(["a"]) == [[11.0]]
        assert await model.aget_text_embedding_batch(["a"]) == [[11.0]]

        assert inner.async_calls == [["a"]]

    asyncio.run(_run())
