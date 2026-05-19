# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from llama_index.core.base.embeddings.base import BaseEmbedding, Embedding
from pydantic import PrivateAttr


class DiskEmbedCache:
    def __init__(self, path: str | Path, model_key: str, max_mb: int = 500):
        self.path = Path(path)
        self.model_key = str(model_key)
        self.max_bytes = max(1, int(max_mb or 500)) * 1024 * 1024
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._writes = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        return sqlite3.connect(str(self.path), timeout=30.0)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS embeddings (
                    text_hash TEXT NOT NULL,
                    model_key TEXT NOT NULL,
                    embedding BLOB NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (text_hash, model_key)
                )
                """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_embeddings_created_at "
                "ON embeddings(created_at)"
            )

    def get_batch(self, texts: list[str]) -> list[Embedding | None]:
        if not texts:
            return []
        hashes = [_hash_text(text) for text in texts]
        placeholders = ",".join("?" for _ in hashes)
        rows: dict[str, bytes] = {}
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                (
                    "SELECT text_hash, embedding FROM embeddings "
                    f"WHERE model_key = ? AND text_hash IN ({placeholders})"
                ),
                (self.model_key, *hashes),
            )
            rows = {str(row[0]): row[1] for row in cursor.fetchall()}

        results: list[Embedding | None] = []
        hits = 0
        for digest in hashes:
            raw = rows.get(digest)
            if raw is None:
                results.append(None)
                continue
            results.append(_decode_embedding(raw))
            hits += 1
        misses = len(texts) - hits
        with self._lock:
            self._hits += hits
            self._misses += misses
        return results

    def put_batch(self, texts: list[str], embeddings: list[Embedding]) -> None:
        if not texts or not embeddings:
            return
        now = time.time()
        rows = [
            (
                _hash_text(text),
                self.model_key,
                _encode_embedding(embedding),
                now,
            )
            for text, embedding in zip(texts, embeddings)
        ]
        with self._lock, self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO embeddings
                    (text_hash, model_key, embedding, created_at)
                VALUES (?, ?, ?, ?)
                """,
                rows,
            )
            self._writes += len(rows)
            self._prune_locked(conn)

    def stats(self, *, reset: bool = False) -> dict[str, int]:
        with self._lock:
            snapshot = {
                "cache_hits": self._hits,
                "cache_misses": self._misses,
                "cache_writes": self._writes,
            }
            if reset:
                self._hits = 0
                self._misses = 0
                self._writes = 0
        return snapshot

    def _prune_locked(self, conn) -> None:
        total = conn.execute(
            "SELECT COALESCE(SUM(length(embedding)), 0) FROM embeddings"
        ).fetchone()[0]
        if int(total or 0) <= self.max_bytes:
            return
        rows = conn.execute(
            "SELECT text_hash, model_key, length(embedding) FROM embeddings "
            "ORDER BY created_at ASC"
        ).fetchall()
        for text_hash, model_key, size in rows:
            if int(total or 0) <= self.max_bytes:
                break
            conn.execute(
                "DELETE FROM embeddings WHERE text_hash = ? AND model_key = ?",
                (text_hash, model_key),
            )
            total = int(total or 0) - int(size or 0)


class CachedEmbedModel(BaseEmbedding):
    _inner: Any = PrivateAttr()
    _cache: DiskEmbedCache = PrivateAttr()

    def __init__(self, inner, cache: DiskEmbedCache):
        params: dict[str, Any] = {
            "model_name": _model_name(inner),
            "embed_batch_size": _embed_batch_size(inner),
        }
        if isinstance(inner, BaseEmbedding):
            params["callback_manager"] = inner.callback_manager
            params["num_workers"] = inner.num_workers
        super().__init__(**params)
        self._inner = inner
        self._cache = cache

    @property
    def inner(self):
        return self._inner

    @property
    def cache(self) -> DiskEmbedCache:
        return self._cache

    def cache_stats(self, *, reset: bool = False) -> dict[str, int]:
        return self._cache.stats(reset=reset)

    def _get_text_embedding(self, text: str) -> Embedding:
        return self.get_text_embedding_batch([text])[0]

    def _get_text_embeddings(self, texts: list[str]) -> list[Embedding]:
        return self.get_text_embedding_batch(texts)

    def get_text_embedding_batch(
        self,
        texts: list[str],
        show_progress: bool = False,
        **kwargs: Any,
    ) -> list[Embedding]:
        cached = self._cache.get_batch(list(texts))
        misses = [
            (idx, text)
            for idx, (text, value) in enumerate(zip(texts, cached))
            if value is None
        ]
        if misses:
            fresh = self._embed_text_misses(
                [text for _, text in misses],
                show_progress=show_progress,
                **kwargs,
            )
            self._cache.put_batch([text for _, text in misses], fresh)
            for (idx, _text), embedding in zip(misses, fresh):
                cached[idx] = embedding
        return [embedding for embedding in cached if embedding is not None]

    async def _aget_text_embedding(self, text: str) -> Embedding:
        return (await self.aget_text_embedding_batch([text]))[0]

    async def _aget_text_embeddings(self, texts: list[str]) -> list[Embedding]:
        return await self.aget_text_embedding_batch(texts)

    async def aget_text_embedding_batch(
        self,
        texts: list[str],
        show_progress: bool = False,
        **kwargs: Any,
    ) -> list[Embedding]:
        cached = self._cache.get_batch(list(texts))
        misses = [
            (idx, text)
            for idx, (text, value) in enumerate(zip(texts, cached))
            if value is None
        ]
        if misses:
            fresh = await self._aembed_text_misses(
                [text for _, text in misses],
                show_progress=show_progress,
                **kwargs,
            )
            self._cache.put_batch([text for _, text in misses], fresh)
            for (idx, _text), embedding in zip(misses, fresh):
                cached[idx] = embedding
        return [embedding for embedding in cached if embedding is not None]

    def _get_query_embedding(self, query: str) -> Embedding:
        if hasattr(self._inner, "get_query_embedding"):
            return self._inner.get_query_embedding(query)
        return self._inner._get_query_embedding(query)

    async def _aget_query_embedding(self, query: str) -> Embedding:
        if hasattr(self._inner, "aget_query_embedding"):
            return await self._inner.aget_query_embedding(query)
        if hasattr(self._inner, "_aget_query_embedding"):
            return await self._inner._aget_query_embedding(query)
        return await asyncio.to_thread(self._get_query_embedding, query)

    def _embed_text_misses(
        self,
        texts: list[str],
        *,
        show_progress: bool = False,
        **kwargs: Any,
    ) -> list[Embedding]:
        if hasattr(self._inner, "get_text_embedding_batch"):
            return self._inner.get_text_embedding_batch(
                texts,
                show_progress=show_progress,
                **kwargs,
            )
        if hasattr(self._inner, "_get_text_embeddings"):
            return self._inner._get_text_embeddings(texts)
        return [self._inner._get_text_embedding(text) for text in texts]

    async def _aembed_text_misses(
        self,
        texts: list[str],
        *,
        show_progress: bool = False,
        **kwargs: Any,
    ) -> list[Embedding]:
        if hasattr(self._inner, "aget_text_embedding_batch"):
            return await self._inner.aget_text_embedding_batch(
                texts,
                show_progress=show_progress,
                **kwargs,
            )
        if hasattr(self._inner, "_aget_text_embeddings"):
            return await self._inner._aget_text_embeddings(texts)
        return await asyncio.to_thread(
            self._embed_text_misses,
            texts,
            show_progress=show_progress,
            **kwargs,
        )


def build_embed_cache_model_key(kind: str, model, embed_dim: int | None = None) -> str:
    parts = [str(kind), _model_name(model)]
    if embed_dim is not None:
        parts.append(str(embed_dim))
    return ":".join(parts)


def _hash_text(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _encode_embedding(embedding) -> bytes:
    return json.dumps(
        [float(value) for value in embedding], separators=(",", ":")
    ).encode("utf-8")


def _decode_embedding(raw: bytes) -> Embedding:
    return [float(value) for value in json.loads(raw.decode("utf-8"))]


def _model_name(model) -> str:
    for attr in ("model_name", "model", "_text_engine", "_query_engine"):
        value = getattr(model, attr, None)
        if value:
            return str(value)
    return model.__class__.__name__


def _embed_batch_size(model) -> int:
    try:
        return min(2048, max(1, int(getattr(model, "embed_batch_size", 10) or 10)))
    except Exception:
        return 10
