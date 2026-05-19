# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from typing import Any


class RetrievalCache:
    def __init__(self, max_entries: int = 1024) -> None:
        self._condition = threading.Condition()
        self._max_entries = max(1, int(max_entries or 1))
        self._items: OrderedDict[tuple[str, int, str], tuple[Any, ...]] = OrderedDict()
        self._inflight: set[tuple[str, int, str]] = set()
        self._generation = 0

    def get_or_set(self, key: tuple[str, int, str], factory) -> list[Any]:
        with self._condition:
            cached = self._items.get(key)
            if cached is not None:
                self._items.move_to_end(key)
                return list(cached)
            while key in self._inflight:
                self._condition.wait()
                cached = self._items.get(key)
                if cached is not None:
                    self._items.move_to_end(key)
                    return list(cached)
            self._inflight.add(key)
            generation = self._generation

        try:
            docs = tuple(factory() or ())
        except Exception:
            with self._condition:
                self._inflight.discard(key)
                self._condition.notify_all()
            raise

        with self._condition:
            if generation == self._generation:
                self._items[key] = docs
                self._items.move_to_end(key)
                while len(self._items) > self._max_entries:
                    self._items.popitem(last=False)
            self._inflight.discard(key)
            self._condition.notify_all()
            return list(docs)

    def clear(self) -> None:
        with self._condition:
            self._items.clear()
            self._generation += 1
            self._condition.notify_all()

    def __len__(self) -> int:
        with self._condition:
            return len(self._items)


class CachedRetriever:
    def __init__(
        self,
        retriever,
        *,
        cache: RetrievalCache,
        retriever_id: str,
        top_k: int,
    ) -> None:
        self._retriever = retriever
        self._cache = cache
        self._retriever_id = retriever_id
        self._top_k = int(top_k)

    def get_relevant_documents(self, query: str):
        query_text = str(query or "")
        query_hash = hashlib.sha256(
            query_text.encode("utf-8", errors="ignore")
        ).hexdigest()
        key = (self._retriever_id, self._top_k, query_hash)
        return self._cache.get_or_set(
            key,
            lambda: self._retriever.get_relevant_documents(query_text),
        )

    def __getattr__(self, name: str):
        return getattr(self._retriever, name)

    def __eq__(self, other: object) -> bool:
        return self._retriever == other
