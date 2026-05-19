# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

import unidiff  # type: ignore[import-untyped]
from llama_index.core import SimpleDirectoryReader, VectorStoreIndex
from llama_index.core.schema import Document

from metis.exceptions import ParsingError
from metis.utils import read_file_content

from .code_index import FunctionIndex, ensure_embedding_safe_nodes
from .diff_utils import extract_content_from_diff, resolve_patch_path
from .helpers import (
    prepare_code_nodes_for_document,
    prepare_nodes_iter,
)
from .repository import EngineRepository
from .runtime import EngineConfig, EngineState

logger = logging.getLogger("metis")


class IndexingService:
    def __init__(
        self,
        config: EngineConfig,
        state: EngineState,
        repository: EngineRepository,
    ):
        self._config = config
        self._state = state
        self._repository = repository

    def index_codebase(
        self,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.index_prepare_nodes()
        self.index_finalize_embeddings(progress_callback=progress_callback)

    def count_index_items_by_kind(self) -> dict[str, int]:
        docs_exts = self._config.plugin_config.get("docs", {}).get(
            "supported_extensions", [".md"]
        )
        code_count = len(self._repository.get_code_files())

        doc_count = 0
        base_path = os.path.abspath(self._config.codebase_path)
        metisignore_spec = self._repository.load_metisignore()
        for root, _, files in os.walk(base_path):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                if os.path.splitext(file_name)[1].lower() not in docs_exts:
                    continue
                if self._repository.is_metisignored(full_path, spec=metisignore_spec):
                    continue
                doc_count += 1

        return {"code": code_count, "docs": doc_count, "total": code_count + doc_count}

    def count_index_items(self) -> int:
        return self.count_index_items_by_kind()["total"]

    def _collect_index_input_files(
        self,
        required_exts: list[str],
        metisignore_spec,
    ) -> list[str]:
        required = {ext.lower() for ext in required_exts}
        base_path = os.path.abspath(self._config.codebase_path)
        input_files: list[str] = []
        for root, _, files in os.walk(base_path):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                if os.path.splitext(file_name)[1].lower() not in required:
                    continue
                if self._repository.is_metisignored(full_path, spec=metisignore_spec):
                    continue
                input_files.append(full_path)
        return sorted(input_files)

    @staticmethod
    def _docstore_hash_matches(docstore, doc_id: str, doc_hash: str | None) -> bool:
        if not doc_hash:
            return False
        getter = getattr(docstore, "get_document_hash", None)
        if callable(getter):
            try:
                return getter(doc_id) == doc_hash
            except Exception:
                return False
        for attr in ("document_hashes", "_document_hashes"):
            hashes = getattr(docstore, attr, None)
            if isinstance(hashes, dict):
                return hashes.get(doc_id) == doc_hash
        return False

    def _clear_retrieval_cache(self) -> None:
        cache = self._state.retrieval_cache
        if cache is not None:
            cache.clear()

    def _reset_query_engines(self) -> None:
        self._clear_retrieval_cache()
        self._state.qe_code = None
        self._state.qe_docs = None

    @staticmethod
    def _function_index_hash_matches(
        function_index: FunctionIndex, doc_id: str, doc_hash: str | None
    ) -> bool:
        return function_index.file_hash_matches(doc_id, doc_hash)

    def index_prepare_nodes_iter(
        self,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        docs_supported_exts = self._config.plugin_config.get("docs", {}).get(
            "supported_extensions", [".md"]
        )
        code_supported_exts = self._repository.get_all_supported_code_extensions()

        logger.info(f"Indexing codebase at: {self._config.codebase_path}")
        metisignore_spec = self._repository.load_metisignore()
        input_files = self._collect_index_input_files(
            code_supported_exts + docs_supported_exts,
            metisignore_spec,
        )
        if input_files:
            reader = SimpleDirectoryReader(
                input_files=input_files,
                filename_as_id=True,
            )
            documents = reader.load_data()
        else:
            documents = []
        logger.info(
            f"Loaded {len(documents)} documents from {self._config.codebase_path}"
        )

        self._config.vector_backend.init()
        storage_context_code, storage_context_docs = (
            self._config.vector_backend.get_storage_contexts()
        )
        doc_splitter = self._repository.get_doc_splitter()
        base_path = os.path.abspath(self._config.codebase_path)
        parent_dir = os.path.dirname(base_path)
        function_index = self._repository.load_function_index() or FunctionIndex()
        code_docs = []
        doc_docs = []
        current_code_doc_ids: set[str] = set()
        skipped_count = 0
        for doc in documents:
            if self._repository.is_metisignored(doc.id_, spec=metisignore_spec):
                continue
            ext = os.path.splitext(doc.id_)[1].lower()
            new_id = os.path.relpath(doc.id_, parent_dir)
            doc.doc_id = new_id
            doc.id_ = new_id
            doc_hash = getattr(doc, "hash", None)

            if ext in docs_supported_exts:
                if self._docstore_hash_matches(
                    storage_context_docs.docstore,
                    new_id,
                    doc_hash,
                ):
                    skipped_count += 1
                    continue
                doc_docs.append(doc)
            elif ext in code_supported_exts:
                current_code_doc_ids.add(new_id)
                unchanged = self._docstore_hash_matches(
                    storage_context_code.docstore,
                    new_id,
                    doc_hash,
                )
                if unchanged and self._function_index_hash_matches(
                    function_index,
                    new_id,
                    doc_hash,
                ):
                    skipped_count += 1
                    continue
                code_docs.append(doc)
            if progress_callback is not None:
                progress_callback(
                    {
                        "event": "index.item.discovered",
                        "message": f"Discovered {new_id}",
                        "current_document_path": new_id,
                        "code_count": len(code_docs),
                        "doc_count": len(doc_docs),
                        "skipped_count": skipped_count,
                    }
                )

        normalized_current_code_doc_ids = {
            os.path.normpath(doc_id) for doc_id in current_code_doc_ids
        }
        for file_path in list(function_index.files()):
            if os.path.normpath(file_path) not in normalized_current_code_doc_ids:
                function_index.remove_file(file_path, rebuild=False)
        prepared = yield from prepare_nodes_iter(
            code_docs,
            doc_docs,
            self._repository.get_plugin_for_extension,
            self._repository.get_splitter_cached,
            doc_splitter,
            max_workers=self._config.max_workers,
            base_function_index=function_index,
        )
        if len(prepared) == 3:
            nodes_code, nodes_docs, function_index = prepared
            self._state.pending_function_index = function_index
        else:
            nodes_code, nodes_docs = prepared
            self._state.pending_function_index = None

        self._state.pending_nodes = (nodes_code, nodes_docs)
        if progress_callback is not None:
            progress_callback(
                {
                    "event": "index.nodes.prepared",
                    "message": "Prepared index nodes",
                    "code_node_count": len(nodes_code),
                    "doc_node_count": len(nodes_docs),
                    "skipped_count": skipped_count,
                }
            )
        return

    def index_prepare_nodes(self):
        for _ in self.index_prepare_nodes_iter():
            pass

    def _embed_cache_stats(self, *, reset: bool = False) -> dict[str, int]:
        totals = {"cache_hits": 0, "cache_misses": 0, "cache_writes": 0}
        for model in (self._config.embed_model_code, self._config.embed_model_docs):
            stats_fn = getattr(model, "cache_stats", None)
            if not callable(stats_fn):
                continue
            stats = stats_fn(reset=reset)
            if not isinstance(stats, dict):
                continue
            for key in totals:
                totals[key] += int(stats.get(key, 0) or 0)
        return totals

    def index_finalize_embeddings(
        self,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self._embed_cache_stats(reset=True)
        pending = self._state.pending_nodes
        if not pending:
            if progress_callback is not None:
                progress_callback(
                    {
                        "event": "index.embeddings.finished",
                        "message": "Embedding complete",
                        **self._embed_cache_stats(),
                    }
                )
            return
        nodes_code, nodes_docs = pending
        if not nodes_code and not nodes_docs:
            if self._state.pending_function_index is not None:
                self._state.pending_function_index.write(
                    self._repository.get_function_index_path()
                )
            self._state.pending_function_index = None
            self._state.pending_nodes = None
            self._reset_query_engines()
            if progress_callback is not None:
                progress_callback(
                    {
                        "event": "index.embeddings.finished",
                        "message": "Embedding complete",
                        **self._embed_cache_stats(),
                    }
                )
            return
        storage_context_code, storage_context_docs = (
            self._config.vector_backend.get_storage_contexts()
        )
        VectorStoreIndex(
            nodes_code,
            storage_context=storage_context_code,
            embed_model=self._config.embed_model_code,
            **self._config.usage_runtime.hooks.embed_model_kwargs(),
        )

        VectorStoreIndex(
            nodes_docs,
            storage_context=storage_context_docs,
            embed_model=self._config.embed_model_docs,
            **self._config.usage_runtime.hooks.embed_model_kwargs(),
        )
        if self._state.pending_function_index is not None:
            self._state.pending_function_index.write(
                self._repository.get_function_index_path()
            )
            self._state.pending_function_index = None
        self._state.pending_nodes = None
        self._reset_query_engines()
        if progress_callback is not None:
            progress_callback(
                {
                    "event": "index.embeddings.finished",
                    "message": "Embedding complete",
                    **self._embed_cache_stats(),
                }
            )

    def update_index(self, patch_text):
        try:
            patch_set = unidiff.PatchSet.from_string(patch_text)
            logger.info("Parsed the provided patch string successfully.")
        except Exception as e:
            raise ParsingError(f"Error parsing patch string: {e}")
        self._config.vector_backend.init()
        storage_context_code, storage_context_docs = (
            self._config.vector_backend.get_storage_contexts()
        )

        index_code = VectorStoreIndex.from_vector_store(
            self._config.vector_backend.vector_store_code,
            storage_context=storage_context_code,
            embed_model=self._config.embed_model_code,
            **self._config.usage_runtime.hooks.embed_model_kwargs(),
        )
        index_docs = VectorStoreIndex.from_vector_store(
            self._config.vector_backend.vector_store_docs,
            storage_context=storage_context_docs,
            embed_model=self._config.embed_model_docs,
            **self._config.usage_runtime.hooks.embed_model_kwargs(),
        )

        doc_splitter = self._repository.get_doc_splitter()
        function_index = self._repository.load_function_index() or FunctionIndex()
        function_index_changed = False

        mutating_started = False
        try:
            for diff_file in patch_set:
                if diff_file.is_binary_file:
                    continue
                resolved_patch_path = resolve_patch_path(
                    self._config.codebase_path,
                    diff_file.path,
                )
                if resolved_patch_path is None:
                    logger.warning(
                        "Skipping patch path outside codebase: %s", diff_file.path
                    )
                    continue
                _abs_patch_path, rel_patch_path = resolved_patch_path
                doc_id = os.path.join(
                    os.path.basename(os.path.abspath(self._config.codebase_path)),
                    rel_patch_path,
                )
                ext = os.path.splitext(doc_id)[1].lower()
                target_index = (
                    index_code
                    if ext in self._repository.get_all_supported_code_extensions()
                    else index_docs
                )

                if diff_file.is_removed_file:
                    mutating_started = True
                    target_index.delete_ref_doc(doc_id, delete_from_docstore=True)
                    if ext in self._repository.get_all_supported_code_extensions():
                        function_index.remove_file(doc_id, rebuild=False)
                        function_index_changed = True
                else:
                    file_path = os.path.join(self._config.codebase_path, rel_patch_path)
                    file_content = read_file_content(file_path)
                    if not file_content and diff_file.is_added_file:
                        file_content = extract_content_from_diff(diff_file)
                    if not file_content:
                        logger.warning("No content available for %s", diff_file.path)
                        continue
                    doc = Document(
                        text=file_content,
                        metadata={"file_name": rel_patch_path},
                        id_=doc_id,
                    )

                    code_exts = self._repository.get_all_supported_code_extensions()
                    if diff_file.is_added_file:
                        if ext in code_exts:
                            plugin = self._repository.get_plugin_for_extension(ext)
                            if not plugin:
                                continue
                            nodes, file_function_index = (
                                prepare_code_nodes_for_document(
                                    doc,
                                    plugin,
                                    self._repository.get_splitter_cached,
                                )
                            )
                            nodes = ensure_embedding_safe_nodes(nodes)
                            function_index.remove_file(doc_id, rebuild=False)
                            function_index.merge(file_function_index, rebuild=False)
                            function_index_changed = True
                        else:
                            nodes = doc_splitter.get_nodes_from_documents([doc])
                        mutating_started = True
                        target_index.insert_nodes(nodes)
                    else:
                        if ext in code_exts:
                            plugin = self._repository.get_plugin_for_extension(ext)
                            if not plugin:
                                continue
                            nodes, file_function_index = (
                                prepare_code_nodes_for_document(
                                    doc,
                                    plugin,
                                    self._repository.get_splitter_cached,
                                )
                            )
                            nodes = ensure_embedding_safe_nodes(nodes)
                            mutating_started = True
                            target_index.delete_ref_doc(
                                doc_id, delete_from_docstore=True
                            )
                            target_index.insert_nodes(nodes)
                            function_index.remove_file(doc_id, rebuild=False)
                            function_index.merge(file_function_index, rebuild=False)
                            function_index_changed = True
                        else:
                            mutating_started = True
                            target_index.refresh_ref_docs([doc])
                    target_index.docstore.set_document_hash(doc.id_, doc.hash)
            if function_index_changed:
                function_index.rebuild_edges()
                function_index.write(self._repository.get_function_index_path())
        finally:
            if mutating_started:
                self._reset_query_engines()
        logger.info("Index update complete based on the provided patch diff.")
