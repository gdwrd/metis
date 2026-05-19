# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from metis.usage import UsageRuntime


@dataclass(slots=True)
class EngineConfig:
    codebase_path: str
    vector_backend: Any
    llm_provider: Any
    usage_runtime: UsageRuntime
    plugin_config: dict[str, Any]
    custom_prompt_text: str | None
    custom_guidance_precedence: str
    embed_model_code: Any
    embed_model_docs: Any
    embed_cache_enabled: bool
    embed_cache_path: str | None
    embed_cache_max_mb: int
    async_llm_enabled: bool
    max_workers: int
    review_max_workers: int
    triage_max_workers: int
    retrieval_cache_max_entries: int
    max_token_length: int
    llama_query_model: str
    similarity_top_k: int
    response_mode: str
    doc_chunk_size: int
    doc_chunk_overlap: int
    metisignore_file: str | None
    review_mode: str
    review_agentic_max_iterations: int
    review_agentic_max_tool_calls: int
    review_agentic_tool_timeout_seconds: int
    review_agentic_max_extra_tokens: int
    review_agentic_wallclock_seconds: float
    review_code_include_paths: list[str]
    review_code_exclude_paths: list[str]
    skip_test_files: bool
    extra_test_path_patterns: list[str]
    code_exts: set[str] = field(default_factory=set)
    ext_plugin_map: dict[str, Any] = field(default_factory=dict)
    ext_pattern_plugin_map: list[tuple[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class EngineState:
    splitter_cache: dict[str, Any] = field(default_factory=dict)
    doc_splitter: Any | None = None
    review_graph: Any | None = None
    ask_graph: Any | None = None
    qe_code: Any | None = None
    qe_docs: Any | None = None
    pending_nodes: tuple[Any, Any] | None = None
    pending_function_index: Any | None = None
    retrieval_cache: Any | None = None
    query_engine_lock: Lock = field(default_factory=Lock)
