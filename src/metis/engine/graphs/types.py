# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Dict, Optional, TypedDict, Required, NotRequired


class ReviewRequest(TypedDict):
    # Required fields
    file_path: Required[str]
    snippet: Required[str]
    context_prompt: Required[str]
    language_prompts: Required[Dict[str, str]]

    # Optional fields
    retriever_code: NotRequired[Any | None]
    retriever_docs: NotRequired[Any | None]
    function_index: NotRequired[Any | None]
    function_index_codebase_path: NotRequired[str]
    snippet_start_line: NotRequired[int]
    snippet_line_ranges: NotRequired[list[tuple[int, int]]]
    default_prompt_key: NotRequired[str]
    relative_file: NotRequired[Optional[str]]
    # Explicit mode: 'file' or 'patch'
    mode: NotRequired[str]
    # Optional original file contents for patch mode
    original_file: NotRequired[Optional[str]]
    use_retrieval_context: NotRequired[bool]
    review_mode: NotRequired[str]
    agentic_options: NotRequired[Any]
    debug_callback: NotRequired[Any]


class AskRequest(TypedDict):
    # Required fields
    question: Required[str]
    retriever_code: Required[Any]
    retriever_docs: Required[Any]


class ReviewState(TypedDict, total=False):
    # Input
    file_path: str
    snippet: str
    retriever_code: Any
    retriever_docs: Any
    function_index: Any
    function_index_codebase_path: str
    snippet_line_ranges: list[tuple[int, int]]
    context_prompt: str
    relative_file: Optional[str]
    mode: str
    original_file: Optional[str]
    use_retrieval_context: bool
    review_mode: str
    agentic_options: Any
    debug_callback: Any
    # Derived
    context: str
    system_prompt: str
    parsed_reviews: list[dict]
    tool_calls: list[dict]
    tool_results: list[str]
    tool_trace: list[dict]
    total_tool_wallclock_ms: int
    agentic_started_at: float
    agentic_iteration: int
    agentic_tool_calls_used: int
    agentic_done: bool
    agentic_force_final: bool


class AskState(TypedDict, total=False):
    # Input
    question: str
    retriever_code: Any
    retriever_docs: Any
    # Derived
    context: str
    code: str
    docs: str
    answer: str


class TriageRequest(TypedDict):
    finding_message: Required[str]
    finding_file_path: Required[str]
    finding_line: Required[int]
    finding_rule_id: Required[str]
    finding_snippet: Required[str]
    finding_source_tool: NotRequired[str]
    finding_is_metis: NotRequired[bool]
    finding_explanation: NotRequired[str]
    retriever_code: NotRequired[Any | None]
    retriever_docs: NotRequired[Any | None]
    debug_callback: NotRequired[Any]
    triage_analyzer: NotRequired[Any]
    triage_codebase_path: NotRequired[str]
    use_retrieval_context: NotRequired[bool]
    triage_evidence_budget: NotRequired[str]
    triage_evidence_retry_timeout_seconds: NotRequired[float]
    triage_tool_executor: NotRequired[Any]
    shared_retrieval_context: NotRequired[str]
    shared_retrieval_query: NotRequired[str]


class TriageState(TypedDict, total=False):
    finding_message: str
    finding_file_path: str
    finding_line: int
    finding_rule_id: str
    finding_snippet: str
    finding_source_tool: str
    finding_is_metis: bool
    finding_explanation: str
    retriever_code: Any
    retriever_docs: Any
    debug_callback: Any
    triage_analyzer: Any
    triage_codebase_path: str
    use_retrieval_context: bool
    triage_system_prompt: str
    triage_decision_prompt: str
    triage_evidence_budget: str
    triage_evidence_retry_count: int
    triage_evidence_started_at: float
    triage_evidence_retry_timeout_seconds: float
    triage_evidence_deadline_at: float
    triage_tool_executor: Any
    shared_retrieval_context: str
    shared_retrieval_query: str
    symbol_resolution_chains: list[dict[str, Any]]
    context: str
    evidence_pack: str
    tool_transcript: str
    decision_status: str
    decision_reason: str
    decision_evidence: list[str]
    decision_resolution_chain: list[str]
    decision_unresolved_hops: list[str]
    evidence_gate_missing: list[str]
    evidence_obligations: list[str]
    obligation_coverage: dict[str, int]
