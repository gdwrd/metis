# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from functools import partial
import time
from typing import cast

from langgraph.cache.memory import InMemoryCache
from langgraph.graph import END, StateGraph

from ..schemas import TriageDecisionModel
from .adjudication import (
    adjudicate_status_deterministic,
    compose_final_reason,
)
from .budget import DEEP, STANDARD, coerce_evidence_budget
from .nodes import (
    triage_node_collect_evidence,
    triage_node_llm,
    triage_node_llm_async,
    triage_node_retrieve,
)
from ..types import TriageRequest, TriageState


def _should_recollect_deep(state: TriageState) -> str:
    missing = list(state.get("evidence_gate_missing") or [])
    retried = int(state.get("triage_evidence_retry_count", 0) or 0)
    budget = str(state.get("triage_evidence_budget", STANDARD.name) or STANDARD.name)
    started_at = float(state.get("triage_evidence_started_at", 0.0) or 0.0)
    timeout_seconds = float(
        state.get("triage_evidence_retry_timeout_seconds", 20.0) or 20.0
    )
    deadline = float(state.get("triage_evidence_deadline_at", 0.0) or 0.0)
    timed_out = bool(
        (deadline and time.monotonic() > deadline)
        or (started_at and (time.monotonic() - started_at) > timeout_seconds)
    )
    if missing and retried <= 0 and budget != DEEP.name and not timed_out:
        return "collect_deep_evidence"
    return "triage"


def _triage_node_collect_deep_evidence(state: TriageState, *, toolbox) -> TriageState:
    deep_state = cast(TriageState, state.copy())
    deep_state["triage_evidence_budget"] = DEEP.name
    deep_state["triage_evidence_retry_count"] = (
        int(state.get("triage_evidence_retry_count", 0) or 0) + 1
    )
    return triage_node_collect_evidence(deep_state, toolbox=toolbox)


class TriageGraph:
    def __init__(
        self,
        llm_provider,
        llama_query_model,
        toolbox,
        plugin_config=None,
        chat_model_kwargs=None,
    ):
        self.llm_provider = llm_provider
        self.llama_query_model = llama_query_model
        self.toolbox = toolbox
        general_prompts = (plugin_config or {}).get("general_prompts", {})
        self.triage_system_prompt = (
            general_prompts.get("triage_system_prompt")
            or "You triage static analysis findings. "
            "Only decide whether the finding is valid or invalid based on static code evidence. "
            "Treat the reported line as potentially inaccurate. "
            "Prefer inspecting nearby code first with sed/cat in the reported file."
        )
        self.triage_decision_prompt = (
            general_prompts.get("triage_decision_prompt")
            or "Given the finding details, RAG context, and tool outputs, return a final triage decision.\n\n"
            "The reported line number might be off; rely on nearby code regions and related symbols.\n\n"
            "{triage_input}\n\nTool Outputs:\n{tool_outputs}\n"
        )
        self._app = None
        self._async_app = None
        self._decision_model = None
        self.chat_model_kwargs = chat_model_kwargs or {}

    def _ensure_models(self):
        if self._decision_model is not None:
            return
        chat_model = self.llm_provider.get_chat_model(
            model=self.llama_query_model, **self.chat_model_kwargs
        )
        self._decision_model = chat_model.with_structured_output(
            TriageDecisionModel, method="function_calling"
        )

    def _get_app(self, *, async_mode: bool = False):
        if async_mode and self._async_app is not None:
            return self._async_app
        if not async_mode and self._app is not None:
            return self._app
        self._ensure_models()
        graph = StateGraph(TriageState)
        graph.add_node("retrieve", triage_node_retrieve)
        graph.add_node(
            "collect_evidence",
            partial(triage_node_collect_evidence, toolbox=self.toolbox),
        )
        graph.add_node(
            "collect_deep_evidence",
            partial(_triage_node_collect_deep_evidence, toolbox=self.toolbox),
        )
        graph.add_node(
            "triage",
            partial(
                triage_node_llm_async if async_mode else triage_node_llm,
                decision_model=self._decision_model,
            ),
        )
        graph.set_entry_point("retrieve")
        graph.add_edge("retrieve", "collect_evidence")
        graph.add_conditional_edges(
            "collect_evidence",
            _should_recollect_deep,
            {
                "collect_deep_evidence": "collect_deep_evidence",
                "triage": "triage",
            },
        )
        graph.add_edge("collect_deep_evidence", "triage")
        graph.add_edge("triage", END)
        compiled = graph.compile(cache=InMemoryCache())
        if async_mode:
            self._async_app = compiled
        else:
            self._app = compiled
        return compiled

    def triage(self, request: TriageRequest) -> dict:
        out = self._get_app().invoke(self._build_initial_state(request))
        return self._finalize_output(out)

    async def atriage(self, request: TriageRequest) -> dict:
        out = await self._get_app(async_mode=True).ainvoke(
            self._build_initial_state(request)
        )
        return self._finalize_output(out)

    def _finalize_output(self, out: TriageState) -> dict:
        structured_resolution_chain = _format_structured_resolution_chains(
            list(out.get("symbol_resolution_chains") or [])
        )
        raw_resolution_chain = list(out.get("decision_resolution_chain") or [])
        if not raw_resolution_chain and structured_resolution_chain:
            raw_resolution_chain = structured_resolution_chain
        try:
            validated = TriageDecisionModel(
                status=out.get("decision_status", ""),
                reason=out.get("decision_reason", ""),
                evidence=list(out.get("decision_evidence") or []),
                resolution_chain=raw_resolution_chain,
                unresolved_hops=list(out.get("decision_unresolved_hops") or []),
            )
        except Exception as exc:
            raise ValueError(f"Invalid triage decision from model: {exc}") from exc

        model_status = validated.status
        reason = validated.reason
        evidence = list(validated.evidence)
        resolution_chain = _merge_structured_resolution_chains(
            list(validated.resolution_chain),
            structured_resolution_chain,
        )
        unresolved_hops = list(validated.unresolved_hops)
        evidence_gate_missing = list(out.get("evidence_gate_missing") or [])
        obligations = list(out.get("evidence_obligations") or [])
        obligation_coverage = dict(out.get("obligation_coverage") or {})
        status, reason_codes = adjudicate_status_deterministic(
            model_status=model_status,
            evidence=evidence,
            resolution_chain=resolution_chain,
            unresolved_hops=unresolved_hops,
            reason=reason,
            obligations=obligations,
            obligation_coverage=obligation_coverage,
        )
        if evidence_gate_missing and status != "inconclusive":
            status = "inconclusive"
            reason_codes.append("OVERRIDE_EVIDENCE_GATE_INCOMPLETE")
        for tag in evidence_gate_missing:
            code = f"EVIDENCE_GATE_MISSING:{tag}"
            if code not in reason_codes:
                reason_codes.append(code)
        if status == "inconclusive" and not unresolved_hops:
            unresolved_hops = [
                "deterministic adjudicator marked evidence as insufficiently stable"
            ]
        reason = compose_final_reason(status, model_status, reason, reason_codes)
        return {
            "status": status,
            "reason": reason,
            "evidence": evidence,
            "resolution_chain": resolution_chain,
            "unresolved_hops": unresolved_hops,
        }

    def _build_initial_state(self, request: TriageRequest) -> TriageState:
        budget = coerce_evidence_budget(request.get("triage_evidence_budget"))
        started_at = time.monotonic()
        timeout_seconds = float(
            request.get("triage_evidence_retry_timeout_seconds", 20.0) or 20.0
        )
        tool_executor = request.get("triage_tool_executor")
        deadline_at = started_at + timeout_seconds if tool_executor is not None else 0.0
        return {
            "finding_message": request["finding_message"],
            "finding_file_path": request["finding_file_path"],
            "finding_line": request["finding_line"],
            "finding_rule_id": request["finding_rule_id"],
            "finding_snippet": request["finding_snippet"],
            "finding_source_tool": request.get("finding_source_tool", ""),
            "finding_is_metis": bool(request.get("finding_is_metis", False)),
            "finding_explanation": request.get("finding_explanation", ""),
            "retriever_code": request["retriever_code"],
            "retriever_docs": request["retriever_docs"],
            "triage_analyzer": request.get("triage_analyzer"),
            "triage_codebase_path": request.get("triage_codebase_path", "."),
            "debug_callback": request.get("debug_callback"),
            "use_retrieval_context": bool(request.get("use_retrieval_context", True)),
            "triage_system_prompt": self.triage_system_prompt,
            "triage_decision_prompt": self.triage_decision_prompt,
            "triage_evidence_budget": budget.name,
            "triage_evidence_retry_count": 0,
            "triage_evidence_started_at": started_at,
            "triage_evidence_retry_timeout_seconds": timeout_seconds,
            "triage_evidence_deadline_at": deadline_at,
            "triage_tool_executor": tool_executor,
            "shared_retrieval_context": request.get("shared_retrieval_context", ""),
            "shared_retrieval_query": request.get("shared_retrieval_query", ""),
        }


def _merge_structured_resolution_chains(
    model_chain: list[str],
    structured_chain_texts: list[str],
) -> list[str]:
    merged = list(model_chain)
    seen = {item for item in merged if item}
    for text in structured_chain_texts:
        if text in seen:
            continue
        seen.add(text)
        merged.append(text)
    return merged


def _format_structured_resolution_chains(structured_chains: list[dict]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for entry in structured_chains:
        chain = entry.get("resolution_chain") if isinstance(entry, dict) else None
        if not isinstance(chain, list) or not chain:
            continue
        parts: list[str] = []
        for hop in chain:
            if not isinstance(hop, dict):
                continue
            symbol = str(hop.get("symbol") or "").strip()
            path = str(hop.get("file") or "").strip()
            line = hop.get("line")
            if not symbol:
                continue
            if path and line is not None:
                parts.append(f"{symbol} @ {path}:{line}")
            elif path:
                parts.append(f"{symbol} @ {path}")
            else:
                parts.append(symbol)
        if not parts:
            continue
        text = " -> ".join(parts)
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out
