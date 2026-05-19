# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import time

import pytest

from metis.engine.analysis.base import AnalyzerEvidence
from metis.engine.graphs.triage import TriageGraph
from metis.engine.graphs.triage.graph import _should_recollect_deep
from metis.engine.graphs.schemas import TriageDecisionModel
from metis.engine.analysis.c_family_helpers import extract_c_family_seed_symbols


class _App:
    def __init__(self, payload):
        self.payload = payload
        self.last_input = None

    def invoke(self, state):
        self.last_input = state
        return self.payload


def _build_graph():
    return TriageGraph(
        llm_provider=object(),
        llama_query_model="dummy",
        toolbox=object(),
        plugin_config={},
    )


class _ChatModel:
    def with_structured_output(self, _schema, method="function_calling"):
        return self

    def invoke(self, _messages):
        return TriageDecisionModel(
            status="valid",
            reason="covered by evidence",
            evidence=["a.c:1"],
            resolution_chain=["source -> sink"],
            unresolved_hops=[],
        )


class _NoChainChatModel:
    def with_structured_output(self, _schema, method="function_calling"):
        return self

    def invoke(self, _messages):
        class _Decision:
            status = "valid"
            reason = "covered by structured wrapper chain"
            evidence = ["a.c:1"]
            resolution_chain = []
            unresolved_hops = []

        return _Decision()


class _LLMProvider:
    def __init__(self, chat_model=None):
        self.chat_model = chat_model or _ChatModel()

    def get_chat_model(self, model, **kwargs):
        return self.chat_model


class _Toolbox:
    def sed(self, _path, _start, _end):
        return ""

    def grep(self, _pattern, _path):
        return ""

    def cat(self, _path):
        return ""

    def find_name(self, _name, max_results=20):
        return []

    def describe(self, name):
        return {"backend": f"test_{name}"}


class _HitToolbox(_Toolbox):
    def grep(self, pattern, path):
        if "foo" in pattern:
            return f"{path}:1:foo(x);\n"
        return ""

    def sed(self, _path, _start, _end):
        return "foo(x);\n"


class _WeakAnalyzer:
    def collect_evidence(self, _request):
        return AnalyzerEvidence(
            supported=False,
            language="c",
            summary="partial analyzer result",
            citations=[],
            resolution_chain=[],
            unresolved_hops=["wrapper unresolved"],
            sections=[],
        )


class _SupportedAnalyzer:
    def collect_evidence(self, _request):
        return AnalyzerEvidence(
            supported=True,
            language="c",
            summary="analyzed a.c",
            citations=["a.c:1"],
            resolution_chain=["source -> sink"],
            flow_chain=["source at a.c:1", "sink at a.c:2"],
            unresolved_hops=[],
            sections=[],
        )


def _build_real_graph(events, toolbox=None):
    return TriageGraph(
        llm_provider=_LLMProvider(),
        llama_query_model="dummy",
        toolbox=toolbox or _Toolbox(),
        plugin_config={},
    ), {
        "finding_message": "msg",
        "finding_file_path": "a.c",
        "finding_line": 1,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x);",
        "retriever_code": None,
        "retriever_docs": None,
        "debug_callback": events.append,
    }


def test_triage_request_can_select_deep_budget(monkeypatch):
    g = _build_graph()
    app = _App(
        {
            "decision_status": "inconclusive",
            "decision_reason": "missing evidence",
            "decision_evidence": [],
            "decision_resolution_chain": [],
            "decision_unresolved_hops": ["missing evidence"],
        }
    )
    monkeypatch.setattr(g, "_get_app", lambda: app)

    g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": None,
            "retriever_docs": None,
            "triage_evidence_budget": "deep",
        }
    )

    assert app.last_input["triage_evidence_budget"] == "deep"


def test_triage_graph_uses_structured_wrapper_chain_without_model_echo(monkeypatch):
    g = TriageGraph(
        llm_provider=_LLMProvider(_NoChainChatModel()),
        llama_query_model="dummy",
        toolbox=object(),
        plugin_config={},
    )
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "covered by structured wrapper chain",
                "decision_evidence": ["a.c:1"],
                "decision_resolution_chain": [],
                "decision_unresolved_hops": [],
                "symbol_resolution_chains": [
                    {
                        "symbol": "safe_alloc",
                        "resolution_chain": [
                            {
                                "symbol": "safe_alloc",
                                "file": "src/util/alloc.c",
                                "line": 12,
                            },
                            {
                                "symbol": "malloc",
                                "file": "src/util/alloc.c",
                                "line": 13,
                            },
                        ],
                    }
                ],
            }
        ),
    )

    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": None,
            "retriever_docs": None,
        }
    )

    assert out["status"] == "valid"
    assert out["resolution_chain"] == [
        "safe_alloc @ src/util/alloc.c:12 -> malloc @ src/util/alloc.c:13"
    ]


def test_extract_c_family_seed_symbols_ignores_file_path_tokens():
    out = extract_c_family_seed_symbols(
        "foo(x);",
        "missingIncludeSystem",
        "src/main.c",
    )
    assert "foo" in out
    assert "main" not in out
    assert "c" not in out


def test_triage_schema_allows_inconclusive_with_unresolved_hops():
    decision = TriageDecisionModel(
        status="inconclusive",
        reason="wrapper chain unresolved",
        evidence=[],
        resolution_chain=["reported finding -> PROJECT_STACK_ALLOC(...)"],
        unresolved_hops=["PROJECT_STACK_ALLOC macro expansion unknown"],
    )
    assert decision.status == "inconclusive"


def test_triage_schema_rejects_inconclusive_without_unresolved_hops():
    with pytest.raises(ValueError):
        TriageDecisionModel(
            status="inconclusive",
            reason="uncertain",
            evidence=[],
            resolution_chain=["x -> y"],
            unresolved_hops=[],
        )


def test_triage_graph_accepts_inconclusive(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "inconclusive",
                "decision_reason": "chain unresolved",
                "decision_evidence": [],
                "decision_resolution_chain": ["finding -> wrapper"],
                "decision_unresolved_hops": ["wrapper definition missing"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "inconclusive"


def test_triage_graph_propagates_retrieval_context_flag(monkeypatch):
    g = _build_graph()
    app = _App(
        {
            "decision_status": "valid",
            "decision_reason": "ok",
            "decision_evidence": ["a.c:1"],
            "decision_resolution_chain": ["x -> y"],
            "decision_unresolved_hops": [],
        }
    )
    monkeypatch.setattr(g, "_get_app", lambda: app)

    g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": None,
            "retriever_docs": None,
            "use_retrieval_context": False,
        }
    )

    assert app.last_input["use_retrieval_context"] is False


def test_triage_graph_fills_unresolved_hops_for_inconclusive(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "inconclusive",
                "decision_reason": "chain unresolved",
                "decision_evidence": [],
                "decision_resolution_chain": ["finding -> wrapper"],
                "decision_unresolved_hops": ["wrapper target unresolved"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "inconclusive"
    assert out["unresolved_hops"] == ["wrapper target unresolved"]


def test_triage_graph_keeps_inconclusive_when_uncertainty_exists(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "inconclusive",
                "decision_reason": "insufficient evidence; cannot determine.",
                "decision_evidence": ["a.c:10"],
                "decision_resolution_chain": ["finding -> symbol -> site"],
                "decision_unresolved_hops": ["macro expansion unresolved"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "inconclusive"


def test_triage_graph_allows_valid_with_non_critical_unresolved_hops(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "evidence chain is present with direct citations.",
                "decision_evidence": ["a.c:10", "a.c:30"],
                "decision_resolution_chain": ["source -> guard -> sink"],
                "decision_unresolved_hops": ["FLOW_SINK_CLASS_UNRESOLVED:helper_call"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "valid"


def test_triage_graph_keeps_inconclusive_with_critical_unresolved_hops(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "evidence chain is present with direct citations.",
                "decision_evidence": ["a.c:10", "a.c:30"],
                "decision_resolution_chain": ["source -> guard -> sink"],
                "decision_unresolved_hops": ["FLOW_SINK_NOT_FOUND"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "inconclusive"


def test_triage_graph_allows_valid_when_macro_unresolved_hop_is_resolved(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "evidence chain is present with direct citations.",
                "decision_evidence": [
                    "a.c:10",
                    "a.c:30",
                    "MACRO_RESOLUTION PROJECT_STACK_ALLOC -> alloca",
                ],
                "decision_resolution_chain": [
                    "source -> guard -> sink",
                    "MACRO_RESOLUTION PROJECT_STACK_ALLOC -> alloca",
                ],
                "decision_unresolved_hops": [
                    "MACRO_DEFINITION_UNRESOLVED:PROJECT_STACK_ALLOC"
                ],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "valid"


def test_triage_graph_does_not_force_inconclusive_for_assumption_findings(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "concrete citations and full chain show issue.",
                "decision_evidence": ["a.c:75", "a.c:102"],
                "decision_resolution_chain": [
                    "reported helper -> run wrapper -> kernel call"
                ],
                "decision_unresolved_hops": [],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "Use of PROJECT_ASSUME instead of runtime checks allows undefined behavior",
            "finding_file_path": "a.c",
            "finding_line": 75,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "valid"


def test_triage_graph_does_not_upgrade_invalid_to_valid(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "invalid",
                "decision_reason": "false positive due to dominating assignment",
                "decision_evidence": ["a.c:10", "a.c:20"],
                "decision_resolution_chain": ["source -> assignment -> sink"],
                "decision_unresolved_hops": [],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "invalid"


def test_triage_graph_applies_evidence_gate_override(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "looks valid",
                "decision_evidence": ["a.c:10"],
                "decision_resolution_chain": ["source -> sink"],
                "decision_unresolved_hops": [],
                "evidence_gate_missing": ["FILE_CONTEXT_MISSING"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "inconclusive"
    assert "OVERRIDE_EVIDENCE_GATE_INCOMPLETE" in out["reason"]


def test_triage_graph_applies_status_specific_obligation_gate(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "invalid",
                "decision_reason": "strong contradiction in observed flow",
                "decision_evidence": ["a.c:10", "a.c:20"],
                "decision_resolution_chain": ["source -> guard -> sink"],
                "decision_unresolved_hops": [],
                "evidence_obligations": [
                    "local_context",
                    "symbol_definition",
                    "constraint_or_guard",
                ],
                "obligation_coverage": {
                    "local_context": 1,
                    "symbol_definition": 1,
                    "constraint_or_guard": 0,
                },
                "obligation_missing": ["constraint_or_guard"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "inconclusive"
    assert "OVERRIDE_OBLIGATION_COVERAGE" in out["reason"]


def test_triage_graph_relaxes_invalid_constraint_gate_when_core_evidence_present(
    monkeypatch,
):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "invalid",
                "decision_reason": "concrete local contradiction in observed flow",
                "decision_evidence": ["a.c:10", "a.c:20"],
                "decision_resolution_chain": ["source -> check -> sink"],
                "decision_unresolved_hops": [],
                "evidence_obligations": [
                    "local_context",
                    "symbol_definition",
                    "use_site",
                    "constraint_or_guard",
                ],
                "obligation_coverage": {
                    "local_context": 1,
                    "symbol_definition": 2,
                    "use_site": 1,
                    "constraint_or_guard": 0,
                },
                "obligation_missing": ["constraint_or_guard"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "invalid"
    assert "OVERRIDE_OBLIGATION_COVERAGE" not in out["reason"]


def test_triage_graph_recollects_once_with_deep_budget_when_obligations_missing():
    events = []
    graph, request = _build_real_graph(events)
    request["triage_analyzer"] = _WeakAnalyzer()

    out = graph.triage(request)

    gate_events = [event for event in events if event.get("event") == "evidence_gate"]
    assert [event["budget"] for event in gate_events] == ["standard", "deep"]
    assert out["status"] == "inconclusive"


def test_triage_graph_recollects_when_only_use_site_grep_is_found():
    events = []
    graph, request = _build_real_graph(events, toolbox=_HitToolbox())
    request["triage_analyzer"] = _WeakAnalyzer()

    out = graph.triage(request)

    gate_events = [event for event in events if event.get("event") == "evidence_gate"]
    assert [event["budget"] for event in gate_events] == ["standard", "deep"]
    assert any(
        "OBLIGATION_MISSING:symbol_definition" in event["missing"]
        for event in gate_events
    )
    assert out["status"] == "inconclusive"


def test_triage_graph_skips_deep_recollect_when_obligations_are_covered():
    events = []
    graph, request = _build_real_graph(events, toolbox=_HitToolbox())
    request["triage_analyzer"] = _SupportedAnalyzer()

    out = graph.triage(request)

    gate_events = [event for event in events if event.get("event") == "evidence_gate"]
    assert [event["budget"] for event in gate_events] == ["standard"]
    assert out["status"] == "valid"


def test_triage_graph_deep_recollect_respects_retry_timeout():
    route = _should_recollect_deep(
        {
            "evidence_gate_missing": ["OBLIGATION_MISSING:use_site"],
            "triage_evidence_budget": "standard",
            "triage_evidence_retry_count": 0,
            "triage_evidence_started_at": time.monotonic() - 30,
            "triage_evidence_retry_timeout_seconds": 1.0,
        }
    )

    assert route == "triage"
