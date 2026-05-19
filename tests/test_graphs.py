# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import asyncio

from metis.engine.graphs.ask import AskGraph
from metis.engine.code_index import extract_function_nodes_from_document
from metis.engine.graphs.review import (
    _line_ranges_for_chunk,
    review_node_retrieve,
    review_node_build_prompt,
    review_node_llm,
    review_node_llm_async,
    review_node_parse,
)
from metis.engine.graphs.triage.llm import _build_user_prompt, triage_node_llm
from metis.plugins.python_plugin import PythonPlugin


class _Doc:
    def __init__(self, text):
        self.page_content = text


class DummyRetriever:
    def __init__(self, label):
        self._label = label

    def get_relevant_documents(self, q):
        return [_Doc(f"{self._label} context for: {q}")]


def test_ask_graph_returns_code_and_docs():
    g = AskGraph(llm_provider=object(), llama_query_model="test-model")
    req = {
        "question": "What is here?",
        "retriever_code": DummyRetriever("code"),
        "retriever_docs": DummyRetriever("docs"),
    }
    out = g.ask(req)  # type: ignore[arg-type]
    assert isinstance(out, dict)
    assert "code" in out and "docs" in out
    assert "code context" in out["code"] or "code" in out["code"].lower()
    assert "docs" in out["docs"].lower()


def test_review_nodes_pipeline_parses():
    # Initial minimal state
    state = {
        "file_path": "a/file.c",
        "snippet": "int main(){}",
        "retriever_code": DummyRetriever("code"),
        "retriever_docs": DummyRetriever("docs"),
        "context_prompt": "Use file: {file_path}",
    }

    # Step 1: retrieve context
    s1 = review_node_retrieve(state)
    assert "context" in s1

    # Step 2: build prompt
    language_prompts = {
        "security_review_file": "Do a security review [[REVIEW_SCHEMA_FIELDS]]",
        "security_review_checks": "Checks...",
        "validation_review": "Validate...",
    }
    s2 = review_node_build_prompt(
        s1,
        language_prompts=language_prompts,
        default_prompt_key="security_review_file",
        report_prompt="",
        custom_prompt_text=None,
        custom_guidance_precedence="",
        schema_prompt_section='- "issue": desc',
    )
    assert "system_prompt" in s2

    # Step 3: run LLM review (stub)
    class _DummyNode:
        def __init__(self, payload):
            self._payload = payload

        def invoke(self, _):
            return self._payload

    review_payload = {
        "reviews": [
            {
                "issue": "Issue A",
                "code_snippet": "int main(){}",
                "reasoning": "Because.",
                "mitigation": "Fix it.",
                "confidence": 0.5,
                "cwe": "CWE-79",
                "severity": "Medium",
            }
        ]
    }

    s3 = review_node_llm(
        s2,
        structured_node=_DummyNode(review_payload),
        fallback_node=None,
    )
    assert "parsed_reviews" in s3
    assert s3["parsed_reviews"]

    # Step 4: parse
    s4 = review_node_parse(s3)
    assert s4.get("parsed_reviews") and isinstance(s4["parsed_reviews"], list)


def test_review_node_retrieve_no_index_skips_retrievers():
    class _BoomRetriever:
        def get_relevant_documents(self, _query):
            raise AssertionError("retriever should not be called")

    state = {
        "file_path": "a/file.c",
        "snippet": "int main(){}",
        "retriever_code": _BoomRetriever(),
        "retriever_docs": _BoomRetriever(),
        "context_prompt": "ignored",
        "use_retrieval_context": False,
    }

    out = review_node_retrieve(state)

    assert out["context"] == ""


def test_review_node_retrieve_prepends_related_functions(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = (
        "def validate(value):\n"
        "    return value > 0\n"
        "\n"
        "def handle(value):\n"
        "    return validate(value)\n"
    )
    (repo / "app.py").write_text(source, encoding="utf-8")
    _nodes, function_index = extract_function_nodes_from_document(
        type("Doc", (), {"text": source, "id_": "app.py"})(),
        PythonPlugin({}),
    )
    state = {
        "file_path": str(repo / "app.py"),
        "relative_file": "app.py",
        "snippet": "def handle(value):\n    return validate(value)\n",
        "retriever_code": DummyRetriever("code"),
        "retriever_docs": DummyRetriever("docs"),
        "function_index": function_index,
        "function_index_codebase_path": str(repo),
        "context_prompt": "Use file: app.py",
    }

    out = review_node_retrieve(state)

    assert out["context"].startswith("RELATED_FUNCTIONS:")
    assert "app.py::validate" in out["context"]
    assert out["context"].find("RELATED_FUNCTIONS:") < out["context"].find(
        "VECTOR_SIMILAR_CODE:"
    )


def test_review_node_retrieve_uses_line_range_for_body_only_chunk(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = (
        "def validate(value):\n"
        "    return value > 0\n"
        "\n"
        "def handle(value):\n"
        "    return validate(value)\n"
    )
    (repo / "app.py").write_text(source, encoding="utf-8")
    _nodes, function_index = extract_function_nodes_from_document(
        type("Doc", (), {"text": source, "id_": "app.py"})(),
        PythonPlugin({}),
    )
    state = {
        "file_path": str(repo / "app.py"),
        "relative_file": "app.py",
        "snippet": "    return validate(value)\n",
        "snippet_line_ranges": [(5, 5)],
        "retriever_code": DummyRetriever("code"),
        "retriever_docs": DummyRetriever("docs"),
        "function_index": function_index,
        "function_index_codebase_path": str(repo),
        "context_prompt": "Use file: app.py",
    }

    out = review_node_retrieve(state)

    assert out["context"].startswith("RELATED_FUNCTIONS:")
    assert "app.py::validate" in out["context"]
    assert "app.py::handle" not in out["context"]


def test_line_ranges_for_chunk_advances_full_file_offsets():
    ranges, next_line = _line_ranges_for_chunk(
        "line 4\nline 5\n",
        explicit_line_ranges=None,
        next_line=4,
    )

    assert ranges == [(4, 5)]
    assert next_line == 6


def test_review_node_llm_omits_context_section_in_no_index_mode():
    captured = {}

    class _DummyNode:
        def invoke(self, payload):
            captured.update(payload)
            return {"reviews": []}

    state = {
        "file_path": "foo.py",
        "snippet": "print('hello')",
        "context": "should not appear",
        "mode": "file",
        "system_prompt": "prompt",
        "use_retrieval_context": False,
    }

    review_node_llm(
        state,
        structured_node=_DummyNode(),
        fallback_node=None,
    )

    assert "CONTEXT:" not in captured["body_text"]


def test_review_node_llm_async_uses_ainvoke():
    captured = {}

    class _AsyncNode:
        async def ainvoke(self, payload):
            captured.update(payload)
            return {"reviews": [{"issue": "Issue"}]}

    state = {
        "file_path": "foo.py",
        "snippet": "print('hello')",
        "context": "",
        "mode": "file",
        "system_prompt": "prompt",
        "use_retrieval_context": False,
    }

    out = asyncio.run(
        review_node_llm_async(
            state,
            structured_node=_AsyncNode(),
            fallback_node=None,
        )
    )

    assert captured["system_prompt"] == "prompt"
    assert out["parsed_reviews"][0]["issue"] == "Issue"


def test_triage_user_prompt_omits_rag_context_in_no_index_mode():
    prompt = _build_user_prompt(
        {
            "finding_rule_id": "R1",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_message": "msg",
            "finding_snippet": "code",
            "context": "should not appear",
            "use_retrieval_context": False,
        }
    )

    assert "RAG Context:" not in prompt


def test_triage_node_llm_omits_context_wording_in_no_index_mode():
    captured = {}

    class _Decision:
        status = "valid"
        reason = "ok"
        evidence = []
        resolution_chain = []
        unresolved_hops = []

    class _DecisionModel:
        def invoke(self, messages):
            captured["system"] = messages[0].content
            captured["user"] = messages[1].content
            return _Decision()

    triage_node_llm(
        {
            "finding_rule_id": "R1",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_message": "msg",
            "finding_snippet": "code",
            "context": "should not appear",
            "use_retrieval_context": False,
            "triage_system_prompt": "system",
            "triage_decision_prompt": (
                "Given the finding details, RAG context, and tool outputs, return a final triage decision.\n\n"
                "{triage_input}\n\nTool Outputs:\n{tool_outputs}\n"
            ),
            "evidence_pack": "tools",
        },
        decision_model=_DecisionModel(),
    )

    combined = captured["system"] + "\n" + captured["user"]
    assert "RAG Context:" not in combined
