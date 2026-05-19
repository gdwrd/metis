# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import time

import pytest

import metis.engine.graphs.review as review_mod
from metis.engine.graphs.review import (
    review_node_agentic_llm,
    review_node_exec_tool,
)
from metis.engine.options import ReviewAgenticOptions


class _SequenceNode:
    def __init__(self, responses):
        self.responses = list(responses)
        self.payloads = []

    def invoke(self, payload):
        self.payloads.append(payload)
        if self.responses:
            return self.responses.pop(0)
        return {"reviews": []}


class _RaisingNode:
    def invoke(self, _payload):
        raise RuntimeError("provider unavailable")


def _base_state(tmp_path):
    return {
        "file_path": str(tmp_path / "app.py"),
        "snippet": "def handle(value):\n    return validate(value)\n",
        "context": "",
        "mode": "file",
        "system_prompt": "review",
        "function_index_codebase_path": str(tmp_path),
        "function_index": None,
        "agentic_options": ReviewAgenticOptions(
            max_iterations=3,
            max_tool_calls=2,
            tool_timeout_seconds=1,
            max_extra_tokens=8000,
        ),
        "tool_results": [],
        "tool_trace": [],
        "agentic_iteration": 0,
        "agentic_tool_calls_used": 0,
        "agentic_done": False,
        "agentic_force_final": False,
    }


def test_agentic_review_respects_tool_call_budget_for_repeated_requests(tmp_path):
    node = _SequenceNode(
        [
            {"tool_calls": [{"name": "get_function_body", "args": {"name": "a"}}]},
            {"tool_calls": [{"name": "get_function_body", "args": {"name": "b"}}]},
            {"tool_calls": [{"name": "get_function_body", "args": {"name": "c"}}]},
        ]
    )
    state = _base_state(tmp_path)

    while not state.get("agentic_done"):
        state = review_node_agentic_llm(state, fallback_node=node)
        if state.get("agentic_done"):
            break
        state = review_node_exec_tool(state)

    assert state["agentic_tool_calls_used"] == 2
    assert len(state["tool_trace"]) == 2
    assert state["agentic_done"] is True


def test_agentic_review_counts_token_budget_skipped_tool_calls(tmp_path):
    node = _SequenceNode(
        [
            {"tool_calls": [{"name": "grep_repo", "args": {"pattern": "needle"}}]},
            {"tool_calls": [{"name": "grep_repo", "args": {"pattern": "needle"}}]},
        ]
    )
    (tmp_path / "app.py").write_text("needle = 'secret'\n", encoding="utf-8")
    state = _base_state(tmp_path)
    state["agentic_options"] = ReviewAgenticOptions(
        max_iterations=3,
        max_tool_calls=1,
        tool_timeout_seconds=1,
        max_extra_tokens=1,
    )

    while not state.get("agentic_done"):
        state = review_node_agentic_llm(state, fallback_node=node)
        if state.get("agentic_done"):
            break
        state = review_node_exec_tool(state)

    assert state["agentic_tool_calls_used"] == 1
    assert state["tool_trace"][0]["name"] == "grep_repo"
    assert state["tool_trace"][0]["status"] == "skipped"
    assert state["tool_trace"][0]["reason"] == "token_budget"
    assert "tool_wallclock_ms" in state["tool_trace"][0]
    assert state["agentic_done"] is True


def test_agentic_review_forces_final_when_token_budget_exhausted(tmp_path):
    node = _SequenceNode(
        [
            {"tool_calls": [{"name": "grep_repo", "args": {"pattern": "needle"}}]},
            {"tool_calls": [{"name": "grep_repo", "args": {"pattern": "needle"}}]},
        ]
    )
    (tmp_path / "app.py").write_text("needle = 'secret'\n", encoding="utf-8")
    state = _base_state(tmp_path)
    state["agentic_options"] = ReviewAgenticOptions(
        max_iterations=3,
        max_tool_calls=3,
        tool_timeout_seconds=1,
        max_extra_tokens=1,
    )

    state = review_node_agentic_llm(state, fallback_node=node)
    state = review_node_exec_tool(state)
    state = review_node_agentic_llm(state, fallback_node=node)

    assert state["agentic_tool_calls_used"] == 1
    assert state["agentic_force_final"] is True
    assert state["agentic_done"] is True
    assert len(node.payloads) == 2


def test_agentic_review_keeps_over_budget_tool_errors_out_of_prompt(tmp_path):
    huge_tool_name = "invalid_" + ("x" * 1000)
    state = _base_state(tmp_path)
    state["agentic_options"] = ReviewAgenticOptions(
        max_iterations=3,
        max_tool_calls=1,
        tool_timeout_seconds=1,
        max_extra_tokens=1,
    )
    state["tool_calls"] = [{"name": huge_tool_name, "args": {}}]

    state = review_node_exec_tool(state)
    node = _SequenceNode([{"reviews": []}])
    state = review_node_agentic_llm(state, fallback_node=node)

    assert state["agentic_tool_calls_used"] == 1
    assert state["tool_results"] == []
    assert state["tool_trace"][0]["status"] == "skipped"
    assert state["tool_trace"][0]["reason"] == "token_budget"
    assert state["tool_trace"][0]["name"].endswith("...[truncated]")
    assert len(state["tool_trace"][0]["name"]) < len(huge_tool_name)
    assert huge_tool_name not in node.payloads[-1]["body_text"]


def test_agentic_review_adds_tool_results_to_next_prompt(tmp_path):
    node = _SequenceNode(
        [
            {"tool_calls": [{"name": "grep_repo", "args": {"pattern": "handle"}}]},
            {
                "reviews": [
                    {
                        "issue": "Issue A",
                        "code_snippet": "def handle(value):",
                        "reasoning": "Because.",
                        "mitigation": "Fix it.",
                        "confidence": 0.8,
                        "cwe": "CWE-79",
                        "severity": "MEDIUM",
                    }
                ]
            },
        ]
    )
    (tmp_path / "app.py").write_text("def handle(value):\n    pass\n", encoding="utf-8")
    state = _base_state(tmp_path)

    state = review_node_agentic_llm(state, fallback_node=node)
    state = review_node_exec_tool(state)
    state = review_node_agentic_llm(state, fallback_node=node)

    assert "TOOL_RESULTS:" in node.payloads[-1]["body_text"]
    assert state["agentic_done"] is True
    assert state["parsed_reviews"][0]["issue"] == "Issue A"


def test_agentic_review_propagates_llm_invocation_failure(tmp_path):
    state = _base_state(tmp_path)

    with pytest.raises(RuntimeError, match="provider unavailable"):
        review_node_agentic_llm(state, fallback_node=_RaisingNode())


def test_agentic_review_executes_tools_in_parallel(monkeypatch, tmp_path):
    state = _base_state(tmp_path)
    state["tool_calls"] = [
        {"name": "grep_repo", "args": {"pattern": "a"}},
        {"name": "grep_repo", "args": {"pattern": "b"}},
    ]

    monkeypatch.setattr(review_mod, "build_toolbox", lambda **_kwargs: object())

    def _slow_tool(_toolbox, name, _args):
        time.sleep(0.1)
        return f"result {name}"

    monkeypatch.setattr(review_mod, "_run_review_tool", _slow_tool)

    started = time.monotonic()
    state = review_node_exec_tool(state)
    elapsed = time.monotonic() - started

    assert elapsed < 0.18
    assert state["agentic_tool_calls_used"] == 2
    assert [item["status"] for item in state["tool_trace"]] == ["ok", "ok"]
    assert all("tool_wallclock_ms" in item for item in state["tool_trace"])
    assert state["total_tool_wallclock_ms"] >= 100


def test_agentic_review_wallclock_budget_forces_final_without_tool_call(
    monkeypatch, tmp_path
):
    state = _base_state(tmp_path)
    state["agentic_started_at"] = time.monotonic() - 2.0
    state["agentic_options"] = ReviewAgenticOptions(
        max_iterations=3,
        max_tool_calls=2,
        tool_timeout_seconds=1,
        max_extra_tokens=8000,
        wallclock_seconds=0.01,
    )
    state["tool_calls"] = [{"name": "grep_repo", "args": {"pattern": "needle"}}]
    monkeypatch.setattr(
        review_mod,
        "_run_review_tool",
        lambda *_args, **_kwargs: pytest.fail("tool should not run"),
    )

    state = review_node_exec_tool(state)

    assert state["agentic_force_final"] is True
    assert state["tool_calls"] == []
    assert state["tool_trace"][-1]["reason"] == "wallclock_budget"
