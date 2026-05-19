# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import time
from concurrent.futures import ThreadPoolExecutor

from metis.engine.graphs.triage.evidence_tools import _gather_symbol_definition_hits
from metis.engine.graphs.triage.evidence_tools import _invoke_with_deadline


def _slice_numbered_lines(lines_by_number, start, end):
    return "\n".join(lines_by_number.get(line, "") for line in range(start, end + 1))


class _WrapperToolbox:
    def __init__(self):
        self.grep_calls = []
        self.sed_calls = []

    def grep(self, pattern, path):
        self.grep_calls.append((pattern, path))
        if "safe_alloc" in pattern:
            return "src/util/alloc.c:12:void *safe_alloc(size_t n) {\n"
        if "malloc" in pattern:
            return "src/util/alloc.c:13:    return malloc(n);\n"
        return ""

    def sed(self, path, start, end):
        self.sed_calls.append((path, start, end))
        return _slice_numbered_lines(
            {
                12: "void *safe_alloc(size_t n) {",
                13: "    return malloc(n);",
                14: "}",
            },
            start,
            end,
        )

    def describe(self, name):
        return {"backend": f"test_{name}"}


class _UseSiteBeforeDefinitionToolbox(_WrapperToolbox):
    def grep(self, pattern, path):
        self.grep_calls.append((pattern, path))
        if "safe_alloc" in pattern:
            return "\n".join(
                [
                    "src/util/alloc.c:5:ptr = safe_alloc(n);",
                    "src/util/alloc.c:12:void *safe_alloc(size_t n) {",
                ]
            )
        if "malloc" in pattern:
            return "src/util/alloc.c:13:    return malloc(n);\n"
        return ""

    def sed(self, path, start, end):
        self.sed_calls.append((path, start, end))
        return _slice_numbered_lines(
            {
                5: "ptr = safe_alloc(n);",
                12: "void *safe_alloc(size_t n) {",
                13: "    return malloc(n);",
                14: "}",
            },
            start,
            end,
        )


class _DeadlineToolbox(_WrapperToolbox):
    def grep(self, pattern, path):
        raise AssertionError("grep should not run after deadline")

    def sed(self, path, start, end):
        raise AssertionError("sed should not run after deadline")


class _SlowToolbox(_WrapperToolbox):
    def grep(self, pattern, path):
        time.sleep(0.05)
        return "src/util/alloc.c:12:void *safe_alloc(size_t n) {\n"


class _SecondHopUseSiteBeforeDefinitionToolbox(_WrapperToolbox):
    def grep(self, pattern, path):
        self.grep_calls.append((pattern, path))
        if "safe_alloc" in pattern:
            return "src/util/alloc.c:12:void *safe_alloc(size_t n) {\n"
        if "inner_alloc" in pattern:
            return "\n".join(
                [
                    "src/util/alloc.c:5:ptr = inner_alloc(n);",
                    "src/util/alloc.c:20:void *inner_alloc(size_t n) {",
                ]
            )
        if "malloc" in pattern:
            return "src/util/alloc.c:21:    return malloc(n);\n"
        return ""

    def sed(self, path, start, end):
        self.sed_calls.append((path, start, end))
        return _slice_numbered_lines(
            {
                5: "ptr = inner_alloc(n);",
                12: "void *safe_alloc(size_t n) {",
                13: "    return inner_alloc(n);",
                14: "}",
                20: "void *inner_alloc(size_t n) {",
                21: "    return malloc(n);",
                22: "}",
            },
            start,
            end,
        )


class _NearSecondHopUseSiteBeforeDefinitionToolbox(_WrapperToolbox):
    def grep(self, pattern, path):
        self.grep_calls.append((pattern, path))
        if "safe_alloc" in pattern:
            return "src/util/alloc.c:12:void *safe_alloc(size_t n) {\n"
        if "inner_alloc" in pattern:
            return "\n".join(
                [
                    "src/util/alloc.c:18:ptr = inner_alloc(n);",
                    "src/util/alloc.c:20:void *inner_alloc(size_t n) {",
                ]
            )
        if "malloc" in pattern:
            return "src/util/alloc.c:21:    return malloc(n);\n"
        return ""

    def sed(self, path, start, end):
        self.sed_calls.append((path, start, end))
        return _slice_numbered_lines(
            {
                12: "void *safe_alloc(size_t n) {",
                13: "    return inner_alloc(n);",
                14: "}",
                18: "ptr = inner_alloc(n);",
                20: "void *inner_alloc(size_t n) {",
                21: "    return malloc(n);",
                22: "}",
            },
            start,
            end,
        )


def test_symbol_definition_gathering_records_safe_alloc_wrapper_chain():
    state = {"triage_codebase_path": "."}
    sections = []
    toolbox = _WrapperToolbox()

    followup_hits, definition_hints, unresolved = _gather_symbol_definition_hits(
        state,
        sections,
        toolbox=toolbox,
        symbols=["safe_alloc"],
        file_path="src/util/alloc.c",
        max_followup_hits=8,
        max_sections=12,
        max_symbol_hops=3,
    )

    evidence = "\n\n".join(sections)
    assert ("src/util/alloc.c", 12) in followup_hits
    assert ("src/util/alloc.c", 13) in followup_hits
    assert unresolved == []
    assert "SYMBOL_RESOLUTION_CHAIN safe_alloc" in evidence
    assert "safe_alloc @ src/util/alloc.c:12" in evidence
    assert "malloc @ <terminal>" in evidence
    assert any("safe_alloc" in hint and "malloc" in hint for hint in definition_hints)
    assert state["symbol_resolution_chains"] == [
        {
            "symbol": "safe_alloc",
            "resolution_chain": [
                {"symbol": "safe_alloc", "file": "src/util/alloc.c", "line": 12},
                {"symbol": "malloc", "file": "<terminal>", "line": None},
            ],
        }
    ]


def test_wrapper_resolution_skips_use_site_before_definition():
    state = {"triage_codebase_path": "."}
    sections = []
    toolbox = _UseSiteBeforeDefinitionToolbox()

    _gather_symbol_definition_hits(
        state,
        sections,
        toolbox=toolbox,
        symbols=["safe_alloc"],
        file_path="src/util/alloc.c",
        max_followup_hits=8,
        max_sections=12,
        max_symbol_hops=3,
    )

    evidence = "\n\n".join(sections)
    assert "SYMBOL_RESOLUTION_CHAIN safe_alloc" in evidence
    assert "safe_alloc @ src/util/alloc.c:12" in evidence
    assert "safe_alloc @ src/util/alloc.c:5" not in evidence
    assert "malloc @ <terminal>" in evidence


def test_symbol_definition_gathering_stops_after_deadline():
    state = {
        "triage_codebase_path": ".",
        "triage_evidence_deadline_at": 1.0,
    }
    sections = []

    followup_hits, definition_hints, unresolved = _gather_symbol_definition_hits(
        state,
        sections,
        toolbox=_DeadlineToolbox(),
        symbols=["safe_alloc"],
        file_path="src/util/alloc.c",
        max_followup_hits=8,
        max_sections=12,
        max_symbol_hops=3,
    )

    assert followup_hits == []
    assert definition_hints == set()
    assert unresolved == ["safe_alloc"]


def test_symbol_definition_gathering_times_out_active_tool_call():
    executor = ThreadPoolExecutor(max_workers=1)
    state = {
        "triage_codebase_path": ".",
        "triage_evidence_deadline_at": time.monotonic() + 0.01,
        "triage_tool_executor": executor,
    }
    sections = []
    started = time.monotonic()

    try:
        followup_hits, definition_hints, unresolved = _gather_symbol_definition_hits(
            state,
            sections,
            toolbox=_SlowToolbox(),
            symbols=["safe_alloc"],
            file_path="src/util/alloc.c",
            max_followup_hits=8,
            max_sections=12,
            max_symbol_hops=3,
        )
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    assert time.monotonic() - started < 0.04
    assert followup_hits == []
    assert definition_hints == set()
    assert unresolved == ["safe_alloc"]


def test_invoke_with_deadline_runs_inline_without_executor():
    state = {
        "triage_evidence_deadline_at": time.monotonic() + 1.0,
    }

    assert _invoke_with_deadline(state, lambda: "ok") == "ok"


def test_invoke_with_deadline_runs_inline_inside_same_executor():
    executor = ThreadPoolExecutor(max_workers=1)
    state = {
        "triage_evidence_deadline_at": time.monotonic() + 1.0,
        "triage_tool_executor": executor,
    }
    try:
        future = executor.submit(_invoke_with_deadline, state, lambda: "ok")
        assert future.result(timeout=1.0) == "ok"
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def test_second_hop_wrapper_resolution_skips_use_site_before_definition():
    state = {"triage_codebase_path": "."}
    sections = []

    _followup_hits, definition_hints, _unresolved = _gather_symbol_definition_hits(
        state,
        sections,
        toolbox=_SecondHopUseSiteBeforeDefinitionToolbox(),
        symbols=["safe_alloc"],
        file_path="src/util/alloc.c",
        max_followup_hits=12,
        max_sections=20,
        max_symbol_hops=3,
    )

    evidence = "\n\n".join(sections)
    assert "safe_alloc @ src/util/alloc.c:12" in evidence
    assert "inner_alloc @ src/util/alloc.c:20" in evidence
    assert "inner_alloc @ src/util/alloc.c:5" not in evidence
    assert "malloc @ <terminal>" in evidence
    assert "inner_alloc @ src/util/alloc.c:5" not in definition_hints


def test_second_hop_wrapper_resolution_records_actual_definition_line_in_near_context():
    state = {"triage_codebase_path": "."}
    sections = []

    _followup_hits, definition_hints, _unresolved = _gather_symbol_definition_hits(
        state,
        sections,
        toolbox=_NearSecondHopUseSiteBeforeDefinitionToolbox(),
        symbols=["safe_alloc"],
        file_path="src/util/alloc.c",
        max_followup_hits=12,
        max_sections=20,
        max_symbol_hops=3,
    )

    evidence = "\n\n".join(sections)
    assert "inner_alloc @ src/util/alloc.c:20" in evidence
    assert "inner_alloc @ src/util/alloc.c:18" not in evidence
    assert "inner_alloc @ src/util/alloc.c:18" not in definition_hints
