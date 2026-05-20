# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json

import pytest

from metis.tui.commands import TuiCommandRequest
from metis.tui.runner import TuiDomainRunner
from metis.engine.research import ResearchRunResult


class _IndexingDomain:
    def __init__(self):
        self.calls = []

    def count_index_items(self):
        self.calls.append("count")
        return 2

    def index_prepare_nodes_iter(self, progress_callback=None):
        self.calls.append("prepare")
        if progress_callback is not None:
            progress_callback(
                {
                    "event": "index.item.discovered",
                    "message": "Discovered a.py",
                    "current_document_path": "a.py",
                }
            )
        yield object()
        yield object()

    def index_finalize_embeddings(self):
        self.calls.append("finalize")


class _ReviewDomain:
    def __init__(self):
        self.calls = []

    def get_code_files(self, options=None):
        self.calls.append(
            (
                "get_code_files",
                None if options is None else options.use_retrieval_context,
            )
        )
        return ["a.py"]

    def review_code(
        self, get_code_files_func=None, options=None, progress_callback=None
    ):
        self.calls.append(
            ("review_code", None if options is None else options.use_retrieval_context)
        )
        if progress_callback is not None:
            progress_callback(
                {
                    "event": "review.file.started",
                    "message": "Reviewing a.py",
                    "current_file": "a.py",
                    "completed_count": 0,
                    "total_files": 1,
                }
            )
        yield {
            "file": "a.py",
            "reviews": [
                {
                    "issue": "bug",
                    "line": 1,
                    "severity": "Low",
                    "cwe": "CWE-20",
                    "reasoning": "reason",
                    "mitigation": "fix",
                }
            ],
        }

    def review_file(self, file_path, options=None):
        self.calls.append(
            (
                "review_file",
                file_path,
                None if options is None else options.use_retrieval_context,
            )
        )
        return {"file": file_path, "reviews": []}

    def review_patch(self, patch_file, options=None):
        self.calls.append(
            (
                "review_patch",
                patch_file,
                None if options is None else options.use_retrieval_context,
            )
        )
        return {"reviews": []}


class _SkippingReviewDomain(_ReviewDomain):
    def review_code(
        self, get_code_files_func=None, options=None, progress_callback=None
    ):
        self.calls.append(
            ("review_code", None if options is None else options.use_retrieval_context)
        )
        if progress_callback is not None:
            progress_callback(
                {
                    "event": "review.file.skipped",
                    "message": "Review skipped a.py",
                    "current_file": "a.py",
                }
            )
        yield None


class _FakeEngine:
    def __init__(self):
        self.indexing = _IndexingDomain()
        self.review = _ReviewDomain()
        self.research = _ResearchDomain()
        self.llm_provider = _FakeProvider()
        self.triage_calls = []

    def triage_sarif_file(self, input_path, output_path=None, **kwargs):
        self.triage_calls.append((input_path, output_path, kwargs["options"]))
        kwargs["progress_callback"]({"event": "start", "total": 1, "index": 1})
        kwargs["debug_callback"]("debug message")
        with open(input_path, encoding="utf-8") as src:
            payload = json.load(src)
        checkpoint_callback = kwargs.get("checkpoint_callback")
        if checkpoint_callback is not None:
            checkpoint_callback(payload, 1, 1)
        kwargs["progress_callback"]({"event": "done", "total": 1, "index": 1})
        with open(output_path, "w", encoding="utf-8") as dst:
            json.dump(payload, dst)
        return output_path


class _ResearchDomain:
    def __init__(self):
        self.calls = []

    def run(self, root, *, options):
        self.calls.append((root, options))
        for path in (
            options.hypotheses_path,
            options.evidence_ledger_path,
            options.sarif_path,
            options.research_report_path,
        ):
            if path:
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("{}\n")
        return ResearchRunResult(
            hypotheses_path=options.hypotheses_path,
            evidence_ledger_path=options.evidence_ledger_path,
            sarif_path=options.sarif_path,
            research_report_path=options.research_report_path,
        )


class _FakeReportModel:
    def __init__(self, responses=None):
        self.messages = None
        self.message_history = []
        self.responses = list(
            responses
            or [
                "## Batch Chain Notes\n\n### Candidate 1\nScore: 8.1",
                "# Security Report\n\n## Attack Chain 1\nScore: 8.1",
            ]
        )

    def invoke(self, messages):
        self.messages = messages
        self.message_history.append(messages)
        return type("Message", (), {"content": self.responses.pop(0)})()


class _FakeProvider:
    def __init__(self, responses=None):
        self.model = _FakeReportModel(responses)
        self.kwargs = []

    def get_chat_model(self, **kwargs):
        self.kwargs.append(kwargs)
        return self.model


def test_runner_indexes_with_service_progress_and_logs(tmp_path):
    events = []
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-index",
        artifacts_base_dir=tmp_path / "tui",
        event_callback=events.append,
    )

    runner.execute(TuiCommandRequest("index", raw="/index"))

    assert engine.indexing.calls == ["count", "prepare", "finalize"]
    assert any(event.type == "index.item.discovered" for event in events)
    assert any(event.type == "index.prepare.summary" for event in events)
    manifest = json.loads(runner.artifacts.paths.manifest.read_text(encoding="utf-8"))
    assert manifest["commands"][0]["status"] == "succeeded"


def test_runner_review_code_writes_default_review_sarif_and_triage_uses_it(tmp_path):
    events = []
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-review",
        artifacts_base_dir=tmp_path / "tui",
        event_callback=events.append,
    )

    runner.execute(TuiCommandRequest("review_code", raw="/review_code"))
    runner.execute(TuiCommandRequest("triage", raw="/triage"))

    assert runner.artifacts.paths.review_sarif.is_file()
    assert runner.artifacts.paths.triage_sarif.is_file()
    assert engine.review.calls == [("get_code_files", None), ("review_code", None)]
    assert engine.triage_calls[0][0] == str(runner.artifacts.paths.review_sarif)
    assert engine.triage_calls[0][1] == str(runner.artifacts.paths.triage_sarif)
    assert any(event.type == "review.result.recorded" for event in events)


def test_runner_research_uses_runtime_defaults(tmp_path):
    events = []
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-research",
        artifacts_base_dir=tmp_path / "tui",
        runtime_config={
            "research_hunters": "ssrf",
            "research_budget": "quick",
            "research_emit_killed": True,
            "research_emit_unresolved": True,
            "research_proof_artifacts": True,
            "research_evidence_policy": "triage_evidence",
        },
        event_callback=events.append,
    )

    runner.execute(
        TuiCommandRequest(
            "research",
            raw="/research",
        )
    )

    root, options = engine.research.calls[0]
    assert root == str(tmp_path)
    assert options.hunters == ("ssrf",)
    assert options.persist is True
    assert options.research_budget == "quick"
    assert options.emit_killed is True
    assert options.emit_unresolved is True
    assert options.proof_artifacts is True
    assert options.evidence_policy == "triage_evidence"
    assert runner.artifacts.paths.research_report.is_file()
    assert runner.artifacts.paths.research_sarif.is_file()
    assert runner.artifacts.paths.research_hypotheses.is_file()
    assert runner.artifacts.paths.research_evidence.is_file()
    assert runner.artifacts.paths.security_report.is_file()
    assert any(event.type == "research.artifacts.written" for event in events)
    assert any(event.type == "security_report.written" for event in events)


def test_runner_research_respects_explicit_hunters(tmp_path):
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-research",
        artifacts_base_dir=tmp_path / "tui",
        runtime_config={
            "research_hunters": "ssrf",
            "research_budget": "quick",
            "research_emit_killed": True,
            "research_emit_unresolved": False,
            "research_proof_artifacts": True,
            "research_evidence_policy": "triage_evidence",
        },
    )

    runner.execute(
        TuiCommandRequest(
            "research",
            args=(
                "--hunters",
                "authz_outlier,ssrf",
                "--research-budget",
                "tiny",
                "--no-emit-killed",
                "--emit-unresolved",
                "--no-proof-artifacts",
                "--evidence-policy",
                "strict",
                "--rebuild",
            ),
            raw=(
                "/research --hunters authz_outlier,ssrf "
                "--research-budget tiny --no-emit-killed --emit-unresolved "
                "--no-proof-artifacts --evidence-policy strict --rebuild"
            ),
        )
    )

    root, options = engine.research.calls[0]
    assert root == str(tmp_path)
    assert options.hunters == ("authz_outlier", "ssrf")
    assert options.persist is True
    assert options.rebuild is True
    assert options.research_budget == "tiny"
    assert options.emit_killed is False
    assert options.emit_unresolved is True
    assert options.proof_artifacts is False
    assert options.evidence_policy == "strict"


def test_runner_review_code_uses_research_profile_runtime(tmp_path):
    events = []
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-review-research",
        artifacts_base_dir=tmp_path / "tui",
        runtime_config={
            "review_profile": "research",
            "research_hunters": "ssrf",
            "research_budget": "quick",
        },
        event_callback=events.append,
    )

    runner.execute(TuiCommandRequest("review_code", raw="/review_code"))

    assert engine.review.calls == []
    root, options = engine.research.calls[0]
    assert root == str(tmp_path)
    assert options.hunters == ("ssrf",)
    assert options.research_budget == "quick"
    assert runner.artifacts.paths.research_report.is_file()
    assert any(event.type == "research.started" for event in events)
    assert any(event.type == "security_report.written" for event in events)


def test_runner_review_code_does_not_duplicate_service_skipped_event(tmp_path):
    events = []
    engine = _FakeEngine()
    engine.review = _SkippingReviewDomain()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-skip",
        artifacts_base_dir=tmp_path / "tui",
        event_callback=events.append,
    )

    runner.execute(TuiCommandRequest("review_code", raw="/review_code"))

    event_types = [event.type for event in events]
    assert event_types.count("review.file.skipped") == 1
    assert "review.result.skipped" in event_types


def test_runner_triage_maps_progress_callbacks_to_events(tmp_path):
    events = []
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-triage",
        artifacts_base_dir=tmp_path / "tui",
        event_callback=events.append,
    )
    runner.artifacts.paths.review_sarif.write_text(
        '{"version":"2.1.0","runs":[]}',
        encoding="utf-8",
    )

    runner.execute(TuiCommandRequest("triage", raw="/triage"))

    assert {event.type for event in events} >= {
        "triage.finding.started",
        "triage.finding.finished",
        "log.message",
        "sarif.triage.checkpoint",
        "sarif.triage.written",
    }


def test_runner_security_report_reads_triage_sarif_and_writes_markdown(tmp_path):
    events = []
    engine = _FakeEngine()
    (tmp_path / "app.py").write_text(
        "\n".join(f"line {index}" for index in range(1, 25)) + "\n",
        encoding="utf-8",
    )
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-report",
        artifacts_base_dir=tmp_path / "tui",
        event_callback=events.append,
    )
    runner.artifacts.paths.triage_sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "CWE-89",
                                        "help": {"text": "SQL injection"},
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "CWE-89",
                                "level": "error",
                                "message": {"text": "SQL injection in login"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 12},
                                        }
                                    }
                                ],
                                "properties": {"triage_status": "true_positive"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner.execute(TuiCommandRequest("security_report", raw="/security_report"))

    assert runner.artifacts.paths.security_report.read_text(
        encoding="utf-8"
    ).startswith("# Security Report")
    assert len(engine.llm_provider.model.message_history) == 2
    batch_prompt = engine.llm_provider.model.message_history[0][1][1]
    final_prompt = engine.llm_provider.model.message_history[1][1][1]
    assert "Analyze attack-chain candidate batch 1/1" in batch_prompt
    assert "Candidate: CHAIN-" in batch_prompt
    assert "SQL Injection" in batch_prompt
    assert "Affected file snippets:" in batch_prompt
    assert "line 12" in batch_prompt
    assert "Synthesize the final report from 1 SARIF finding" in final_prompt
    assert "1 prebuilt attack-chain candidate" in final_prompt
    assert "## Batch Chain Notes" in final_prompt
    prompt = batch_prompt
    assert "SQL injection in login" in prompt
    assert "app.py:12" in prompt
    assert [kwargs["max_tokens"] for kwargs in engine.llm_provider.kwargs] == [
        65536,
        65536,
    ]
    findings = json.loads(
        runner.artifacts.paths.security_report_findings.read_text(encoding="utf-8")
    )
    candidates = json.loads(
        runner.artifacts.paths.security_report_candidates.read_text(encoding="utf-8")
    )
    context = json.loads(
        runner.artifacts.paths.security_report_context.read_text(encoding="utf-8")
    )
    assert findings[0]["finding_id"] == "F-0001"
    assert candidates[0]["chain_id"].startswith("CHAIN-")
    assert runner.artifacts.paths.security_report_batch_notes.is_file()
    assert context["model_context_policy"].startswith("compact candidate summaries")
    assert context["affected_file_snippets"][0]["path"] == "app.py"
    assert {event.type for event in events} >= {
        "security_report.started",
        "security_report.findings.extracted",
        "security_report.candidates.built",
        "security_report.batches.prepared",
        "security_report.snippets.attached",
        "security_report.llm.started",
        "security_report.batch.started",
        "security_report.batch.finished",
        "security_report.synthesis.started",
        "security_report.artifacts.written",
        "security_report.written",
    }


def test_runner_security_report_retries_empty_model_and_writes_fallback(tmp_path):
    events = []
    engine = _FakeEngine()
    engine.llm_provider = _FakeProvider(["", ""])
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-report-empty",
        artifacts_base_dir=tmp_path / "tui",
        event_callback=events.append,
    )
    runner.artifacts.paths.triage_sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"rules": [{"id": "CWE-89"}]}},
                        "results": [
                            {
                                "ruleId": "CWE-89",
                                "level": "error",
                                "message": {"text": "SQL injection in login"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner.execute(TuiCommandRequest("security_report", raw="/security_report"))

    report = runner.artifacts.paths.security_report.read_text(encoding="utf-8")
    assert report.startswith("# Security Report")
    assert "deterministic fallback report" in report
    assert "SQL injection in login" in report
    assert len(engine.llm_provider.kwargs) == 2
    assert [event.type for event in events].count("log.message") == 2
    assert any(event.type == "security_report.written" for event in events)


def test_runner_security_report_batches_all_findings_before_final_synthesis(tmp_path):
    events = []
    engine = _FakeEngine()
    batch_responses = [
        "## Batch 1 Notes\n\n### Candidate\nfirst-window",
        "## Batch 2 Notes\n\n### Candidate\nsecond-window",
        "## Batch 3 Notes\n\n### Candidate\nthird-window",
        "## Batch 4 Notes\n\n### Candidate\nfourth-window",
        "# Security Report\n\n### Chain 1\nScore: 8.0",
    ]
    engine.llm_provider = _FakeProvider(batch_responses)
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-report-large",
        artifacts_base_dir=tmp_path / "tui",
        event_callback=events.append,
    )
    results = [
        {
            "ruleId": f"CWE-1{index:03d}",
            "level": "warning",
            "message": {"text": f"SQL injection finding {index}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"pkg{index}/app.py"},
                        "region": {"startLine": index + 1},
                    }
                }
            ],
        }
        for index in range(85)
    ]
    runner.artifacts.paths.triage_sarif.write_text(
        json.dumps({"version": "2.1.0", "runs": [{"results": results}]}),
        encoding="utf-8",
    )

    runner.execute(TuiCommandRequest("security_report", raw="/security_report"))

    assert len(engine.llm_provider.model.message_history) == 5
    batch_prompts = [
        messages[1][1] for messages in engine.llm_provider.model.message_history[:4]
    ]
    joined_batches = "\n".join(batch_prompts)
    for index in range(85):
        assert f"SQL injection finding {index}" in joined_batches
    final_prompt = engine.llm_provider.model.message_history[4][1][1]
    assert "Batch 1 Notes" in final_prompt
    assert "Batch 2 Notes" in final_prompt
    assert "Batch 3 Notes" in final_prompt
    assert [event.type for event in events].count("security_report.batch.started") == 4


def test_runner_security_report_adds_cross_batch_chain_notes_to_final_prompt(tmp_path):
    events = []
    engine = _FakeEngine()
    engine.llm_provider = _FakeProvider(
        [
            "## Batch Notes\n\nStandalone candidates analyzed.",
            "## Cross-Batch Notes\n\nXCHAIN-001 produces RCE.",
            "# Security Report\n\n### Cross-batch RCE\nScore: 9.5",
        ]
    )
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-report-cross",
        artifacts_base_dir=tmp_path / "tui",
        event_callback=events.append,
    )
    runner.artifacts.paths.triage_sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "CWE-434",
                                "level": "error",
                                "message": {
                                    "text": "Unauthenticated upload can write arbitrary PHP file with attacker-controlled path"
                                },
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": "src/upload/api.py"
                                            },
                                            "region": {"startLine": 20},
                                        }
                                    }
                                ],
                            },
                            {
                                "ruleId": "CWE-78",
                                "level": "error",
                                "message": {
                                    "text": "Command execution loads plugin file from writable plugin directory"
                                },
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": "src/runtime/load.py"
                                            },
                                            "region": {"startLine": 90},
                                        }
                                    }
                                ],
                            },
                        ]
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner.execute(TuiCommandRequest("security_report", raw="/security_report"))

    assert len(engine.llm_provider.model.message_history) == 3
    cross_prompt = engine.llm_provider.model.message_history[1][1][1]
    final_prompt = engine.llm_provider.model.message_history[2][1][1]
    assert "Analyze 1 cross-batch attack-chain candidate" in cross_prompt
    assert "XCHAIN-001" in cross_prompt
    assert "Cross-Batch Notes" in final_prompt
    context = json.loads(
        runner.artifacts.paths.security_report_context.read_text(encoding="utf-8")
    )
    cross_candidates = json.loads(
        runner.artifacts.paths.security_report_cross_batch_candidates.read_text(
            encoding="utf-8"
        )
    )
    assert context["cross_batch_candidates"] == 1
    assert cross_candidates[0]["chain_id"] == "XCHAIN-001"
    assert {event.type for event in events} >= {
        "security_report.cross_batch.built",
        "security_report.cross_batch.started",
        "security_report.cross_batch.finished",
    }


def test_runner_failure_marks_command_and_manifest_failed(tmp_path):
    events = []
    engine = _FakeEngine()

    def _raise(*_args, **_kwargs):
        raise RuntimeError("boom")

    engine.review.review_code = _raise
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-fail",
        artifacts_base_dir=tmp_path / "tui",
        event_callback=events.append,
    )

    with pytest.raises(RuntimeError, match="boom"):
        runner.execute(TuiCommandRequest("review_code", raw="/review_code"))

    manifest = json.loads(runner.artifacts.paths.manifest.read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["commands"][0]["status"] == "failed"
    assert any(event.type == "command.failed" for event in events)
    assert any(event.type == "run.failed" for event in events)


def test_runner_review_file_and_patch_use_domain_services_not_cli_handlers(tmp_path):
    review_file = tmp_path / "a.py"
    review_file.write_text("print('hi')", encoding="utf-8")
    patch_file = tmp_path / "change.diff"
    patch_file.write_text("diff --git a/a.py b/a.py", encoding="utf-8")
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-paths",
        artifacts_base_dir=tmp_path / "tui",
    )

    runner.execute(
        TuiCommandRequest("review_file", (str(review_file),), "/review_file a.py")
    )
    runner.execute(
        TuiCommandRequest(
            "review_patch", (str(patch_file),), "/review_patch change.diff"
        )
    )

    assert ("review_file", str(review_file), None) in engine.review.calls
    assert ("review_patch", str(patch_file), None) in engine.review.calls


def test_runner_review_commands_preserve_explicit_retrieval_opt_out(tmp_path):
    review_file = tmp_path / "a.py"
    review_file.write_text("print('hi')", encoding="utf-8")
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-no-retrieval",
        artifacts_base_dir=tmp_path / "tui",
    )

    runner.execute(
        TuiCommandRequest(
            "review_file",
            (str(review_file),),
            "/review_file --no-retrieval-context a.py",
            use_retrieval_context=False,
        )
    )

    assert ("review_file", str(review_file), False) in engine.review.calls


def test_runner_init_writes_root_context(tmp_path):
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-init",
        artifacts_base_dir=tmp_path / "tui",
    )

    runner.execute(TuiCommandRequest("init", raw="/init"))

    context = tmp_path / "CONTEXT.md"
    assert context.is_file()
    assert "Metis Project Context" in context.read_text(encoding="utf-8")


def test_runner_init_replaces_context_symlink_without_overwriting_target(tmp_path):
    outside = tmp_path.parent / "outside-context-target.md"
    outside.write_text("do not overwrite", encoding="utf-8")
    (tmp_path / "CONTEXT.md").symlink_to(outside)
    engine = _FakeEngine()
    runner = TuiDomainRunner(
        engine,
        codebase_path=tmp_path,
        run_id="run-init-symlink",
        artifacts_base_dir=tmp_path / "tui",
    )

    runner.execute(TuiCommandRequest("init", raw="/init"))

    context = tmp_path / "CONTEXT.md"
    assert not context.is_symlink()
    assert "Metis Project Context" in context.read_text(encoding="utf-8")
    assert outside.read_text(encoding="utf-8") == "do not overwrite"
