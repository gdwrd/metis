# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from metis.cli import entry
from metis.cli import commands
from metis.cli import command_registry
from metis.bench import BenchmarkRegressionError


@pytest.mark.parametrize(
    "cmd", ["review_file", "review_code", "review_patch", "triage"]
)
def test_prepare_command_runtime_allows_opt_in_no_index_for_supported_command(cmd):
    args = SimpleNamespace(ignore_index=False, quiet=True, codebase_path="src/metis")

    runtime = entry._prepare_command_runtime(  # type: ignore[attr-defined]
        cmd=cmd,
        cmd_args=["src/a.c", "--ignore-index"],
        args=args,
    )

    assert runtime is not None
    assert runtime.command_args == ["src/a.c"]
    assert runtime.use_retrieval_context is False


@pytest.mark.parametrize("cmd", ["ask", "update"])
def test_prepare_command_runtime_rejects_disallowed_inline_ignore_index(
    monkeypatch, cmd
):
    args = SimpleNamespace(ignore_index=False, quiet=True, codebase_path="src/metis")
    captured = []
    monkeypatch.setattr(
        command_registry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(message),
    )

    runtime = entry._prepare_command_runtime(  # type: ignore[attr-defined]
        cmd=cmd,
        cmd_args=["why", "--ignore-index"],
        args=args,
    )

    assert runtime is None
    assert any(
        "--ignore-index can only be used" in str(message) for message in captured
    )


def test_execute_command_rejects_triage_flag_for_ask_before_index_gating(monkeypatch):
    args = SimpleNamespace(
        quiet=True,
        triage=True,
        output_file=None,
        ignore_index=True,
        non_interactive=True,
        codebase_path="src/metis",
    )
    captured = []
    monkeypatch.setattr(
        command_registry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    result = entry.execute_command(
        SimpleNamespace(),
        "ask",
        ["hi"],
        args,
    )

    assert result is None
    assert any("--triage can only be used" in message for message in captured)
    assert not any("Index missing" in message for message in captured)


def test_execute_command_allows_interactive_triage_command_with_global_triage_flag(
    monkeypatch,
):
    args = SimpleNamespace(
        quiet=True,
        triage=True,
        output_file=None,
        ignore_index=False,
        non_interactive=False,
        codebase_path="src/metis",
        include_triaged=False,
    )
    calls = []
    engine = SimpleNamespace(
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "triage",
            "summary": {},
            "cumulative": {},
        },
    )
    monkeypatch.setattr(entry, "determine_output_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "print_usage_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        command_registry.CommandSpec,
        "invoke",
        lambda self, engine, cmd_args, args, runtime: calls.append(
            (runtime.command, cmd_args, runtime.use_retrieval_context)
        ),
    )

    result = entry.execute_command(engine, "triage", ["findings.sarif"], args)

    assert result is None
    assert calls == [("triage", ["findings.sarif"], True)]


def test_execute_command_allows_interactive_ask_with_global_triage_flag(monkeypatch):
    args = SimpleNamespace(
        quiet=True,
        triage=True,
        output_file=None,
        ignore_index=False,
        non_interactive=False,
        codebase_path="src/metis",
    )
    calls = []
    engine = SimpleNamespace(
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "ask",
            "summary": {},
            "cumulative": {},
        },
    )

    monkeypatch.setattr(entry, "determine_output_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "print_usage_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        command_registry.CommandSpec,
        "invoke",
        lambda self, engine, cmd_args, args, runtime: calls.append(
            (runtime.command, cmd_args, runtime.use_retrieval_context)
        ),
    )

    result = entry.execute_command(engine, "ask", ["hi"], args)

    assert result is None
    assert calls == [("ask", ["hi"], True)]


def test_execute_command_passes_bench_command_args(monkeypatch, tmp_path):
    args = SimpleNamespace(
        quiet=True,
        triage=False,
        output_file=[str(tmp_path / "bench.json")],
        ignore_index=False,
        non_interactive=True,
        codebase_path="src/metis",
    )
    captured = []
    engine = SimpleNamespace(
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "bench",
            "summary": {},
            "cumulative": {},
        },
    )

    monkeypatch.setattr(entry, "print_usage_summary", lambda *_args, **_kwargs: None)

    def fake_run_benchmark(_engine, options):
        captured.append(options.quick)
        return {
            "mode": "review",
            "case_count": 1,
            "totals": {"tp": 1, "fp": 0, "fn": 0, "recall": 1.0, "precision": 1.0},
        }

    monkeypatch.setattr("metis.cli.commands.run_benchmark", fake_run_benchmark)

    result = entry.execute_command(engine, "bench", ["--quick"], args)

    assert result is None
    assert captured == [True]


@pytest.mark.parametrize("cmd", ["ask", "update"])
def test_execute_command_rejects_ignore_index_flag_before_index_gating(
    monkeypatch, cmd
):
    args = SimpleNamespace(
        quiet=True,
        triage=False,
        output_file=None,
        ignore_index=True,
        codebase_path="src/metis",
    )
    captured = []
    monkeypatch.setattr(
        command_registry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    result = entry.execute_command(
        SimpleNamespace(),
        cmd,
        ["hi"],
        args,
    )

    assert result is None
    assert any("--ignore-index can only be used" in message for message in captured)
    assert not any("Index missing" in message for message in captured)


@pytest.mark.parametrize("cmd", ["ask", "update"])
def test_execute_command_rejects_inline_ignore_index_flag_before_index_gating(
    monkeypatch, cmd
):
    args = SimpleNamespace(
        quiet=True,
        triage=False,
        output_file=None,
        ignore_index=False,
        codebase_path="src/metis",
    )
    captured = []
    monkeypatch.setattr(
        command_registry,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    result = entry.execute_command(
        SimpleNamespace(),
        cmd,
        ["hi", "--ignore-index"],
        args,
    )

    assert result is None
    assert any("--ignore-index can only be used" in message for message in captured)
    assert not any("Index missing" in message for message in captured)


def test_run_non_interactive_keeps_quiet_without_verbose():
    args = SimpleNamespace(
        command="triage data.sarif",
        verbose=False,
        quiet=True,
        log_level="DEBUG",
    )

    exit_code, farewell = entry.run_non_interactive(SimpleNamespace(), args)

    assert exit_code == 1
    assert farewell is None
    assert args.quiet is True


def test_run_non_interactive_shows_inline_command_help(monkeypatch):
    args = SimpleNamespace(
        command="research --help",
        verbose=False,
        quiet=True,
        log_level="DEBUG",
    )
    captured = []
    monkeypatch.setattr(
        entry,
        "execute_command",
        lambda _engine, cmd, cmd_args, command_args: captured.append(
            (cmd, cmd_args, command_args.quiet)
        ),
    )

    exit_code, farewell = entry.run_non_interactive(SimpleNamespace(), args)

    assert exit_code == 0
    assert farewell is None
    assert captured == [("research", ["--help"], False)]
    assert args.quiet is False


def test_execute_review_code_accepts_inline_research_profile(monkeypatch, tmp_path):
    captured = []

    class _ReviewDomain:
        def get_code_files(self, options=None):  # pragma: no cover - must not run
            raise AssertionError("normal review should not run")

    class _ResearchService:
        def run(self, root, *, options):
            from metis.engine.research import ResearchRunResult

            captured.append(
                (
                    root,
                    options.hunters,
                    options.research_budget,
                    options.proof_artifacts,
                    options.evidence_policy,
                )
            )
            return ResearchRunResult()

    engine = SimpleNamespace(
        codebase_path=str(tmp_path),
        review=_ReviewDomain(),
        research=_ResearchService(),
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "review_code",
            "summary": {},
            "cumulative": {},
        },
    )
    args = SimpleNamespace(
        quiet=True,
        verbose=False,
        triage=False,
        output_file=None,
        ignore_index=False,
        non_interactive=True,
        review_profile="normal",
        hunters="authz_outlier",
        research_budget="standard",
        proof_artifacts=False,
        evidence_policy="triage_evidence",
        _runtime_config={},
    )
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands, "pretty_print_reviews", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(commands, "save_output", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "print_usage_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **kwargs: func(
            *func_args,
            **{key: value for key, value in kwargs.items() if key != "quiet"},
        ),
    )

    entry.execute_command(
        engine,
        "review_code",
        [
            "--review-profile",
            "research",
            "--hunters",
            "ssrf",
            "--research-budget",
            "quick",
            "--proof-artifacts",
            "--evidence-policy",
            "triage_evidence",
        ],
        args,
    )

    assert captured == [
        (str(tmp_path), ("ssrf",), "quick", True, "triage_evidence")
    ]


@pytest.mark.parametrize(
    "argv", [["metis", "--version"], ["metis", "tui", "--version"]]
)
def test_main_version_paths_do_not_build_engine(monkeypatch, capsys, argv):
    monkeypatch.setattr("sys.argv", argv)
    calls = []
    monkeypatch.setattr(entry, "build_engine", lambda *_args: calls.append("build"))
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: {})

    entry.main()

    captured = capsys.readouterr()
    assert "Metis" in captured.out
    assert calls == []


def test_main_tui_passes_runtime_to_run_tui(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "tui",
            "--hunters",
            "authz_outlier,ssrf",
            "--research-budget",
            "tiny",
            "--proof-artifacts",
            "--evidence-policy",
            "strict",
        ],
    )
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    runtime = {
        "research_hunters": "ssrf",
        "research_budget": "quick",
    }
    engine = SimpleNamespace(has_usage=lambda: False, close=lambda: None)
    captured = {}

    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: runtime)
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (engine, object()))

    def _run_tui(run_engine, args, *, startup_state=None, runtime=None):
        captured["engine"] = run_engine
        captured["runtime"] = runtime
        captured["startup_state"] = startup_state
        captured["codebase_path"] = args.codebase_path

    monkeypatch.setattr("metis.tui.app.run_tui", _run_tui)

    entry.main()

    assert captured["engine"] is engine
    assert captured["runtime"]["research_hunters"] == "authz_outlier,ssrf"
    assert captured["runtime"]["research_budget"] == "tiny"
    assert captured["runtime"]["research_proof_artifacts"] is True
    assert captured["runtime"]["research_evidence_policy"] == "strict"
    assert captured["startup_state"].chat_enabled is True
    assert captured["codebase_path"] == "."


def test_main_rewrites_top_level_bench_command(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "bench.json"
    monkeypatch.setattr(
        "sys.argv",
        ["metis", "bench", "--quick", "--output-file", str(output)],
    )
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: {})
    engine = SimpleNamespace(
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "bench",
            "summary": {},
            "cumulative": {},
        },
    )
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (engine, object()))
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)
    captured = []

    def fake_run_benchmark(_engine, options):
        captured.append(options.quick)
        return {
            "mode": "review",
            "case_count": 1,
            "totals": {"tp": 1, "fp": 0, "fn": 0, "recall": 1.0, "precision": 1.0},
        }

    monkeypatch.setattr("metis.cli.commands.run_benchmark", fake_run_benchmark)

    entry.main()

    assert captured == [True]
    assert output.exists()


def test_main_rewrites_top_level_research_command(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "research.json"
    monkeypatch.setattr(
        "sys.argv",
        ["metis", "research", "model", "--output-file", str(output)],
    )
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: {})

    class _SecurityModelService:
        def load_or_build(self, *_args, **_kwargs):
            from metis.engine.research import ProjectSecurityModel

            return ProjectSecurityModel(project_root_hash="hash")

    engine = SimpleNamespace(
        codebase_path=str(tmp_path),
        research=SimpleNamespace(security_model=_SecurityModelService()),
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "research",
            "summary": {},
            "cumulative": {},
        },
    )
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (engine, object()))
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)
    monkeypatch.setattr(entry, "print_usage_summary", lambda *_args, **_kwargs: None)

    entry.main()

    assert output.exists()


def test_main_rewrites_top_level_variants_command(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    patch_file = tmp_path / "fix.patch"
    patch_file.write_text("", encoding="utf-8")
    output = tmp_path / "variants.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "variants",
            "--from-fix",
            str(patch_file),
            "--output-file",
            str(output),
        ],
    )
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: {})
    captured = []

    class _ResearchService:
        def run_variants(self, *_args, **kwargs):
            from metis.engine.research import ResearchRunResult

            captured.append(kwargs["from_fix"])
            return ResearchRunResult()

    engine = SimpleNamespace(
        codebase_path=str(tmp_path),
        research=_ResearchService(),
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "variants",
            "summary": {},
            "cumulative": {},
        },
    )
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (engine, object()))
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)
    monkeypatch.setattr(entry, "print_usage_summary", lambda *_args, **_kwargs: None)

    entry.main()

    assert captured == [str(patch_file)]
    assert output.exists()


def test_main_applies_worker_count_cli_overrides(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "--non-interactive",
            "--command",
            "help",
            "--review-max-workers",
            "12",
            "--triage-max-workers",
            "14",
        ],
    )
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        entry,
        "load_runtime_config",
        lambda **_kwargs: {
            "max_workers": 8,
            "review_max_workers": 8,
            "triage_max_workers": 8,
        },
    )
    captured = {}

    def _build_engine(args, runtime):
        captured["args"] = args
        captured["runtime"] = dict(runtime)
        engine = SimpleNamespace(has_usage=lambda: False, close=lambda: None)
        return engine, object()

    monkeypatch.setattr(entry, "build_engine", _build_engine)
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)
    monkeypatch.setattr(entry, "run_non_interactive", lambda *_args: (0, None))

    entry.main()

    assert captured["args"].review_max_workers == 12
    assert captured["args"].triage_max_workers == 14
    assert captured["runtime"]["review_max_workers"] == 12
    assert captured["runtime"]["triage_max_workers"] == 14


def test_main_applies_research_profile_cli_overrides(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "--non-interactive",
            "--command",
            "help",
            "--review-profile",
            "research",
            "--hunters",
            "authz_outlier,ssrf",
            "--research-budget",
            "tiny",
            "--proof-artifacts",
            "--evidence-policy",
            "triage_evidence",
        ],
    )
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: {})
    captured = {}

    def _build_engine(args, runtime):
        captured["args"] = args
        captured["runtime"] = dict(runtime)
        engine = SimpleNamespace(has_usage=lambda: False, close=lambda: None)
        return engine, object()

    monkeypatch.setattr(entry, "build_engine", _build_engine)
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)
    monkeypatch.setattr(entry, "run_non_interactive", lambda *_args: (0, None))

    entry.main()

    assert captured["args"].review_profile == "research"
    assert captured["args"].hunters == "authz_outlier,ssrf"
    assert captured["args"].research_budget == "tiny"
    assert captured["args"].proof_artifacts is True
    assert captured["args"].evidence_policy == "triage_evidence"
    assert captured["runtime"]["review_profile"] == "research"
    assert captured["runtime"]["research_hunters"] == "authz_outlier,ssrf"
    assert captured["runtime"]["research_budget"] == "tiny"
    assert captured["runtime"]["research_proof_artifacts"] is True
    assert captured["runtime"]["research_evidence_policy"] == "triage_evidence"


def test_main_applies_research_runtime_defaults(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "--non-interactive",
            "--command",
            "help",
        ],
    )
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        entry,
        "load_runtime_config",
        lambda **_kwargs: {
            "research_hunters": "ssrf",
            "research_budget": "quick",
            "research_proof_artifacts": True,
            "research_evidence_policy": "triage_evidence",
        },
    )
    captured = {}

    def _build_engine(args, runtime):
        captured["args"] = args
        captured["runtime"] = dict(runtime)
        engine = SimpleNamespace(has_usage=lambda: False, close=lambda: None)
        return engine, object()

    monkeypatch.setattr(entry, "build_engine", _build_engine)
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)
    monkeypatch.setattr(entry, "run_non_interactive", lambda *_args: (0, None))

    entry.main()

    assert captured["args"].hunters == "ssrf"
    assert captured["args"].research_budget == "quick"
    assert captured["args"].proof_artifacts is True
    assert captured["args"].evidence_policy == "triage_evidence"


def test_top_level_research_command_uses_runtime_defaults(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "metis",
            "research",
            "run",
            "--no-persist",
        ],
    )
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        entry,
        "load_runtime_config",
        lambda **_kwargs: {
            "research_hunters": "ssrf",
            "research_budget": "quick",
            "research_emit_killed": True,
            "research_emit_unresolved": True,
            "research_proof_artifacts": True,
            "research_evidence_policy": "triage_evidence",
        },
    )
    captured = {}

    class _ResearchService:
        def run(self, _root, *, options):
            from metis.engine.research import ResearchRunResult

            captured["options"] = options
            return ResearchRunResult()

    engine = SimpleNamespace(
        codebase_path=str(tmp_path),
        research=_ResearchService(),
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "research",
            "summary": {},
            "cumulative": {},
        },
    )
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (engine, object()))
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)
    monkeypatch.setattr(entry, "print_usage_summary", lambda *_args, **_kwargs: None)

    entry.main()

    options = captured["options"]
    assert options.hunters == ("ssrf",)
    assert options.research_budget == "quick"
    assert options.emit_killed is True
    assert options.emit_unresolved is True
    assert options.proof_artifacts is True
    assert options.evidence_policy == "triage_evidence"


def test_main_exits_one_for_top_level_bench_regression(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["metis", "bench", "--quick"])
    monkeypatch.setattr(entry, "configure_logger", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(entry, "load_runtime_config", lambda **_kwargs: {})
    engine = SimpleNamespace(
        usage_command=lambda *_args, **_kwargs: nullcontext("command"),
        finalize_usage_command=lambda _command: {
            "display_name": "bench",
            "summary": {},
            "cumulative": {},
        },
    )
    monkeypatch.setattr(entry, "build_engine", lambda *_args: (engine, object()))
    monkeypatch.setattr(entry, "finalize_cli_session_and_close", lambda *_args: None)

    def fake_run_benchmark(_engine, _options):
        result = {
            "mode": "review",
            "case_count": 1,
            "totals": {"tp": 0, "fp": 0, "fn": 1, "recall": 0.0, "precision": 0.0},
            "regression_failed": True,
            "regressions": [{"cwe": "CWE-121"}],
        }
        raise BenchmarkRegressionError(result["regressions"], result)

    monkeypatch.setattr("metis.cli.commands.run_benchmark", fake_run_benchmark)

    with pytest.raises(SystemExit) as exc:
        entry.main()

    assert exc.value.code == 1
