# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from metis.cli import entry
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
