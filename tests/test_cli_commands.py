# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from types import SimpleNamespace

from metis.cli import commands
from metis.cli.command_runtime import CommandRuntime
from metis.bench import BenchmarkOptions, BenchmarkRegressionError
from metis.engine.options import ReviewOptions, TriageOptions


def test_run_review_code_uses_review_domain_surface(monkeypatch):
    calls = []

    class _ReviewDomain:
        def get_code_files(self, options=None):
            assert isinstance(options, ReviewOptions)
            calls.append(("get_code_files", options.use_retrieval_context))
            return ["a.py"]

        def review_code(self, options=None):
            assert isinstance(options, ReviewOptions)
            calls.append(("review_code", options.use_retrieval_context))
            yield {"file": "a.py", "reviews": []}

    engine = SimpleNamespace(review=_ReviewDomain())
    args = SimpleNamespace(
        verbose=True,
        quiet=True,
        triage=False,
        output_file=None,
    )
    runtime = CommandRuntime(
        command="review_code",
        command_args=[],
        use_retrieval_context=True,
    )

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands, "iterate_with_progress", lambda _total, iterable: list(iterable)
    )
    monkeypatch.setattr(
        commands, "_finalize_review_output", lambda *_args, **_kwargs: None
    )

    commands.run_review_code(engine, args, runtime)

    assert calls == [("get_code_files", True), ("review_code", True)]


def test_run_bench_parses_args_and_saves_output(monkeypatch, tmp_path):
    captured = []

    def fake_run_benchmark(_engine, options):
        captured.append(options)
        return {
            "mode": "review",
            "case_count": 1,
            "totals": {"tp": 1, "fp": 0, "fn": 0, "recall": 1.0, "precision": 1.0},
        }

    monkeypatch.setattr(commands, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    output = tmp_path / "bench.json"
    args = SimpleNamespace(quiet=True, output_file=[str(output)])

    commands.run_bench(
        SimpleNamespace(),
        ["--quick", "--triage", "--manifest", "custom.yaml"],
        args,
        CommandRuntime(
            command="bench",
            command_args=[],
            use_retrieval_context=False,
        ),
    )

    assert captured == [
        BenchmarkOptions(
            manifest_path="custom.yaml",
            quick=True,
            triage=True,
            baseline_path=None,
            recall_tolerance=0.05,
            update_baseline=False,
        )
    ]
    assert output.exists()


def test_run_bench_parses_cap_args(monkeypatch, tmp_path):
    captured = []

    def fake_run_benchmark(_engine, options):
        captured.append(options)
        return {
            "mode": "review",
            "case_count": 1,
            "totals": {"tp": 1, "fp": 0, "fn": 0, "recall": 1.0, "precision": 1.0},
        }

    monkeypatch.setattr(commands, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    output = tmp_path / "bench.json"
    args = SimpleNamespace(quiet=True, output_file=[str(output)])

    commands.run_bench(
        SimpleNamespace(),
        ["--quick", "--max-cost", "1.5", "--max-wallclock", "60"],
        args,
        CommandRuntime(
            command="bench",
            command_args=[],
            use_retrieval_context=False,
        ),
    )

    assert captured[0].max_cost_usd == 1.5
    assert captured[0].max_wallclock_seconds == 60.0


def test_run_bench_parses_perf_args(monkeypatch, tmp_path):
    captured = []

    def fake_run_benchmark(_engine, options):
        captured.append(options)
        return {
            "mode": "review",
            "case_count": 1,
            "totals": {"tp": 1, "fp": 0, "fn": 0, "recall": 1.0, "precision": 1.0},
            "perf": True,
            "perf_regression_failed": False,
        }

    monkeypatch.setattr(commands, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    output = tmp_path / "bench.json"
    baseline = tmp_path / "perf-baseline.json"
    args = SimpleNamespace(quiet=True, output_file=[str(output)])

    commands.run_bench(
        SimpleNamespace(),
        [
            "--quick",
            "--perf",
            "--perf-baseline",
            str(baseline),
            "--perf-wallclock-tolerance",
            "0.3",
        ],
        args,
        CommandRuntime(
            command="bench",
            command_args=[],
            use_retrieval_context=False,
        ),
    )

    assert captured[0].perf is True
    assert captured[0].perf_baseline_path == str(baseline)
    assert captured[0].perf_wallclock_tolerance == 0.3


def test_run_bench_saves_regression_result_then_raises(monkeypatch, tmp_path):
    result = {
        "mode": "review",
        "case_count": 1,
        "totals": {"tp": 0, "fp": 0, "fn": 1, "recall": 0.0, "precision": 0.0},
        "regression_failed": True,
        "regressions": [{"cwe": "CWE-121"}],
    }

    def fake_run_benchmark(_engine, _options):
        raise BenchmarkRegressionError(result["regressions"], result)

    monkeypatch.setattr(commands, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    output = tmp_path / "bench.json"
    args = SimpleNamespace(quiet=True, output_file=[str(output)])

    try:
        commands.run_bench(
            SimpleNamespace(),
            ["--quick"],
            args,
            CommandRuntime(
                command="bench",
                command_args=[],
                use_retrieval_context=False,
            ),
        )
    except BenchmarkRegressionError:
        pass
    else:
        raise AssertionError("expected BenchmarkRegressionError")

    assert output.exists()


def test_run_update_uses_indexing_domain_surface(monkeypatch, tmp_path):
    patch_file = tmp_path / "change.diff"
    patch_file.write_text("diff --git a/a.py b/a.py", encoding="utf-8")

    captured: list[str] = []

    class _IndexingDomain:
        def update_index(self, patch_text):
            captured.append(patch_text)

    engine = SimpleNamespace(indexing=_IndexingDomain())
    args = SimpleNamespace(quiet=True)

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **_func_kwargs: func(*func_args),
    )

    commands.run_update(
        engine,
        str(patch_file),
        args,
        CommandRuntime(
            command="update",
            command_args=[str(patch_file)],
            use_retrieval_context=True,
        ),
    )

    assert captured == ["diff --git a/a.py b/a.py"]


def test_run_index_verbose_uses_indexing_domain_surface(monkeypatch):
    calls: list[str] = []

    class _IndexingDomain:
        def count_index_items(self):
            calls.append("count")
            return 2

        def index_prepare_nodes_iter(self):
            calls.append("prepare")
            yield None
            yield None

        def index_finalize_embeddings(self):
            calls.append("finalize")

    engine = SimpleNamespace(indexing=_IndexingDomain())

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands, "iterate_with_progress", lambda _total, iterable: list(iterable)
    )
    monkeypatch.setattr(
        commands, "with_timer", lambda _message, func, **_kwargs: func()
    )

    commands.run_index(engine, verbose=True, quiet=True)

    assert calls == ["count", "prepare", "finalize"]


def test_run_triage_propagates_no_index_mode_and_warning(tmp_path, monkeypatch):
    sarif_path = tmp_path / "input.sarif"
    sarif_path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
    captured = []

    class _DummyEngine:
        def triage_sarif_file(self, input_path, output_path=None, **kwargs):
            assert input_path == str(sarif_path)
            assert isinstance(kwargs["options"], TriageOptions)
            assert kwargs["options"].use_retrieval_context is False
            return output_path or input_path

    args = SimpleNamespace(
        quiet=False,
        output_file=None,
        include_triaged=False,
    )
    runtime = CommandRuntime(
        command="triage",
        command_args=[str(sarif_path)],
        use_retrieval_context=False,
    )
    monkeypatch.setattr(
        commands,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    commands.run_triage(_DummyEngine(), str(sarif_path), args, runtime)

    assert any("Running without index" in message for message in captured)


def test_run_review_patch_propagates_no_index_mode(monkeypatch, tmp_path):
    patch_file = tmp_path / "change.diff"
    patch_file.write_text("diff --git a/a.py b/a.py", encoding="utf-8")
    captured = []

    class _ReviewDomain:
        def review_patch(self, patch_file=None, options=None):
            assert isinstance(options, ReviewOptions)
            assert options.use_retrieval_context is False
            return {"reviews": [], "overall_changes": ""}

    engine = SimpleNamespace(review=_ReviewDomain())
    args = SimpleNamespace(
        quiet=False,
        triage=False,
        output_file=None,
    )
    runtime = CommandRuntime(
        command="review_patch",
        command_args=[str(patch_file)],
        use_retrieval_context=False,
    )

    monkeypatch.setattr(
        commands, "_finalize_review_output", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        commands,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **func_kwargs: func(
            *func_args,
            **{k: v for k, v in func_kwargs.items() if k != "quiet"},
        ),
    )

    commands.run_review(engine, str(patch_file), args, runtime)

    assert any("Running without index" in message for message in captured)


def test_run_review_code_triggers_triage_when_global_flag_enabled(monkeypatch):
    calls = []

    class _ReviewDomain:
        def get_code_files(self, options=None):
            return ["a.py"]

        def review_code(self, options=None):
            yield {"file": "a.py", "reviews": []}

    class _Engine:
        def __init__(self):
            self.review = _ReviewDomain()

        def triage_sarif_payload(self, payload, **kwargs):
            calls.append(kwargs["options"].include_triaged)
            payload["runs"] = []
            return payload

    engine = _Engine()
    args = SimpleNamespace(
        verbose=False,
        quiet=True,
        triage=True,
        include_triaged=False,
        output_file=None,
    )
    runtime = CommandRuntime(
        command="review_code",
        command_args=[],
        use_retrieval_context=True,
    )

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **func_kwargs: func(
            *func_args,
            **{k: v for k, v in func_kwargs.items() if k != "quiet"},
        ),
    )
    monkeypatch.setattr(
        commands, "pretty_print_reviews", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(commands, "save_output", lambda *_args, **_kwargs: None)

    commands.run_review_code(engine, args, runtime)

    assert calls == [False]


def test_review_and_triage_options_include_test_filter_flags():
    args = SimpleNamespace(
        review_mode="standard",
        review_agentic_max_iterations=2,
        review_agentic_max_tool_calls=4,
        review_agentic_tool_timeout_seconds=5,
        review_agentic_max_extra_tokens=8000,
        review_agentic_wallclock_seconds=60.0,
        include_triaged=False,
        skip_test_files=True,
        extra_test_path_patterns=("fixtures/**",),
    )
    runtime = CommandRuntime(
        command="review_code",
        command_args=[],
        use_retrieval_context=False,
    )

    review_options = commands._review_options_for_runtime(args, runtime)
    triage_options = commands._triage_options_for_runtime(args, runtime)

    assert review_options.skip_test_files is True
    assert triage_options.skip_test_files is True
    assert review_options.extra_test_path_patterns == ("fixtures/**",)
    assert triage_options.extra_test_path_patterns == ("fixtures/**",)
