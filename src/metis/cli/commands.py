# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import argparse
import inspect
import importlib
from pathlib import Path
from rich.markup import escape

from metis.bench import BenchmarkOptions, BenchmarkRegressionError, run_benchmark
from metis.engine.options import ReviewAgenticOptions, ReviewOptions, TriageOptions
from .command_runtime import CommandRuntime
from metis.utils import read_file_content, safe_decode_unicode
from metis.sarif.writer import generate_sarif
from metis.usage import usage_operation
from .triage_cli import run_triage_action
from .utils import (
    check_file_exists,
    with_spinner,
    with_timer,
    collect_reviews,
    iterate_with_progress,
    count_index_items,
    pretty_print_reviews,
    save_output,
    print_console,
)


def _finalize_embeddings(indexing, progress_callback=None):
    finalize = indexing.index_finalize_embeddings
    try:
        signature = inspect.signature(finalize)
    except (TypeError, ValueError):
        signature = None
    if signature is not None and "progress_callback" not in signature.parameters:
        return finalize()
    return finalize(progress_callback=progress_callback)


def _print_no_index_warning(args, runtime: CommandRuntime):
    if runtime.use_retrieval_context:
        return
    if runtime.no_index_warning_emitted:
        return
    print_console(
        "[yellow]Warning:[/yellow] Running without index; relevant-context retrieval was skipped.",
        args.quiet,
    )
    runtime.no_index_warning_emitted = True


def _review_options_for_runtime(args, runtime: CommandRuntime) -> ReviewOptions:
    review_mode = getattr(args, "review_mode", None) or "standard"
    return ReviewOptions(
        use_retrieval_context=runtime.use_retrieval_context,
        review_mode=review_mode,
        skip_test_files=bool(getattr(args, "skip_test_files", False)),
        extra_test_path_patterns=tuple(
            getattr(args, "extra_test_path_patterns", ()) or ()
        ),
        agentic=ReviewAgenticOptions(
            max_iterations=int(getattr(args, "review_agentic_max_iterations", 2)),
            max_tool_calls=int(getattr(args, "review_agentic_max_tool_calls", 4)),
            tool_timeout_seconds=int(
                getattr(args, "review_agentic_tool_timeout_seconds", 5)
            ),
            max_extra_tokens=int(
                getattr(args, "review_agentic_max_extra_tokens", 8000)
            ),
            wallclock_seconds=float(
                getattr(args, "review_agentic_wallclock_seconds", 60.0)
            ),
        ),
    )


def _triage_options_for_runtime(args, runtime: CommandRuntime) -> TriageOptions:
    return TriageOptions(
        use_retrieval_context=runtime.use_retrieval_context,
        include_triaged=bool(getattr(args, "include_triaged", False)),
        skip_test_files=bool(getattr(args, "skip_test_files", False)),
        extra_test_path_patterns=tuple(
            getattr(args, "extra_test_path_patterns", ()) or ()
        ),
    )


def show_help(args=None):
    print_console("""
[bold blue]Metis CLI[/bold blue]

Type one of the following commands (with arguments):

- [cyan]index[/cyan]
- [cyan]review_patch mypatch.diff[/cyan]
- [cyan]review_file path_to_file/myfile.c[/cyan]
- [cyan]review_code[/cyan]
- [cyan]bench[/cyan]
- [cyan]triage findings.sarif[/cyan]
- [cyan]update patch.diff[/cyan]
- [cyan]ask "Give me an overview of the code"[/cyan]
- [magenta]exit[/magenta]   (quit the tool)
- [magenta]help[/magenta]   (show this message)

Options:
    --backend chroma|postgres  Vector backend to use (default: chroma).
    --output-file PATH         Save analysis results to this file.
    --custom-prompt PATH       Custom prompt file (.md or .txt) to guide analysis.
    --triage                   Triage findings and annotate SARIF output for review commands.
    --include-triaged          Include findings already triaged by Metis.
    --ignore-index             Allow review_file, review_code, review_patch, and triage to run without index-backed context.
    --review-mode MODE         standard or agentic review mode (default: standard).
    --skip-test-files          Skip files matching test/fixture path heuristics.
    --no-skip-test-files       Disable configured test/fixture path filtering.
    --review-max-workers N     Override review_code worker count.
    --review-agentic-wallclock N
                               Best-effort per-file agentic wall-clock budget.
    --triage-max-workers N     Override triage worker count.
    --no-embed-cache           Disable the local disk embedding cache for indexing.
    --async-llm                Opt into async LLM graph orchestration where supported.
    --project-schema SCHEMA    (Optional) Project identifier if postgresql is used.
    --chroma-dir DIR           (Optional) Directory to store ChromaDB data (default: ./chromadb).
    --verbose                  (Optional) Shows detailed output in the terminal window.
    --version                  (Optional) Show program version
""")


def show_version(args=None):
    version = importlib.metadata.version("metis")
    print_console("Metis [green]" + version + "[/green]")


def run_bench(engine, cmd_args, args, runtime: CommandRuntime):
    parser = argparse.ArgumentParser(prog="bench", add_help=False)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--manifest", default="tests/benchmarks/manifest.yaml")
    parser.add_argument("--baseline")
    parser.add_argument("--recall-tolerance", type=float, default=0.05)
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--triage", action="store_true")
    parser.add_argument("--max-cost", type=float, dest="max_cost_usd")
    parser.add_argument("--max-wallclock", type=float, dest="max_wallclock_seconds")
    parser.add_argument("--perf", action="store_true")
    parser.add_argument(
        "--perf-baseline", default="tests/benchmarks/perf-baseline.json"
    )
    parser.add_argument("--perf-wallclock-tolerance", type=float, default=0.20)
    parser.add_argument("-h", "--help", action="store_true")
    bench_args = parser.parse_args(cmd_args)
    if bench_args.help:
        print_console(
            """
[bold blue]Metis bench[/bold blue]

Options:
    --quick                  Run quick benchmark cases only.
    --manifest PATH          Benchmark manifest path.
    --baseline PATH          Baseline JSON for recall regression checks.
    --recall-tolerance N     Allowed per-CWE recall drop (default: 0.05).
    --update-baseline        Write the current result to --baseline.
    --triage                 Run review findings through SARIF triage before scoring.
    --max-cost USD           Stop after the completed case that exceeds estimated spend.
    --max-wallclock SECONDS  Stop after the completed case that exceeds elapsed time.
    --perf                   Compare wall-clock metrics against a perf baseline.
    --perf-baseline PATH     Perf baseline JSON (default: tests/benchmarks/perf-baseline.json).
    --perf-wallclock-tolerance N
                             Allowed wall-clock growth ratio (default: 0.20).
""",
            args.quiet,
        )
        return
    if bench_args.max_cost_usd is not None and bench_args.max_cost_usd < 0:
        parser.error("--max-cost must be non-negative")
    if (
        bench_args.max_wallclock_seconds is not None
        and bench_args.max_wallclock_seconds < 0
    ):
        parser.error("--max-wallclock must be non-negative")
    if bench_args.perf_wallclock_tolerance < 0:
        parser.error("--perf-wallclock-tolerance must be non-negative")

    review_mode = str(getattr(args, "review_mode", "standard") or "standard")
    agentic_options = None
    if review_mode == "agentic":
        agentic_options = ReviewAgenticOptions(
            max_iterations=int(getattr(args, "review_agentic_max_iterations", 2)),
            max_tool_calls=int(getattr(args, "review_agentic_max_tool_calls", 4)),
            tool_timeout_seconds=int(
                getattr(args, "review_agentic_tool_timeout_seconds", 5)
            ),
            max_extra_tokens=int(
                getattr(args, "review_agentic_max_extra_tokens", 8000)
            ),
            wallclock_seconds=float(
                getattr(args, "review_agentic_wallclock_seconds", 60.0)
            ),
        )

    options = BenchmarkOptions(
        manifest_path=bench_args.manifest,
        quick=bench_args.quick,
        triage=bench_args.triage,
        baseline_path=bench_args.baseline,
        recall_tolerance=bench_args.recall_tolerance,
        update_baseline=bench_args.update_baseline,
        review_mode=review_mode,
        agentic_options=agentic_options,
        max_cost_usd=bench_args.max_cost_usd,
        max_wallclock_seconds=bench_args.max_wallclock_seconds,
        perf=bench_args.perf,
        perf_baseline_path=bench_args.perf_baseline if bench_args.perf else None,
        perf_wallclock_tolerance=bench_args.perf_wallclock_tolerance,
    )
    try:
        result = run_benchmark(engine, options)
    except BenchmarkRegressionError as exc:
        result = exc.result or {
            "regressions": exc.regressions,
            "regression_failed": True,
        }
        save_output(args.output_file, result, args.quiet)
        _print_benchmark_summary(result, args.quiet)
        raise
    save_output(args.output_file, result, args.quiet)
    _print_benchmark_summary(result, args.quiet)


def _print_benchmark_summary(result, quiet=False):
    totals = result.get("totals", {})
    print_console(
        (
            "[bold cyan]Benchmark complete[/bold cyan] "
            f"mode={escape(str(result.get('mode', 'unknown')))} "
            f"cases={result.get('case_count', 0)} "
            f"tp={totals.get('tp', 0)} fp={totals.get('fp', 0)} fn={totals.get('fn', 0)} "
            f"recall={float(totals.get('recall', 0.0)):.3f} "
            f"precision={float(totals.get('precision', 0.0)):.3f}"
        ),
        quiet,
    )
    if result.get("regression_failed"):
        print_console("[red]Benchmark regression failed.[/red]", quiet)
    if result.get("partial"):
        print_console(
            f"[yellow]Benchmark partial:[/yellow] {escape(str(result.get('partial_reason', 'cap exceeded')))}",
            quiet,
        )
    if result.get("perf_regression_failed"):
        print_console("[red]Benchmark perf regression failed.[/red]", quiet)


def run_review(engine, patch_file, args, runtime: CommandRuntime):
    if not check_file_exists(patch_file):
        return
    _print_no_index_warning(args, runtime)
    options = _review_options_for_runtime(args, runtime)
    results = with_spinner(
        "Reviewing patch...",
        engine.review.review_patch,
        patch_file=patch_file,
        options=options,
        quiet=args.quiet,
    )
    _finalize_review_output(engine, results, args, runtime)


def run_file_review(engine, file_path, args, runtime: CommandRuntime):
    if not check_file_exists(file_path):
        return
    _print_no_index_warning(args, runtime)
    options = _review_options_for_runtime(args, runtime)
    raw_result = with_spinner(
        f"Reviewing file {file_path}...",
        engine.review.review_file,
        file_path=file_path,
        options=options,
        quiet=args.quiet,
    )

    if raw_result and isinstance(raw_result.get("reviews"), list):
        results = {"reviews": [raw_result]}
    else:
        results = {"reviews": []}

    _finalize_review_output(engine, results, args, runtime)


def run_review_code(engine, args, runtime: CommandRuntime):
    _print_no_index_warning(args, runtime)
    options = _review_options_for_runtime(args, runtime)
    if args.verbose:
        print_console("[cyan]Reviewing codebase...[/cyan]", args.quiet)
        total = len(engine.review.get_code_files(options=options))
        file_reviews = iterate_with_progress(
            total,
            engine.review.review_code(options=options),
        )
        results = {"reviews": file_reviews}
    else:
        results = with_spinner(
            "Reviewing codebase...",
            collect_reviews,
            engine,
            options=options,
            quiet=args.quiet,
        )
    _finalize_review_output(engine, results, args, runtime)


def run_index(engine, verbose=False, quiet=False):
    if verbose:
        print_console("[cyan]Indexing codebase...[/cyan]", quiet)
        total = count_index_items(engine)
        if total > 0:
            iterate_with_progress(total, engine.indexing.index_prepare_nodes_iter())

            def _progress(payload):
                if payload.get("event") != "index.embeddings.finished":
                    return
                hits = int(payload.get("cache_hits", 0) or 0)
                misses = int(payload.get("cache_misses", 0) or 0)
                if hits or misses:
                    print_console(
                        f"[cyan]Embedding cache:[/cyan] hits={hits} misses={misses}",
                        quiet,
                    )

            with_timer(
                "Embedding indexes...",
                lambda: _finalize_embeddings(
                    engine.indexing,
                    progress_callback=_progress,
                ),
                quiet=quiet,
            )
            print_console("[green]Indexing completed successfully.[/green]", quiet)
            return

    with_spinner("Indexing codebase...", engine.indexing.index_codebase, quiet=quiet)
    print_console("[green]Indexing completed successfully.[/green]", quiet)


def run_update(engine, patch_file, args, runtime: CommandRuntime):
    if not check_file_exists(patch_file):
        return
    file_diff = read_file_content(patch_file)
    with_spinner(
        "Updating index...",
        engine.indexing.update_index,
        file_diff,
        quiet=args.quiet,
    )
    print_console("[green]Index update completed.[/green]", args.quiet)


def run_ask(engine, question, args, runtime: CommandRuntime):
    answer = with_spinner(
        "Thinking...", engine.ask_question, question, quiet=args.quiet
    )
    print_console("[bold magenta]Metis Answer:[/bold magenta]\n")
    if isinstance(answer, dict):
        if "code" in answer:
            print_console(
                f"[bold yellow]Code Context:[/bold yellow] {escape(safe_decode_unicode(answer['code']))} \n",
            )
        if "docs" in answer:
            print_console(
                f"[bold blue]Documentation Context:[/bold blue] {escape(safe_decode_unicode(answer['docs']))}",
            )
    else:
        print_console(escape(str(answer)))
    save_output(args.output_file, answer, args.quiet)


def run_triage(engine, sarif_path, args, runtime: CommandRuntime):
    if not check_file_exists(sarif_path, quiet=args.quiet):
        return
    if Path(sarif_path).suffix.lower() != ".sarif":
        print_console("[red]Only .sarif input files are supported.[/red]", args.quiet)
        return
    _print_no_index_warning(args, runtime)
    print_console("[cyan]Loading SARIF findings...[/cyan]", args.quiet)
    options = _triage_options_for_runtime(args, runtime)

    output_target = None
    if args.output_file:
        sarif_targets = [
            p for p in args.output_file if str(p).lower().endswith(".sarif")
        ]
        if sarif_targets:
            output_target = sarif_targets[0]

    def _invoke(kwargs):
        return engine.triage_sarif_file(
            sarif_path,
            output_target,
            options=options,
            **kwargs,
        )

    saved_path = run_triage_action(
        args,
        action=_invoke,
        spinner_text="Triaging SARIF findings...",
    )
    print_console(
        f"[green]Triage complete. SARIF saved to {escape(str(saved_path))}[/green]",
        args.quiet,
    )


def _build_triaged_sarif_payload(engine, results, args, runtime: CommandRuntime):
    if not getattr(args, "triage", False):
        return None
    try:
        sarif_payload = generate_sarif(results)
        _print_no_index_warning(args, runtime)
        options = _triage_options_for_runtime(args, runtime)

        def _invoke(kwargs):
            return engine.triage_sarif_payload(
                sarif_payload,
                options=options,
                **kwargs,
            )

        with usage_operation("triage"):
            return run_triage_action(
                args,
                action=_invoke,
                spinner_text="Triaging findings...",
            )
    except Exception as exc:
        print_console(
            f"[yellow]Triage skipped due to error: {escape(str(exc))}[/yellow]",
            args.quiet,
        )
        return None


def _finalize_review_output(engine, results, args, runtime: CommandRuntime):
    pretty_print_reviews(results, args.quiet)
    sarif_payload = _build_triaged_sarif_payload(engine, results, args, runtime)
    save_output(args.output_file, results, args.quiet, sarif_payload=sarif_payload)
