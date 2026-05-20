# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import argparse
import inspect
import importlib
from pathlib import Path
from rich.markup import escape

from metis.bench import BenchmarkOptions, BenchmarkRegressionError, run_benchmark
from metis.engine.options import ReviewAgenticOptions, ReviewOptions, TriageOptions
from metis.engine.research import (
    DEFAULT_RESEARCH_HUNTERS,
    HypothesisStatus,
    ResearchOptions,
    generate_research_sarif,
    hypotheses_to_review_results,
    write_research_sarif,
)
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

DEFAULT_RESEARCH_HUNTERS_TEXT = ",".join(DEFAULT_RESEARCH_HUNTERS)


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
    review_profile = getattr(args, "review_profile", None) or "normal"
    return ReviewOptions(
        use_retrieval_context=runtime.use_retrieval_context,
        review_mode=review_mode,
        review_profile=review_profile,
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
- [cyan]research model[/cyan]
- [cyan]research graph[/cyan]
- [cyan]variants --from-fix patch.diff[/cyan]
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
    --review-profile PROFILE   normal or research review objective (default: normal).
    --hunters LIST             Research hunters for research profile commands.
    --from-fix PATH            Mine variant hypotheses from a fix patch.
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
    parser.add_argument("--research", action="store_true")
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
    --research               Run vulnerability research hunters and score hypotheses.
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
        research=bench_args.research,
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


def run_research(engine, cmd_args, args, runtime: CommandRuntime):
    parser = argparse.ArgumentParser(prog="research", add_help=False)
    parser.add_argument(
        "subcommand",
        nargs="?",
        choices=("model", "graph", "run"),
        default="run",
    )
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--persist", dest="persist", action="store_true", default=None)
    parser.add_argument("--no-persist", dest="persist", action="store_false")
    parser.add_argument("--hunters")
    parser.add_argument("--research-budget")
    parser.add_argument("--emit-killed", action="store_true", default=None)
    parser.add_argument("--emit-unresolved", action="store_true", default=None)
    parser.add_argument("--proof-artifacts", action="store_true", default=None)
    parser.add_argument("--evidence-policy")
    parser.add_argument("--evidence-ledger", nargs="?", const=True, default=None)
    parser.add_argument("--research-report", nargs="?", const=True, default=None)
    parser.add_argument("--sarif", nargs="?", const=True, default=None)
    parser.add_argument("--hypotheses", nargs="?", const=True, default=None)
    parser.add_argument("-h", "--help", action="store_true")
    research_args = parser.parse_args(cmd_args)
    if research_args.help:
        print_console(
            """
[bold blue]Metis research[/bold blue]

Commands:
    run                     Run configured vulnerability research hunters.
    model                   Build or load .metis/security_model.json.
    graph                   Build or load .metis/security_graph.json.

Options:
    --rebuild               Force rebuilding model/graph artifacts.
    --persist               Persist research artifacts for run (default for run).
    --no-persist            Return a report without writing research artifacts.
    --hunters LIST          Comma-separated hunters for run (default: configured research hunter set).
    --research-budget NAME  Budget label stored in the run metrics.
    --emit-killed           Include killed hypotheses in research SARIF.
    --emit-unresolved       Include unresolved hypotheses in research SARIF.
    --proof-artifacts       Generate safe local proof artifacts for proven hypotheses.
    --evidence-policy NAME  Bounded evidence tool policy for verification.
    --evidence-ledger [PATH]
                            Write evidence JSONL to PATH, or the default .metis path.
    --research-report [PATH]
                            Write full JSON report to PATH, or the default .metis path.
    --sarif [PATH]          Write research SARIF to PATH, or the default .metis path.
""",
            args.quiet,
        )
        return

    root = getattr(engine, "codebase_path", None) or engine._config.codebase_path
    if research_args.subcommand == "graph":
        graph = engine.research.security_graph.load_or_build(
            root,
            rebuild=research_args.rebuild,
        )
        payload = graph.model_dump(mode="json")
    elif research_args.subcommand == "run":
        hunters = _parse_hunters(
            research_args.hunters
            if research_args.hunters is not None
            else _runtime_get(runtime, "research_hunters", DEFAULT_RESEARCH_HUNTERS_TEXT)
        )
        persist = True if research_args.persist is None else bool(research_args.persist)
        emit_killed = _research_bool_default(
            research_args.emit_killed,
            runtime,
            "research_emit_killed",
        )
        emit_unresolved = _research_bool_default(
            research_args.emit_unresolved,
            runtime,
            "research_emit_unresolved",
        )
        proof_artifacts = _research_bool_default(
            research_args.proof_artifacts,
            runtime,
            "research_proof_artifacts",
        )
        evidence_policy = _research_text_default(
            research_args.evidence_policy,
            runtime,
            "research_evidence_policy",
            "triage_evidence",
        )
        research_budget = _research_text_default(
            research_args.research_budget,
            runtime,
            "research_budget",
            "standard",
        )
        result = engine.research.run(
            root,
            options=ResearchOptions(
                hunters=hunters or DEFAULT_RESEARCH_HUNTERS,
                persist=persist,
                rebuild=research_args.rebuild,
                research_budget=research_budget,
                emit_killed=emit_killed,
                emit_unresolved=emit_unresolved,
                proof_artifacts=proof_artifacts,
                evidence_policy=evidence_policy,
                hypotheses_path=_optional_cli_path(research_args.hypotheses),
                evidence_ledger_path=_optional_cli_path(
                    research_args.evidence_ledger
                ),
                sarif_path=_optional_cli_path(research_args.sarif),
                research_report_path=_optional_cli_path(
                    research_args.research_report
                ),
            ),
        )
        payload = result.model_dump(mode="json")
        _save_research_output_files(
            args.output_file,
            payload,
            result.generated,
            evidence_ledger_path=result.evidence_ledger_path,
            include_statuses=_research_include_statuses_from_flags(
                emit_killed=emit_killed,
                emit_unresolved=emit_unresolved,
            ),
            quiet=args.quiet,
        )
        print_console(
            _format_research_summary(result),
            args.quiet,
        )
        return
    else:
        model = engine.research.security_model.load_or_build(
            root,
            rebuild=research_args.rebuild,
        )
        payload = model.model_dump(mode="json")
    save_output(args.output_file, payload, args.quiet)
    print_console(
        f"[green]Research {escape(str(research_args.subcommand))} complete.[/green]",
        args.quiet,
    )


def run_variants(engine, cmd_args, args, runtime: CommandRuntime):
    parser = argparse.ArgumentParser(prog="variants", add_help=False)
    parser.add_argument("--from-fix")
    parser.add_argument("--from-sarif")
    parser.add_argument("--from-report")
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--persist", dest="persist", action="store_true", default=None)
    parser.add_argument("--no-persist", dest="persist", action="store_false")
    parser.add_argument("--research-budget")
    parser.add_argument("--emit-killed", action="store_true", default=None)
    parser.add_argument("--emit-unresolved", action="store_true", default=None)
    parser.add_argument("--proof-artifacts", action="store_true", default=None)
    parser.add_argument("--evidence-policy")
    parser.add_argument("--evidence-ledger", nargs="?", const=True, default=None)
    parser.add_argument("--research-report", nargs="?", const=True, default=None)
    parser.add_argument("--sarif", nargs="?", const=True, default=None)
    parser.add_argument("--hypotheses", nargs="?", const=True, default=None)
    parser.add_argument("-h", "--help", action="store_true")
    variant_args = parser.parse_args(cmd_args)
    if variant_args.help:
        print_console(
            """
[bold blue]Metis variants[/bold blue]

Options:
    --from-fix PATH        Mine variants from a unified diff or patch file.
    --from-sarif PATH      Mine variants from fixed SARIF finding metadata.
    --from-report PATH     Mine variants from a markdown/text report.
    --rebuild              Force rebuilding graph artifacts.
    --persist              Persist research artifacts (default).
    --no-persist           Return a report without writing research artifacts.
    --emit-killed          Include killed hypotheses in research SARIF.
    --emit-unresolved      Include unresolved hypotheses in research SARIF.
    --proof-artifacts      Generate safe local proof artifacts for proven variants.
    --evidence-policy NAME Bounded evidence tool policy for verification.
    --evidence-ledger [PATH]
                           Write evidence JSONL to PATH, or the default .metis path.
    --research-report [PATH]
                           Write full JSON report to PATH, or the default .metis path.
    --sarif [PATH]         Write research SARIF to PATH, or the default .metis path.
""",
            args.quiet,
        )
        return
    if not any(
        (variant_args.from_fix, variant_args.from_sarif, variant_args.from_report)
    ):
        parser.error("one of --from-fix, --from-sarif, or --from-report is required")
    for input_path in (
        variant_args.from_fix,
        variant_args.from_sarif,
        variant_args.from_report,
    ):
        if input_path and not check_file_exists(input_path, quiet=args.quiet):
            return

    root = getattr(engine, "codebase_path", None) or engine._config.codebase_path
    persist = True if variant_args.persist is None else bool(variant_args.persist)
    emit_killed = _research_bool_default(
        variant_args.emit_killed,
        runtime,
        "research_emit_killed",
    )
    emit_unresolved = _research_bool_default(
        variant_args.emit_unresolved,
        runtime,
        "research_emit_unresolved",
    )
    proof_artifacts = _research_bool_default(
        variant_args.proof_artifacts,
        runtime,
        "research_proof_artifacts",
    )
    research_budget = _research_text_default(
        variant_args.research_budget,
        runtime,
        "research_budget",
        "standard",
    )
    evidence_policy = _research_text_default(
        variant_args.evidence_policy,
        runtime,
        "research_evidence_policy",
        "triage_evidence",
    )
    result = engine.research.run_variants(
        root,
        from_fix=variant_args.from_fix,
        from_sarif=variant_args.from_sarif,
        from_report=variant_args.from_report,
        options=ResearchOptions(
            persist=persist,
            rebuild=variant_args.rebuild,
            research_budget=research_budget,
            emit_killed=emit_killed,
            emit_unresolved=emit_unresolved,
            proof_artifacts=proof_artifacts,
            evidence_policy=evidence_policy,
            hypotheses_path=_optional_cli_path(variant_args.hypotheses),
            evidence_ledger_path=_optional_cli_path(variant_args.evidence_ledger),
            sarif_path=_optional_cli_path(variant_args.sarif),
            research_report_path=_optional_cli_path(variant_args.research_report),
        ),
    )
    payload = result.model_dump(mode="json")
    _save_research_output_files(
        args.output_file,
        payload,
        result.generated,
        evidence_ledger_path=result.evidence_ledger_path,
        include_statuses=_research_include_statuses_from_flags(
            emit_killed=emit_killed,
            emit_unresolved=emit_unresolved,
        ),
        quiet=args.quiet,
    )
    print_console(_format_variants_summary(result), args.quiet)


def _parse_hunters(raw: str | None) -> tuple[str, ...]:
    return tuple(item.strip() for item in str(raw or "").split(",") if item.strip())


def _optional_cli_path(raw: str | bool | None) -> str | None:
    if raw is None or raw is True:
        return None
    return str(raw)


def _research_bool_default(
    value: bool | None,
    runtime: CommandRuntime,
    key: str,
) -> bool:
    if value is None:
        return bool(_runtime_get(runtime, key, False))
    return bool(value)


def _research_text_default(
    value: str | None,
    runtime: CommandRuntime,
    key: str,
    default: str,
) -> str:
    if value is None:
        return str(_runtime_get(runtime, key, default) or default)
    return str(value or default)


def _runtime_get(runtime, key: str, default=None):
    get_value = getattr(runtime, "get", None)
    if callable(get_value):
        return get_value(key, default)
    config = getattr(runtime, "config", None)
    if isinstance(config, dict) and key in config:
        return config.get(key, default)
    return getattr(runtime, key, default)


def _research_include_statuses(research_args) -> tuple[HypothesisStatus, ...]:
    return _research_include_statuses_from_flags(
        emit_killed=bool(getattr(research_args, "emit_killed", False)),
        emit_unresolved=bool(getattr(research_args, "emit_unresolved", False)),
    )


def _research_include_statuses_from_flags(
    *,
    emit_killed: bool,
    emit_unresolved: bool,
) -> tuple[HypothesisStatus, ...]:
    statuses = [HypothesisStatus.PROVEN]
    if emit_killed:
        statuses.append(HypothesisStatus.KILLED)
    if emit_unresolved:
        statuses.append(HypothesisStatus.UNRESOLVED)
    return tuple(statuses)


def _save_research_output_files(
    output_files,
    payload,
    hypotheses,
    *,
    evidence_ledger_path: str | None,
    include_statuses: tuple[HypothesisStatus, ...],
    quiet: bool,
) -> None:
    if not output_files:
        return
    files = [output_files] if isinstance(output_files, (str, Path)) else output_files
    json_outputs = []
    for file_entry in files:
        output_path = Path(file_entry)
        if output_path.suffix.lower() == ".sarif":
            write_research_sarif(
                hypotheses,
                output_path,
                evidence_ledger_path=evidence_ledger_path,
                include_statuses=include_statuses,
            )
            print_console(
                f"[blue]Research SARIF saved to {escape(str(output_path))}[/blue]",
                quiet,
            )
        else:
            json_outputs.append(output_path)
    if json_outputs:
        save_output(json_outputs, payload, quiet)


def _format_research_summary(result) -> str:
    summary = (
        "[green]Research run complete.[/green] "
        f"generated={len(result.generated)} proven={len(result.proven)} "
        f"killed={len(result.killed)} unresolved={len(result.unresolved)}"
    )
    budget = result.metric_summary.get("research_budget")
    if budget:
        summary += f" budget={escape(str(budget))}"
    artifact_parts = []
    for label, value in (
        ("hypotheses", result.hypotheses_path),
        ("evidence", result.evidence_ledger_path),
        ("sarif", result.sarif_path),
        ("report", result.research_report_path),
    ):
        if value:
            artifact_parts.append(f"{label}={escape(str(value))}")
    proof_count = len(getattr(result, "proof_artifact_paths", ()) or ())
    if proof_count:
        artifact_parts.append(f"proof_artifacts={proof_count}")
    if artifact_parts:
        summary += " artifacts: " + " ".join(artifact_parts)
    return summary


def _format_variants_summary(result) -> str:
    patterns = result.metric_summary.get("variant_patterns", [])
    return (
        "[green]Variant mining complete.[/green] "
        f"patterns={len(patterns)} generated={len(result.generated)} "
        f"proven={len(result.proven)} killed={len(result.killed)} "
        f"unresolved={len(result.unresolved)}"
    )


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
    hypotheses = result.get("hypotheses")
    if isinstance(hypotheses, dict):
        key_metric = hypotheses.get("proven_vulnerabilities_per_analysis_budget")
        per_wallclock = "n/a"
        if isinstance(key_metric, dict):
            raw_per_wallclock = key_metric.get("per_wallclock_second")
            if isinstance(raw_per_wallclock, int | float):
                per_wallclock = f"{float(raw_per_wallclock):.3f}/s"
        print_console(
            (
                "[bold cyan]Research benchmark[/bold cyan] "
                f"generated={hypotheses.get('generated', 0)} "
                f"proven={hypotheses.get('proven', 0)} "
                f"killed={hypotheses.get('killed', 0)} "
                f"unresolved={hypotheses.get('unresolved', 0)} "
                "evidence="
                f"{float(hypotheses.get('evidence_completeness_rate', 0.0)):.3f} "
                f"proven_per_budget={per_wallclock}"
            ),
            quiet,
        )


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
    options = _review_options_for_runtime(args, runtime)
    if options.review_profile == "research":
        _run_review_code_research(engine, args, runtime)
        return
    _print_no_index_warning(args, runtime)
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


def _run_review_code_research(engine, args, runtime: CommandRuntime):
    root = getattr(engine, "codebase_path", None) or engine._config.codebase_path
    hunters = _parse_hunters(getattr(args, "hunters", None)) or DEFAULT_RESEARCH_HUNTERS
    result = with_spinner(
        "Running vulnerability research...",
        engine.research.run,
        root,
        options=ResearchOptions(
            hunters=hunters,
            persist=True,
            research_budget=str(getattr(args, "research_budget", "standard")),
            proof_artifacts=bool(getattr(args, "proof_artifacts", False)),
            evidence_policy=str(
                getattr(
                    args,
                    "evidence_policy",
                    _runtime_get(
                        runtime,
                        "research_evidence_policy",
                        "triage_evidence",
                    ),
                )
                or "triage_evidence"
            ),
        ),
        quiet=args.quiet,
    )
    review_results = hypotheses_to_review_results(
        result.generated,
        evidence_ledger_path=result.evidence_ledger_path,
    )
    sarif_payload = generate_research_sarif(
        result.generated,
        evidence_ledger_path=result.evidence_ledger_path,
    )
    pretty_print_reviews(review_results, args.quiet)
    triaged_payload = _build_triaged_sarif_payload(
        engine,
        review_results,
        args,
        runtime,
    )
    save_output(
        args.output_file,
        review_results,
        args.quiet,
        sarif_payload=triaged_payload or sarif_payload,
    )


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
