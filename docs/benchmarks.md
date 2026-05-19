# Metis Benchmarks

`metis bench` runs the benchmark manifest, scores the generated SARIF, and emits JSON plus a concise terminal summary.

Quick local run:

```bash
metis bench --quick --output-file results/bench.json
```

By default, bench runs review-only scoring. Add `--triage` to measure post-triage actionable findings:

```bash
metis bench --quick --triage --output-file results/bench-triage.json
```

Review-only runs count every reported SARIF result as active and set inconclusive metrics to `not_applicable`. Triage-enabled runs count only `metisTriageStatus=valid` and untriaged findings as active. `invalid` findings are suppressed from precision/recall, and `inconclusive` findings are counted separately; expected findings suppressed by triage remain false negatives.

## Adding a Case

Add source files under `tests/benchmarks/cases/` and register them in `tests/benchmarks/manifest.yaml`:

```yaml
- id: internal-cwe121-001
  source: internal
  cwe: CWE-121
  language: c
  path: cases/internal/cwe121/001
  quick: true
  expected_findings:
    - file: vuln.c
      line_range: [6, 8]
      cwe: CWE-121
      severity_min: medium
```

## Baselines

Use a baseline JSON to fail when per-CWE recall drops by more than the tolerance:

```bash
metis bench --quick --baseline tests/benchmarks/baseline-quick.json --recall-tolerance 0.05
```

Refresh a baseline intentionally:

```bash
metis bench --quick --baseline tests/benchmarks/baseline-quick.json --update-baseline
```

The checked-in corpus is a harness smoke baseline, not a representative detection-quality benchmark. Juliet, OWASP Benchmark, pinned OSS CVEs, and clean negative projects should be added as separate manifest cases as corpus ownership and runtime budget are agreed.

Use `--perf` to compare benchmark command timing against a performance baseline:

```bash
metis bench --quick --perf --perf-baseline tests/benchmarks/perf-baseline.json
```

Perf baselines record corpus identity plus per-command metrics:

```json
{
  "mode": "review",
  "quick": true,
  "case_count": 1,
  "case_ids": ["internal-cwe121-001"],
  "commands": {
    "review_code": {
      "wallclock_seconds": 60.0,
      "total_tokens": 0
    }
  }
}
```

By default, Metis fails the perf check when a comparable command's wall-clock time grows by more than 20%. Token totals are compared into `perf_observations` for inspection and baseline history, but wall-clock is the hard regression gate in this mode. The PR workflow keeps perf checks deterministic through unit/contract tests; live provider-dependent timing should be treated as scheduled/reporting evidence unless the runner and provider are stable enough for gating.

## Cost & Wallclock Caps

Use caps to keep scheduled benchmark runs bounded:

```bash
metis bench --quick --max-cost 1.50 --max-wallclock 1800 --output-file results/bench-nightly.json
```

Caps are checked after each completed case. When a cap is exceeded, Metis stops scheduling further cases, computes metrics over the completed cases, and emits `"partial": true` with a `partial_reason`. Baseline regression checks are skipped for partial runs because the case set no longer matches the baseline corpus.

Cost is best-effort. Metis uses usage accounting cost fields when providers supply them; otherwise it estimates from total tokens using `METIS_BENCH_FALLBACK_USD_PER_MILLION_TOKENS` (default `1.0`). Treat `--max-wallclock` as the hard operational guard when provider cost metadata is unavailable.

The GitHub nightly job uses `--max-cost 1.50` and `--max-wallclock 1800` for the optional live quick benchmark step.

## Runtime Speed Knobs

Wave 3 performance switches are deliberately incremental and measurable:

- The SQLite embedding cache is enabled by default and can be disabled with `--no-embed-cache` or `metis_engine.embed_cache_enabled: false`.
- Async LLM execution is opt-in with `--async-llm` or `metis_engine.async_llm_enabled: true`.
- Agentic review keeps `max_iterations=3` and `max_tool_calls=6` by default; `review.agentic.wallclock_seconds` adds a wall-clock guard without reducing recall-sensitive tool access.

Use `metis bench --perf` before changing those defaults. In particular, lower agentic iteration or tool-call defaults only with live benchmark evidence showing latency improves without recall loss.

## Skipping Test Files

Runtime review and triage can skip intentionally vulnerable test or fixture files with:

```yaml
filters:
  skip_test_files: true
  extra_test_path_patterns:
    - fixtures/**
```

The CLI mirrors the config with `--skip-test-files` and `--no-skip-test-files`. The default remains `false` for backward compatibility.

The built-in heuristic covers common test directories and names such as `tests/`, `test/`, `__tests__/`, `*_test.go`, `test_*.py`, `*.spec.ts`, `*.test.js`, Juliet `testcases/`, and OWASP `BenchmarkTest*.java`. Language plugins can extend this by implementing `get_test_path_patterns()` or by declaring `test_path_patterns` in their plugin config.

Benchmark execution always passes `skip_test_files=False`, even if the global filter is enabled, because benchmark corpora often live under fixture-like paths by design.
