# Metis Detection Roadmap — Top 5 High-Leverage Tasks

> **Status:** Proposal
> **Scope:** The first 20% of changes targeting ~80% of the achievable
> improvement in vulnerability detection.
> **Companion document:** `docs/improvement-proposals.md` (full long-form proposal).

---

## Table of Contents

1. [Goals & Guiding Principles](#1-goals--guiding-principles)
2. [Task 1 — Evaluation Harness & Baseline](#task-1--evaluation-harness--baseline)
3. [Task 2 — Function-Level Chunks + Caller/Callee Retrieval](#task-2--function-level-chunks--callercallee-retrieval)
4. [Task 3 — Bounded Agentic Fetch-More-Context Loop](#task-3--bounded-agentic-fetch-more-context-loop)
5. [Task 4 — Lift `GenericTreeSitterAnalyzer` to C-Family Depth](#task-4--lift-generictreesitteranalyzer-to-c-family-depth)
6. [Task 5 — Adaptive Evidence Budget + Multi-Hop Symbol Resolution](#task-5--adaptive-evidence-budget--multi-hop-symbol-resolution)
7. [Sequencing & Dependencies](#sequencing--dependencies)
8. [Cross-Cutting Concerns](#cross-cutting-concerns)

---

## 1. Goals & Guiding Principles

**Goal.** Maximize the *measurable* increase in true-positive vulnerability
findings from the existing Metis pipeline, with the smallest amount of new
code and minimum risk to current behavior.

**Guiding principles**

- **Measure first, then change.** No optimization without a baseline.
- **Reuse what exists.** Tree-sitter runtime, plugins, LangGraph nodes,
  triage adjudication, evidence tools — all stay; we extend, not replace.
- **Default-off for risky changes.** New behaviors gated behind flags or
  modes until benchmarks confirm they're net-positive.
- **Recall first, precision second.** Most user pain today is missed bugs;
  precision work (calibration, dedup) lands after recall lift.
- **Avoid lock-in.** Sidecar files instead of new infra; portable JSON
  formats; nothing that blocks moving to a graph DB later if needed.

---

## Task 1 — Evaluation Harness & Baseline

**ID:** `eval-harness`
**Why first:** Tasks 2–5 are all bets on detection quality. Without a
baseline + repeatable measurement, none of them are provable, and CI cannot
prevent silent regressions when prompts or models change.

### 1.1 Deliverables

1. A new CLI subcommand: `metis bench`.
2. A benchmark corpus checked into a separate repo or `tests/benchmarks/`,
   with a manifest describing each case.
3. A scoring module producing per-CWE recall, precision, F1, plus
   inconclusive-rate and token cost.
4. CI integration that fails if recall on the corpus drops by more than
   a configured tolerance.
5. A short `docs/benchmarks.md` describing how to add a case and how to
   interpret results.

### 1.2 Benchmark corpus composition

| Source | Languages | Purpose |
|--------|-----------|---------|
| Juliet Test Suite (subset) | C, C++, Java | Memory safety, integer issues, taint sinks; ground-truth labels |
| OWASP Benchmark (subset) | Java | Web injection patterns; ground-truth labels |
| 2–3 real OSS repos pinned to a vulnerable commit + CVE list | Python, JS, Go | Realism; cross-file flows |
| Internal curated cases | All supported languages | Cover gaps not represented above |
| "Negative" repos (clean code) | Mixed | Precision regression signal |

Subset Juliet/OWASP aggressively (e.g., 50–200 cases per CWE) to keep a
bench run under ~30 minutes on a developer laptop.

### 1.3 Manifest format

```yaml
# tests/benchmarks/manifest.yaml
- id: juliet-cwe121-001
  source: juliet
  cwe: CWE-121
  language: c
  path: cases/juliet/cwe121/001/
  expected_findings:
    - file: vuln.c
      line_range: [42, 48]
      cwe: CWE-121
      severity_min: medium
- id: owasp-bench-sqli-007
  source: owasp-benchmark
  cwe: CWE-89
  language: java
  path: cases/owasp/sqli/007/
  expected_findings:
    - file: BenchmarkTest00007.java
      line_range: [55, 75]
      cwe: CWE-89
```

### 1.4 Scoring

A finding is a **true positive** if: (a) reported file matches, (b) reported
line falls within the expected `line_range` ± tolerance, (c) the reported
CWE matches a configurable equivalence class (e.g., CWE-89 ≡ CWE-564).
Otherwise it is a false positive. Expected findings not produced are
false negatives.

Output format:

```json
{
  "run_id": "...",
  "model": "gpt-5.5",
  "git_sha": "abc123",
  "totals": { "tp": 412, "fp": 188, "fn": 96, "inconclusive": 47 },
  "by_cwe": {
    "CWE-89":  { "tp": 38, "fp": 9,  "fn": 4,  "recall": 0.905, "precision": 0.808 },
    "CWE-121": { "tp": 26, "fp": 17, "fn": 12, "recall": 0.684, "precision": 0.605 }
  },
  "by_language": { "c": {...}, "python": {...} },
  "tokens":  { "review_in": 4_120_000, "review_out": 320_000, "triage_in": 1_800_000 },
  "wallclock_seconds": 1742
}
```

### 1.5 Touched / new files

| File | Change |
|------|--------|
| `src/metis/cli/commands.py` | Add `bench` subcommand |
| New: `src/metis/bench/runner.py` | Orchestrate review+triage over manifest |
| New: `src/metis/bench/scoring.py` | Match findings to expectations, compute metrics |
| New: `src/metis/bench/manifest.py` | Manifest schema + loader |
| New: `tests/benchmarks/manifest.yaml` + `cases/` | Corpus |
| New: `.github/workflows/bench.yml` | Nightly run; PR-gated subset run |
| New: `docs/benchmarks.md` | Usage docs |

### 1.6 Acceptance criteria

- `metis bench --quick` runs a ~5-minute subset locally.
- `metis bench` emits the JSON above and a human-readable summary.
- CI runs the quick subset on every PR; full run nightly.
- Baseline numbers committed to `docs/benchmarks.md`.
- A regression in any per-CWE recall > 5 pts fails CI (overrideable with
  a labeled PR).

### 1.7 Risks & mitigations

- **Risk:** Corpus drift / overfitting prompts to the bench. **Mitigation:**
  Hold out 20% of cases as a private set, surface only aggregate scores.
- **Risk:** Token cost of nightly bench. **Mitigation:** Quick subset on PR,
  full run nightly only on `main`, allow `--max-cost` cap.
- **Risk:** Flaky line matching. **Mitigation:** Tolerance window + CWE
  equivalence classes documented in manifest.

---

## Task 2 — Function-Level Chunks + Caller/Callee Retrieval

**ID:** `fn-chunks-callers`
**Why second:** This is the keystone change. Today review sees a single
chunk in isolation and frequently cannot decide "is this input validated?"
Adding the actual called/calling functions to the prompt converts a large
class of guesses into answers. Also unblocks Task 3.

### 2.1 What changes

1. **Indexing:** For every supported language, emit *function-level* nodes
   alongside (or replacing) the current line-based `CodeSplitter` chunks.
2. **Sidecar:** Build `function_index.json` at index time, mapping
   qualified name → `{file, start_line, end_line, callees, signature}`.
3. **Review retrieval:** Before the LLM call, look up functions called by
   the snippet under review (1 hop) and 1 direct caller; prepend their
   bodies to `CONTEXT` (bounded by char budget).

### 2.2 New plugin hook

Add to `BaseLanguagePlugin`:

```python
def get_function_node_types(self) -> dict[str, list[str]]:
    """
    Tree-sitter node-type declarations used to extract function-level
    structure for indexing and retrieval.

    Returns a dict with keys:
      - "function": node types representing a function/method/closure
      - "call":     node types representing a call expression
      - "name":     child field/role to read for the function or call name
      - "import":   node types representing imports (optional)
    Default implementation returns {} -> falls back to line-based chunking.
    """
    return {}
```

Per-plugin overrides go in `plugins/python_plugin.py`,
`plugins/typescript_plugin.py`, `plugins/go_plugin.py`,
`plugins/rust_plugin.py`, `plugins/solidity_plugin.py`,
`plugins/c_plugin.py`, `plugins/cpp_plugin.py`,
`plugins/javascript_plugin.py`. (C-family can reuse the existing
extraction in `engine/analysis/c_family_ast.py`.)

### 2.3 Function index schema

```json
{
  "version": 1,
  "indexed_at": "2026-05-14T15:30:00Z",
  "functions": {
    "src/api/handlers.py::get_user": {
      "file": "src/api/handlers.py",
      "start_line": 42,
      "end_line": 58,
      "signature": "def get_user(request)",
      "language": "python",
      "callees": ["src/db/queries.py::fetch_user_data"],
      "callers": ["src/api/router.py::dispatch"]
    }
  },
  "by_name": {
    "get_user": ["src/api/handlers.py::get_user", "src/admin/users.py::get_user"]
  }
}
```

`by_name` lets the retriever resolve unqualified names from a snippet to
candidate definitions when multiple exist; review prompt includes all
candidates if disambiguation is uncertain (capped at 3).

### 2.4 Indexing flow change

`engine/indexing_service.py: index_codebase()`:

```
SimpleDirectoryReader → classify (code/docs)
  ├─ docs:  SentenceSplitter → embed  (unchanged)
  └─ code:  for each file:
              if plugin.get_function_node_types():
                  fn_nodes = extract_function_nodes(file, plugin)
                  emit fn_nodes (with metadata: name, callees, signature)
                  update function_index.json
              else:
                  fall back to line-based CodeSplitter (current behavior)
              embed → vector store
```

The function index is written to `<index_dir>/function_index.json`. It is
small (text only), versioned, and rebuilt incrementally when files change
(reuse existing diff-aware indexing in `IndexingService`).

### 2.5 Review retrieval change

`engine/graphs/review.py: review_node_retrieve()` currently performs
vector-similarity retrieval. Add a parallel pass:

1. Identify the function(s) that the current `snippet` belongs to (via
   `function_index` reverse lookup by file+line).
2. Collect callees (1 hop) and 1 direct caller for each.
3. Slice their bodies from disk with bounded char budget
   (e.g., 1500 chars per function, max 6 functions, max 8000 chars total).
4. Prepend a clearly-labeled `RELATED_FUNCTIONS:` section to `CONTEXT`,
   ahead of the existing vector-similarity context.

Order of context (most-relevant first, since LLM attention degrades):
`RELATED_FUNCTIONS` → `VECTOR_SIMILAR_CODE` → `DOCS`.

### 2.6 Touched / new files

| File | Change |
|------|--------|
| `src/metis/plugins/base.py` | New `get_function_node_types()` hook |
| `src/metis/plugins/*_plugin.py` (8 plugins) | Implement hook |
| `src/metis/engine/indexing_service.py` | Function-node extraction; sidecar write |
| `src/metis/engine/helpers.py: prepare_nodes_iter` | Yield function-shaped nodes |
| New: `src/metis/engine/code_index.py` | `function_index.json` read/write/lookup |
| `src/metis/engine/graphs/review.py: review_node_retrieve` | Add caller/callee pass |
| `src/metis/engine/graphs/utils.py: retrieve_text` | Hybrid merge w/ priority |
| `src/metis/engine/repository.py` | Expose function-index lookup |
| Tests under `tests/engine/test_code_index.py`, `tests/plugins/test_function_node_types.py` |

### 2.7 Acceptance criteria

- For each supported language, indexing a representative file produces
  function nodes for ≥90% of the language's defined functions.
- `function_index.json` round-trips and is rebuildable incrementally.
- A review of a function whose validation lives in a callee correctly
  picks up that callee in `RELATED_FUNCTIONS` (verified by unit tests +
  bench cases).
- Bench (Task 1) shows a positive recall delta on at least Python and
  JavaScript subsets.
- No more than +20% wallclock regression on a baseline review run, and
  no more than +15% token usage.

### 2.8 Risks & mitigations

- **Risk:** Function extraction is incorrect for some constructs (Python
  decorators, JS arrow functions, Go method receivers). **Mitigation:**
  Per-language unit tests with golden files; fall back to line chunking
  when extraction yields zero functions for a file.
- **Risk:** Char budget blowup. **Mitigation:** Hard caps + truncation
  with `... [truncated N lines] ...` markers.
- **Risk:** Naming collisions across files. **Mitigation:** `by_name`
  candidate list capped at 3; prefer same-file/same-package candidates
  via simple heuristic.
- **Risk:** Stale sidecar. **Mitigation:** File-mtime check on retrieval;
  on mismatch, re-extract the affected file lazily.

---

## Task 3 — Bounded Agentic Fetch-More-Context Loop

**ID:** `agentic-fetch`
**Why third:** Builds directly on Task 2's function index. Even with
caller/callee context, the LLM occasionally needs to reach further (a
sanitizer two hops away, a config constant, a base class). Letting it
*ask* for what it needs is far cheaper than always fetching everything.

### 3.1 What changes

Add an opt-in review mode where the LLM may invoke read-only tools
mid-review to fetch additional context, then revise its findings.

### 3.2 Tools (read-only, bounded)

| Tool | Args | Returns | Bounds |
|------|------|---------|--------|
| `get_function_body` | `name: str` | source of matching function(s) | max 3 candidates, max 4000 chars total |
| `get_callers` | `name: str` | list of `{file, line, snippet}` | max 5 callers, snippet ±5 lines |
| `grep_repo` | `pattern: str, path_glob?: str` | matching lines with file:line | max 30 hits, pattern length ≥3 chars, no `.*` only |

All tool outputs are passed through a **comment & string-literal
stripper** for the language of the source file, to reduce prompt-injection
surface from indexed third-party code. (Strings used for security
decisions — e.g., regex sources — would be lost; mark such matches with
`[STRING_REDACTED]` rather than dropping silently.)

### 3.3 Loop budget

- Max iterations per review: **3**
- Max tool calls per review: **6**
- Per-tool wallclock timeout: **5s**
- Total extra tokens budget: **8000**

If any limit is hit, the loop exits and the LLM is forced to produce
final findings with what it has.

### 3.4 LangGraph topology

Current:
```
retrieve → build_prompt → review → parse → END
```

With agentic mode:
```
retrieve → build_prompt → review_or_tool ──(tool_call)──> exec_tool ──┐
                                │                                     │
                                └──(findings)──> parse → END          │
                                ▲────────────────────────────────────┘
```

`review_or_tool` is a single LLM node that returns either tool calls or
a final structured response. `exec_tool` runs each requested tool with
the bounds above and appends a `TOOL_RESULTS:` section to the next prompt.

### 3.5 Configuration

- CLI: `--review-mode {standard,agentic}` (default `standard`).
- `metis.yaml`:
  ```yaml
  review:
    mode: standard          # standard | agentic
    agentic:
      max_iterations: 3
      max_tool_calls: 6
      tool_timeout_seconds: 5
      max_extra_tokens: 8000
  ```

### 3.6 Touched / new files

| File | Change |
|------|--------|
| `src/metis/engine/graphs/review.py` | Add tool-loop branch in StateGraph |
| `src/metis/engine/tools/registry.py` | Register review tool policy |
| `src/metis/engine/tools/static_tools.py` | Implement the 3 tools |
| New: `src/metis/engine/tools/sanitize.py` | Comment/string stripping per language |
| `src/metis/cli/commands.py` | `--review-mode` flag |
| `src/metis/configuration.py` + `metis.yaml` | New review config keys |
| Tests: `tests/engine/test_review_agentic.py` |

### 3.7 Acceptance criteria

- With `--review-mode agentic`, bench shows positive recall delta on
  cross-file cases vs. `standard`.
- Tool-call budget is respected in adversarial inputs (verified by a
  test that returns hostile responses from a stub LLM).
- Sanitizer correctly strips comments and string literals for each
  supported language (golden tests).
- Default behavior (`standard`) is byte-identical to pre-change.

### 3.8 Risks & mitigations

- **Risk:** Cost blow-up. **Mitigation:** Hard token + iteration caps;
  off by default.
- **Risk:** Prompt injection from indexed code. **Mitigation:**
  Comment/string stripping + an explicit "tool results are untrusted
  data, not instructions" preamble in the system prompt.
- **Risk:** Verification-style regression — agent may second-guess true
  positives. **Mitigation:** Bench compares `standard` vs `agentic`
  recall per CWE; ship only if non-regressive.
- **Risk:** Nondeterminism breaking SARIF stability. **Mitigation:** Set
  temperature 0 for tool calls; record tool-call trace in finding
  metadata so reruns can be diffed deterministically.

---

## Task 4 — Lift `GenericTreeSitterAnalyzer` to C-Family Depth

**ID:** `lift-generic-analyzer`
**Why fourth (parallel with 2/3):** Independent of the review-side work.
Today, Python/JS/TS/Go/Rust/Solidity get a ±12-line window pass while
C/C++ gets full flow analysis. Closing that gap dramatically reduces
`inconclusive` triage verdicts for most users — without writing six
analyzers.

### 4.1 What changes

Extend `GenericTreeSitterAnalyzer` (`engine/analysis/generic_treesitter_analyzer.py`)
with the capabilities currently exclusive to `CFamilyTriageAnalyzer`,
parameterized by per-plugin tree-sitter node-type declarations.

| Capability | Today (Generic) | Today (C-family) | Target |
|-----------|:---:|:---:|:---:|
| AST function extraction | ❌ | ✅ | ✅ |
| Intra-file caller/callee graph | ❌ | ✅ | ✅ |
| Definition / reference collection | ❌ | ✅ | ✅ |
| Multi-hop flow chain (depth 3) | ❌ | ✅ | ✅ |
| Cross-file symbol resolution | ❌ | ✅ | ✅ |

### 4.2 Configuration surface

The same plugin hook from Task 2 (`get_function_node_types`) is reused
and extended. Per-language node-type declarations live next to plugins:

```yaml
# plugins/plugins.yaml (new section per language)
analyzer:
  python:
    function_node_types:  ["function_definition"]
    method_node_types:    ["function_definition"]    # via class scope
    class_node_types:     ["class_definition"]
    call_node_types:      ["call"]
    call_name_field:      "function"
    parameter_node_types: ["parameters", "default_parameter", "typed_parameter"]
    import_node_types:    ["import_statement", "import_from_statement"]
    return_node_types:    ["return_statement"]
  javascript:
    function_node_types:  ["function_declaration", "function_expression",
                           "arrow_function", "method_definition"]
    call_node_types:      ["call_expression"]
    call_name_field:      "function"
    import_node_types:    ["import_statement", "import_clause"]
  go:
    function_node_types:  ["function_declaration", "method_declaration"]
    call_node_types:      ["call_expression"]
    call_name_field:      "function"
    import_node_types:    ["import_declaration", "import_spec"]
  # rust, typescript, solidity ...
```

The analyzer reads these declarations (no per-language Python code).

### 4.3 Implementation

Refactor existing C-family helpers into a language-agnostic core where
possible:

- `c_family_ast.py: _collect_functions/_collect_definitions/_collect_references/_collect_calls`
  → extract a shared `treesitter_ast.py` core that takes a config dict.
- `c_family_flow.py: _build_structured_flow_chain` → generalize signature
  to accept the analyzer's call graph and a depth cap; keep C/C++
  specialization (macro-aware) as a subclass override.
- `c_family_xref.py: _resolve_unresolved_hops_across_codebase` →
  generalize to use the shared call graph + grep fallback.

`GenericTreeSitterAnalyzer.collect_evidence()` becomes:

```
parse → extract_functions → build_intra_file_callgraph
      → build_flow_chain(depth=3) → resolve_unresolved_hops_across_codebase
      → assemble AnalyzerEvidence
```

`CFamilyTriageAnalyzer` retains its macro-semantics and preprocessor
specifics as overrides, but most code paths converge.

### 4.4 Touched / new files

| File | Change |
|------|--------|
| `src/metis/engine/analysis/generic_treesitter_analyzer.py` | Implement extended pipeline |
| New: `src/metis/engine/analysis/treesitter_ast.py` | Shared AST helpers extracted from `c_family_ast.py` |
| New: `src/metis/engine/analysis/flow_common.py` | Generalized flow chain |
| New: `src/metis/engine/analysis/xref_common.py` | Generalized cross-file resolution |
| `src/metis/engine/analysis/c_family_*.py` | Reduce to deltas over the common core |
| `src/metis/plugins/plugins.yaml` | Per-language `analyzer:` sections |
| `src/metis/plugins/base.py` | Loader for `analyzer:` config |
| Tests: `tests/engine/analysis/test_generic_*` per language |

### 4.5 Acceptance criteria

- `inconclusive` triage rate on the bench (Task 1) for non-C languages
  drops by at least 30% absolute.
- C/C++ triage results are unchanged on the bench (regression guard).
- Per-language smoke tests for function extraction, intra-file call
  graph, and a 2-hop wrapper resolution case.

### 4.6 Risks & mitigations

- **Risk:** Tree-sitter grammar differences cause silent miscounts.
  **Mitigation:** Per-language golden tests; analyzer logs a structural
  summary (function count, call count) for spot-checking.
- **Risk:** Refactoring C-family analyzer breaks current users.
  **Mitigation:** Preserve `CFamilyTriageAnalyzer` public surface;
  refactor incrementally with full existing test pass at each step.
- **Risk:** Cross-file resolution is slow on monorepos.
  **Mitigation:** Bound by hop count and per-symbol candidate cap;
  reuse function index from Task 2 if available (graph lookup is
  O(1) vs. grep O(n)).

---

## Task 5 — Adaptive Evidence Budget + Multi-Hop Symbol Resolution

**ID:** `triage-deepening`
**Why fifth (parallel-friendly):** Cheapest of the five; directly
reduces "inconclusive" verdicts caused by wrappers and obligation misses.
Independent of the others — but compounds with Task 4.

### 5.1 What changes

1. Replace fixed triage constants with an `EvidenceBudget` selectable
   at runtime; auto-retry with a deeper budget when obligations are
   unmet, before falling back to `inconclusive`.
2. Extend `_gather_symbol_definition_hits` in
   `engine/graphs/triage/evidence_tools.py` to follow wrapper chains for
   2–3 hops, recording the resolution chain.
3. Add a conditional re-collect edge to the triage StateGraph.

### 5.2 EvidenceBudget

```python
# engine/graphs/triage/budget.py
@dataclass(frozen=True)
class EvidenceBudget:
    name: str
    max_sections: int
    max_chars: int
    max_symbol_terms: int
    max_followup_hits: int
    max_symbol_hops: int

SIMPLE   = EvidenceBudget("simple",   16,  8000, 2, 6,  1)
STANDARD = EvidenceBudget("standard", 28, 14000, 4, 12, 2)  # current defaults
DEEP     = EvidenceBudget("deep",     48, 24000, 8, 24, 3)
```

`engine/graphs/triage/constants.py` keeps its constants for backward
compatibility but they become the values inside `STANDARD`.

### 5.3 Multi-hop symbol resolution

Today `_gather_symbol_definition_hits()` resolves each symbol to its
definition (one grep). Extend so that, when a definition is itself a
thin wrapper (e.g., function body is a single call expression delegating
to another symbol), the analyzer resolves that next symbol too, up to
`budget.max_symbol_hops`.

Detection of "thin wrapper": tree-sitter parse of the definition body
yields ≤2 statements and one of them is a `call_expression` whose name
differs from the wrapper. This avoids unbounded chains while catching
the dominant case (`safe_alloc → malloc`).

Record the chain in evidence metadata:

```json
{
  "symbol": "safe_alloc",
  "resolution_chain": [
    {"symbol": "safe_alloc", "file": "src/util/alloc.c", "line": 12},
    {"symbol": "malloc",     "file": "<libc>",            "line": null}
  ]
}
```

Adjudication can use this chain (e.g., to keep a finding `valid` when
the wrapper resolves to a known-dangerous primitive).

### 5.4 Adaptive retry in the StateGraph

`engine/graphs/triage/graph.py` currently:
```
retrieve → collect_evidence → llm_decide → adjudicate → END
```

Becomes:
```
retrieve → collect_evidence(STANDARD) ──(obligations met?)──┐
                                                yes         │
                                                            ▼
                                          llm_decide → adjudicate → END
                                                no
                                                │
                                                ▼
                       collect_evidence(DEEP) → llm_decide → adjudicate → END
```

A per-finding hard cap (e.g., max one re-collect, max +20s wallclock)
prevents runaway cost on adversarial inputs.

### 5.5 Touched / new files

| File | Change |
|------|--------|
| New: `src/metis/engine/graphs/triage/budget.py` | `EvidenceBudget` dataclass + presets |
| `src/metis/engine/graphs/triage/constants.py` | Defaults wrapped by `STANDARD` |
| `src/metis/engine/graphs/triage/evidence.py` | Accept budget; honor caps |
| `src/metis/engine/graphs/triage/evidence_tools.py` | Multi-hop resolution + chain recording |
| `src/metis/engine/graphs/triage/graph.py` | Conditional re-collect edge |
| `src/metis/engine/graphs/triage/adjudication.py` | Use resolution chain when present |
| Tests: `tests/engine/triage/test_budget.py`, `test_wrapper_resolution.py` |

### 5.6 Acceptance criteria

- Bench (Task 1) shows triage `inconclusive` rate drops by at least 25%
  absolute on the non-C subset, with no precision loss in adjudicated
  verdicts.
- A unit test verifies `safe_alloc → malloc` chain is recorded.
- Per-finding wallclock cap enforced under a stub that always returns
  obligation misses.

### 5.7 Risks & mitigations

- **Risk:** Deep budget burns tokens on findings that are genuinely
  unresolvable. **Mitigation:** Hard cap on retries + telemetry.
- **Risk:** Wrapper detection mis-classifies real logic as a wrapper.
  **Mitigation:** Conservative heuristic (≤2 statements + single call);
  unit-tested; opt-in second-hop only when first hop is a thin wrapper.

---

## Sequencing & Dependencies

```
Task 1: eval-harness  ────────────────────────────────┐
                                                      │
        ├──> Task 2: fn-chunks-callers ──> Task 3: agentic-fetch
        │
        ├──> Task 4: lift-generic-analyzer    (parallel with 2/3)
        │
        └──> Task 5: triage-deepening         (parallel; small)
```

- **Wave A:** Task 1.
- **Wave B (parallel):** Tasks 2, 4, 5.
- **Wave C:** Task 3 (after 2 lands).

Each task lands behind its own flag/mode where applicable, so partial
delivery does not destabilize the default pipeline.

---

## Cross-Cutting Concerns

These apply to every task and should be considered during code review.

### Determinism & SARIF stability
All new behavior must keep `temperature=0` paths and stable finding IDs.
Where nondeterminism is unavoidable (Task 3 tool loops), record the
trace in finding metadata so reruns can be diffed.

### Cost & telemetry
Every new code path emits token-cost and wallclock counters. The bench
report (Task 1) tracks them per task so we can see regressions early.

### Backward compatibility
- Existing `metis.yaml`, CLI flags, and SARIF output remain valid.
- Function index sidecar is a versioned additive artifact; absence
  triggers fall-back to current behavior.
- All new modes default to off until benchmarks confirm gains.

### Prompt-injection hygiene
With Tasks 2 and 3 piping more code into LLM prompts (including
third-party code), include a sanitizer pass that strips/marks comments
and string literals before they are concatenated into prompts, and a
system-prompt preamble explicitly labeling fetched content as untrusted
data.

### Test code vs production code
A simple file-path heuristic (`tests/`, `_test.go`, `*.spec.ts`, etc.)
should be respected by both review and triage to avoid wasting
attention on intentionally-vulnerable fixtures. Optional: a per-plugin
override.

### Migration
First time `metis index` runs after Task 2, the function index sidecar
is built incrementally. No user action required. Document in
`docs/benchmarks.md` and the changelog.
