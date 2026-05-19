# Metis Improvement Proposals: Towards 50× Better Vulnerability Detection

> **Author:** Arm Product Security Team
> **Status:** Proposal
> **Scope:** Indexing, Review, and Triage pipelines

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture Baseline](#2-current-architecture-baseline)
3. [Tier 1 — Foundational Improvements](#3-tier-1--foundational-improvements)
   - 3.1 [Semantic Code Graph Index](#31-semantic-code-graph-index)
   - 3.2 [Multi-Pass Review Pipeline](#32-multi-pass-review-pipeline)
   - 3.3 [Cross-File Data Flow Tracing](#33-cross-file-data-flow-tracing)
4. [Tier 2 — Significant Impact](#4-tier-2--significant-impact)
   - 4.1 [Security-Focused Retrieval](#41-security-focused-retrieval)
   - 4.2 [Rich Triage Analysis for All Languages](#42-rich-triage-analysis-for-all-languages)
   - 4.3 [Confidence Calibration & Finding Deduplication](#43-confidence-calibration--finding-deduplication)
   - 4.4 [Iterative Evidence Deepening for Triage](#44-iterative-evidence-deepening-for-triage)
5. [Tier 3 — Refinements](#5-tier-3--refinements)
   - 5.1 [Agentic Review Mode](#51-agentic-review-mode)
   - 5.2 [SARIF-Integrated Feedback Loop](#52-sarif-integrated-feedback-loop)
   - 5.3 [Incremental / Diff-Aware Review](#53-incremental--diff-aware-review)
   - 5.4 [Multi-Model Ensemble](#54-multi-model-ensemble)
   - 5.5 [Pre-Review Static Analysis Integration](#55-pre-review-static-analysis-integration)
6. [Improvement × Impact Matrix](#6-improvement--impact-matrix)
7. [Suggested Implementation Order](#7-suggested-implementation-order)

---

## 1. Executive Summary

Metis is an AI-powered security code review tool that combines LLM reasoning with
RAG-based context retrieval and deterministic triage guardrails. After a thorough
analysis of the indexing, review, and triage pipelines, we identified 12 concrete
improvements that can compound to achieve roughly 50× better vulnerability
detection. This document details each improvement with technical specifics
grounded in the current codebase architecture.

The improvements are tiered by impact:

- **Tier 1 (Foundational):** Semantic code graph, multi-pass review, cross-file
  data flow tracing — these address the root limitations that cause entire
  vulnerability classes to be missed today.
- **Tier 2 (Significant):** Security-focused retrieval, rich language analyzers,
  confidence calibration, iterative evidence deepening — these multiply the
  effectiveness of Tier 1 foundations.
- **Tier 3 (Refinements):** Agentic review, feedback loops, diff-aware review,
  multi-model ensemble, static analysis integration — polish and operational
  excellence.

---

## 2. Current Architecture Baseline

### 2.1 Indexing Pipeline

**Entry point:** `IndexingService.index_codebase()` in `engine/indexing_service.py`

The current indexing flow:

1. `SimpleDirectoryReader` recursively loads all source and documentation files
   matching configured extensions.
2. Files are classified as *code* or *docs* based on extension.
3. Code files are split using Tree-sitter `CodeSplitter` (configured per language
   plugin with `chunk_lines`, `chunk_lines_overlap`, `max_chars`).
4. Documentation files are split using `SentenceSplitter`.
5. All nodes are embedded via `text-embedding-3-large` and stored in two separate
   `VectorStoreIndex` instances (code and docs), backed by ChromaDB or pgvector.

**Current limitations:**
- Chunks are line-based, not semantic. A function can be split mid-body across
  two chunks, losing coherence.
- No relationships between chunks are captured — call graphs, data flows, imports
  are invisible to the index.
- Chunk metadata contains only `file_name`; no security-relevant tags.

### 2.2 Review Pipeline

**Entry point:** `ReviewService.review_file()` → `ReviewGraph.review()` in
`engine/graphs/review.py`

The current review flow (LangGraph `StateGraph`):

```
retrieve → build_prompt → LLM (structured output) → parse
```

1. **Retrieve:** Query the code and docs vector stores for context relevant to the
   file being reviewed.
2. **Build prompt:** Compose a system prompt from language-specific templates
   (`security_review_file`, `security_review_checks`, `security_review_report`)
   plus the retrieved context, original file, and schema instructions.
3. **LLM call:** Send to the model (`gpt-5.5`, temperature 0.0) via
   `with_structured_output(ReviewResponseModel)` with a fallback to
   `StrOutputParser` if structured output fails.
4. **Parse:** Normalize the response, enrich with metadata (line numbers,
   snippets), and return.

For large files, the snippet is split via `split_snippet()` and each chunk is
reviewed independently. Full-codebase review (`review_code`) runs all files in
parallel via `ThreadPoolExecutor(max_workers=5)`.

**Current limitations:**
- Each file chunk is reviewed in complete isolation — no cross-file reasoning.
- Single LLM pass with no iterative deepening or self-verification.
- RAG context is chosen by text similarity, not by semantic relevance to the
  security question.

### 2.3 Triage Pipeline

**Entry point:** `TriageService.triage_sarif_payload()` →
`TriageGraph.triage()` in `engine/graphs/triage/graph.py`

The current triage flow (LangGraph `StateGraph`):

```
retrieve → collect_evidence → LLM decision → deterministic adjudication
```

1. **Retrieve:** Build a purpose-built retrieval query from the SARIF finding
   metadata and fetch deduped context from vector stores.
2. **Collect evidence:** Deterministic evidence assembly:
   - Analyzer-level evidence (C/C++ flow analysis via `CFamilyTriageAnalyzer` or
     generic structural analysis via `GenericTreeSitterAnalyzer`).
   - File-local context windows via `sed`.
   - Tree-sitter scope symbols near the reported line.
   - Symbol definition probing via bounded `grep` (local → fallback paths).
   - C/C++ macro definition and semantics resolution.
   - Hit context windows around grep matches.
   - Evidence obligation derivation and coverage computation.
3. **LLM decision:** A single structured output call for
   `{status, reason, evidence, resolution_chain, unresolved_hops}`.
4. **Deterministic adjudication:** Post-LLM rules that enforce:
   - Contradiction signals → force `invalid`.
   - Critical unresolved hops → force `inconclusive`.
   - Insufficient evidence for `valid` → downgrade to `inconclusive`.
   - Invalid-to-valid upgrades → blocked.
   - Obligation coverage checks → downgrade when missing.

**Current limitations:**
- Evidence collection is bounded to `EVIDENCE_PACK_MAX_CHARS = 14000` and
  `MAX_SECTIONS = 28`, which may be insufficient for complex findings.
- Non-C/C++ languages use `GenericTreeSitterAnalyzer`, which only does a
  lightweight structural pass (no real flow analysis, no call chain following).
- Symbol resolution is single-hop and grep-based — wrapper chains,
  polymorphism, and callbacks are not followed.

---

## 3. Tier 1 — Foundational Improvements

These improvements address root limitations that cause entire vulnerability
classes to be missed. Combined, they have the potential for 10–20× improvement
in detection capability.

### 3.1 Semantic Code Graph Index

**Problem:**
The current index treats code as flat text. `IndexingService.index_prepare_nodes_iter()`
splits code into line-based chunks via `CodeSplitter(language=..., chunk_lines=...,
chunk_lines_overlap=..., max_chars=...)`. This means:
- A 60-line function may be split across two chunks, losing its coherence.
- Two functions in the same file that call each other have no recorded relationship.
- When the review pipeline retrieves context, it gets text-similar chunks, not
  functionally-relevant code.

**Proposed solution:**
Build a **code knowledge graph** at index time alongside (or replacing) the flat
chunk index:

#### 3.1.1 Function-Level Semantic Nodes

At index time, use Tree-sitter (already available via `TreeSitterRuntime`) to
extract **function-level nodes** instead of arbitrary line-based chunks:

```python
@dataclass
class FunctionNode:
    file_path: str
    name: str
    signature: str
    body: str
    start_line: int
    end_line: int
    docstring: str
    language: str
    calls: list[str]          # function names called within body
    parameters: list[str]     # parameter names and types
    return_type: str
    security_tags: list[str]  # auto-classified tags
```

Tree-sitter already collects `function_definition`, `function_declaration`, and
`method_definition` nodes (see `c_family_ast.py: _collect_functions()`). Extend
this to all languages at index time rather than only during triage.

#### 3.1.2 Relationship Edges

For each function node, extract edges:

| Edge Type | Source | Target | Extraction Method |
|-----------|--------|--------|-------------------|
| `CALLS` | Function A | Function B | Tree-sitter call expression nodes |
| `IMPORTS` | File A | File B | `import`/`#include`/`require` statements |
| `INHERITS` | Class A | Class B | Tree-sitter class heritage nodes |
| `RETURNS_TO` | Function A | Caller site | Reverse of `CALLS` |
| `DATA_FLOWS_TO` | Param of A | Arg in call to B | Parameter/argument position matching |

#### 3.1.3 Security Annotations

Auto-tag each function node with security-relevant metadata using pattern matching
on the function name, body, and called functions:

| Tag | Detection Pattern |
|-----|-------------------|
| `INPUT_BOUNDARY` | HTTP handler, CLI arg parser, `read()`, `recv()`, `input()`, deserialization |
| `AUTH_CHECK` | Functions named `*auth*`, `*login*`, `*verify*`, `*token*` |
| `CRYPTO_OP` | `encrypt`, `decrypt`, `hash`, `sign`, `verify`, `hmac` |
| `MEMORY_OP` | `malloc`, `free`, `realloc`, `alloca`, `mmap` (C/C++) |
| `FILE_IO` | `open`, `read`, `write`, `unlink`, path manipulation |
| `NETWORK_IO` | `socket`, `connect`, `send`, `recv`, HTTP client calls |
| `COMMAND_EXEC` | `exec`, `system`, `popen`, `subprocess`, `eval` |
| `SQL_QUERY` | `execute`, `query`, `cursor`, ORM query builders |
| `PRIVILEGE` | `setuid`, `setgid`, capability manipulation |

#### 3.1.4 Storage

Store the graph as additional metadata in the existing vector store:
- Each function node is embedded with its signature + body + docstring.
- Metadata fields include `calls`, `called_by`, `imports`, `security_tags`.
- The vector store supports metadata filtering, enabling queries like
  "find all functions tagged `INPUT_BOUNDARY` that call functions tagged
  `SQL_QUERY`".

Alternatively, store the graph in a lightweight graph structure (adjacency lists
in JSON) alongside the vector index, loaded into memory at review time.

#### 3.1.5 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/indexing_service.py` | Add graph extraction pass after `prepare_nodes_iter()` |
| `engine/helpers.py: prepare_nodes_iter()` | Yield function-level nodes alongside chunk nodes |
| `plugins/base.py: BaseLanguagePlugin` | Add `get_function_extractor()` method |
| `engine/repository.py` | Add graph query methods |
| `vector_store/base.py` | Add graph storage/retrieval interface |

#### 3.1.6 Expected Impact

- **Direct:** RAG retrieval becomes functionally-aware — when reviewing function A,
  the system can retrieve the implementation of functions A calls, not just
  text-similar code.
- **Enabling:** This is the foundation for cross-file data flow tracing (§3.3),
  security-focused retrieval (§4.1), and agentic review (§5.1).
- **Estimated improvement:** 3–5× on its own; enables 10×+ when combined with
  cross-file tracing.

---

### 3.2 Multi-Pass Review Pipeline

**Problem:**
The current review is a single LLM call per file chunk
(`ReviewGraph.review()` → `review_node_llm()`). The LLM sees the file
content + RAG context and must identify all vulnerabilities in one pass.

This misses vulnerabilities that require:
- Understanding which functions are entry points (attack surface).
- Following data from entry points through call chains to dangerous sinks.
- Verifying whether a seemingly vulnerable pattern is actually exploitable given
  the surrounding guards and validations.

Human security reviewers don't work this way — they first scan for attack
surface, then zoom into suspicious paths, then verify each finding.

**Proposed solution:**
Replace the current single-node `review` step in the LangGraph `StateGraph` with
a **3-phase pipeline**:

#### 3.2.1 Phase 1: Reconnaissance

Goal: Identify the attack surface of the codebase.

```
reconnaissance → [attack_surface_map]
```

For each file (or group of related files):
- Identify **entry points**: HTTP handlers, CLI parsers, message consumers,
  signal handlers, exported API functions.
- Identify **trust boundaries**: where external input enters the system,
  where privilege levels change, where data crosses process/network boundaries.
- Identify **dangerous sinks**: SQL queries, command execution, file operations,
  memory operations, crypto operations, deserialization.
- Produce an **attack surface map**: a ranked list of (entry_point, sink)
  pairs that represent potential vulnerability paths.

This phase uses the code graph index (§3.1) for structural analysis and a
lightweight LLM call for classification. The prompt focuses entirely on
identification, not vulnerability analysis.

#### 3.2.2 Phase 2: Deep Analysis

Goal: For each attack surface path, collect all relevant code and analyze
the complete data flow.

```
for each (entry_point, sink) in attack_surface_map:
    collect_path_code → deep_analysis → [findings]
```

For each identified path:
1. **Collect path code:** Use the code graph to gather all functions along
   the path from entry point to sink. Include callers, callees, and any
   validation/sanitization functions in between.
2. **Deep analysis:** Present the complete path to the LLM with a focused
   prompt: "Analyze this data flow path for vulnerabilities. The data enters
   at [entry_point] and reaches [sink]. Here is the complete code along the
   path."
3. The LLM can reason about the full chain — whether inputs are validated,
   whether sanitization is correct, whether type confusion is possible, etc.

This phase produces higher-quality findings because the LLM sees the complete
context instead of isolated chunks.

#### 3.2.3 Phase 3: Verification

Goal: Validate each finding against the actual code to reduce false positives.

```
for each finding in findings:
    verification → [confirmed_finding | dismissed]
```

For each finding from Phase 2:
1. **Challenge prompt:** Present the finding to a second LLM call with the
   instruction: "A security reviewer claims this code has the following
   vulnerability: [finding]. Given the complete code context below, evaluate
   whether this vulnerability is actually exploitable. Consider all guards,
   validations, type constraints, and environmental factors."
2. **Verdict:** The verification call returns a confidence adjustment.
   Findings that survive verification get boosted confidence; those that
   are challenged get reduced confidence or are dismissed.

#### 3.2.4 New LangGraph Architecture

The current `ReviewGraph` StateGraph:

```
retrieve → build_prompt → review → parse → END
```

Becomes:

```
retrieve → reconnaissance → build_attack_surface →
  [for each path] → collect_path → deep_analysis →
  [for each finding] → verify → parse → END
```

The new graph is wider (parallel paths) but each path is deeper (more LLM
reasoning per finding). Total LLM calls increase, but finding quality
improves dramatically.

#### 3.2.5 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/graphs/review.py` | Replace single `review_node_llm` with 3-phase pipeline |
| `engine/graphs/types.py` | Add `ReconState`, `DeepAnalysisState`, `VerificationState` |
| `engine/review_service.py` | Adapt `review_file()` and `review_code()` for multi-pass |
| `plugins/plugins.yaml` | Add `reconnaissance_prompt`, `deep_analysis_prompt`, `verification_prompt` |
| `engine/graphs/schemas/review.py` | Add schemas for each phase output |

#### 3.2.6 Cost Management

Multi-pass review uses more LLM calls. Mitigations:
- Phase 1 (reconnaissance) can use a cheaper/faster model.
- Phase 2 (deep analysis) uses the full model but only for identified paths —
  not every line of code.
- Phase 3 (verification) is optional and can be controlled by a flag.
- A `--review-depth` flag: `shallow` (current behavior), `standard`
  (recon + deep), `thorough` (all 3 phases).

#### 3.2.7 Expected Impact

- **Direct:** Catches cross-function and cross-file vulnerabilities that single-pass
  review cannot see. Reduces false positives through verification.
- **Estimated improvement:** 5–8× on its own; compounds with code graph (§3.1)
  for 10–15×.

---

### 3.3 Cross-File Data Flow Tracing

**Problem:**
The most critical vulnerability classes — SQL injection, command injection,
XSS, path traversal, SSRF — are inherently cross-file: user input enters in
one file and reaches a dangerous sink in another. The current review pipeline
reviews each file independently, making these vulnerabilities invisible.

The triage pipeline has some cross-file capability via grep-based symbol
probing (`_gather_symbol_definition_hits()`) and C/C++ cross-file xref
(`CFamilyXrefMixin._resolve_unresolved_hops_across_codebase()`), but:
- These are only used during triage (after findings are already generated),
  not during review (when findings should be generated).
- They are text-based (grep), not semantic.
- They follow only 1 hop for non-C languages.

**Proposed solution:**
Build lightweight **inter-procedural taint tracking** that operates at review
time:

#### 3.3.1 Source/Sink/Sanitizer Classification

At index time (using the code graph from §3.1), classify functions:

| Category | Examples | Detection |
|----------|----------|-----------|
| **Source** (user input enters) | HTTP request params, `input()`, `read()`, `recv()`, env vars, file reads, CLI args | Name/signature patterns + call graph position |
| **Sink** (dangerous operations) | `execute()`, `system()`, `eval()`, `innerHTML`, `open()`, `write()`, `query()` | Name patterns + known dangerous APIs |
| **Sanitizer** (input cleaned) | `escape()`, `sanitize()`, `validate()`, `encode()`, type casting, allowlist checks | Name patterns + return-type analysis |

#### 3.3.2 Taint Propagation Rules

Define how taint flows through code:

1. **Direct propagation:** If function A receives tainted input as parameter `p`
   and passes `p` (or a derivative) to function B, the corresponding parameter
   of B is tainted.
2. **Return propagation:** If function A returns tainted data, any variable
   assigned the return value of A is tainted.
3. **Kill rules:** If tainted data passes through a sanitizer, the taint is
   removed (conditional on the sanitizer being appropriate for the sink type).
4. **Collection propagation:** If tainted data is stored in a data structure
   (dict, list, object field), the structure becomes tainted.

#### 3.3.3 Path Enumeration

At review time, for each source in the codebase:

1. Start from the source function.
2. Follow the call graph forward, propagating taint through parameters and
   return values.
3. At each hop, check if a sink is reached.
4. If a sink is reached, check if any sanitizer was applied between source
   and sink.
5. If no sanitizer (or an inappropriate sanitizer) was applied, record the
   path as a potential vulnerability.

The enumeration is bounded by depth (configurable, default 6 hops) and
width (max paths per source, default 20).

#### 3.3.4 Path Presentation to LLM

For each identified taint path, present the complete chain to the LLM:

```
TAINT PATH: HTTP request parameter "user_id" → possible SQL injection

Source: src/api/handlers.py:42 - get_user(request)
  → request.args.get("user_id") is user-controlled

Hop 1: src/api/handlers.py:45 - calls fetch_user_data(user_id)
  [code of fetch_user_data]

Hop 2: src/db/queries.py:18 - fetch_user_data calls build_query(user_id)
  [code of build_query]

Sink: src/db/queries.py:23 - cursor.execute(query)
  [code around the execute call]

No sanitizer detected between source and sink.

QUESTION: Is user_id used in a way that could lead to SQL injection?
Consider parameterized queries, type casting, allowlists, or other
mitigations that may be present in the code.
```

This gives the LLM exactly the right context to reason about the
vulnerability with high accuracy.

#### 3.3.5 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/indexing_service.py` | Extract source/sink/sanitizer classifications at index time |
| `engine/review_service.py` | Add taint path enumeration before LLM review |
| `engine/graphs/review.py` | Add taint-path-aware prompt construction |
| `plugins/base.py` | Add `get_source_patterns()`, `get_sink_patterns()`, `get_sanitizer_patterns()` per language |
| New: `engine/taint/` | Taint propagation engine, path enumeration, path presentation |

#### 3.3.6 Expected Impact

- **Direct:** Catches entire vulnerability classes that are invisible to
  single-file review: SQL injection, XSS, command injection, path traversal,
  SSRF, insecure deserialization, IDOR.
- **This is the single highest-impact improvement** because these are the
  most common and most critical vulnerability types in real-world applications.
- **Estimated improvement:** 5–10× on its own for web/API codebases.

---

## 4. Tier 2 — Significant Impact

These improvements multiply the effectiveness of Tier 1 foundations. Combined,
they add 5–10× improvement.

### 4.1 Security-Focused Retrieval

**Problem:**
The current retrieval system (`review_node_retrieve()` in
`engine/graphs/review.py` and `triage_node_retrieve()` in
`engine/graphs/triage/retrieval.py`) uses generic text similarity to find
relevant context. The query for review is:

```python
context_prompt_template = "You are a senior software engineer and your task is
to explain what the following FILE does..."
```

This retrieves text-similar code, which may not be the most
security-relevant context. When reviewing a password validation function,
the retrieval might return a comment about passwords rather than the actual
authentication flow that calls the function.

**Proposed solution:**

#### 4.1.1 Hybrid Retrieval: Vector + Graph

When reviewing a function, retrieve context using two strategies and merge:

1. **Vector similarity** (current): Find text-similar chunks.
2. **Graph traversal** (new): From the code graph (§3.1), collect:
   - Direct callers of the function (who uses this code?)
   - Direct callees (what does this code depend on?)
   - Functions sharing the same data structures (what else touches this data?)
   - Functions with matching security tags (what other auth/crypto/IO code exists?)

Merge results with priority: graph-adjacent code > vector-similar code from
same module > vector-similar code from other modules.

#### 4.1.2 Security-Aware Query Expansion

Expand the retrieval query with security-relevant terms:

- If the code contains `password`, also retrieve code related to `hash`,
  `salt`, `bcrypt`, `compare`, `validate`.
- If the code contains `query`, also retrieve code related to `sanitize`,
  `parameterize`, `escape`, `bind`.
- If the code contains `file_path`, also retrieve code related to
  `normalize`, `validate_path`, `realpath`, `chroot`.

This makes the LLM see relevant mitigations and validations that may exist
elsewhere in the codebase.

#### 4.1.3 Priority Weighting

Not all retrieved context is equally useful. Rank by security relevance:

| Priority | Context Type | Rationale |
|----------|-------------|-----------|
| 1 (highest) | Input validation for the function's parameters | Directly relevant to exploitability |
| 2 | Callers that pass user-controlled data | Shows how inputs arrive |
| 3 | Callees that perform dangerous operations | Shows what happens downstream |
| 4 | Configuration and policy code | Shows intended security constraints |
| 5 (lowest) | General utility code | May provide background but rarely decisive |

#### 4.1.4 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/graphs/review.py: review_node_retrieve()` | Replace with hybrid retrieval |
| `engine/graphs/utils.py: retrieve_text()` | Add graph-based retrieval path |
| `engine/graphs/triage/retrieval.py` | Add graph-based retrieval for triage |
| `vector_store/base.py` | Add metadata-filtered queries |

#### 4.1.5 Expected Impact

- **Direct:** LLM sees functionally-relevant context instead of text-similar
  noise. Particularly impactful for understanding whether sanitization exists
  elsewhere in the codebase.
- **Estimated improvement:** 2–3× improvement in review accuracy.

---

### 4.2 Rich Triage Analysis for All Languages

**Problem:**
C/C++ triage uses `CFamilyTriageAnalyzer` which performs deep analysis:
- Full AST indexing (`_index_tree`, `_collect_definitions`, `_collect_references`,
  `_collect_calls`, `_collect_functions`)
- Structured flow chain building (`_build_structured_flow_chain`) with source →
  check → sink hops, caller collection, callee traversal up to depth 3
- Cross-file symbol resolution (`_resolve_unresolved_hops_across_codebase`)
- Macro semantics analysis (`_analyze_macro_semantics`)

All other languages (Python, JS, Go, Rust, TypeScript, Solidity) use
`GenericTreeSitterAnalyzer` which only does:
- Extract a ±12-line window around the reported line
- Regex-extract call names from the window
- Produce a single-hop flow chain with no caller/callee analysis

This means Python, JavaScript, and other commonly-used languages get
dramatically worse triage quality than C/C++.

**Proposed solution:**
Build language-specific analyzers for each supported language that match
or approach the C/C++ analyzer's depth:

#### 4.2.1 Analyzer Capabilities by Language

| Capability | C/C++ (current) | Generic (current) | Target (proposed) |
|-----------|:---:|:---:|:---:|
| AST-based function extraction | ✅ | ❌ | ✅ |
| Caller/callee graph (intra-file) | ✅ | ❌ | ✅ |
| Definition/reference collection | ✅ | ❌ | ✅ |
| Multi-hop flow chain | ✅ (depth 3) | ❌ (single hop) | ✅ (depth 3) |
| Cross-file symbol resolution | ✅ | ❌ | ✅ |
| Language-specific patterns | ✅ (macros, includes) | ❌ | ✅ (see below) |

#### 4.2.2 Language-Specific Patterns

| Language | Patterns to Handle |
|----------|--------------------|
| **Python** | Decorators (`@app.route`), class inheritance, `__init__`/`__new__`, `import` chains, `*args`/`**kwargs` propagation, context managers |
| **JavaScript/TypeScript** | Callbacks/promises/async-await, closures, prototype chains, `require`/`import` module resolution, event emitters |
| **Go** | Goroutine launches, defer statements, interface implementations, error return pattern, channel operations |
| **Rust** | Trait implementations, `unsafe` blocks, ownership/borrowing patterns, `Result`/`Option` unwrap chains |
| **Solidity** | Reentrancy patterns, `delegatecall`, storage layout, modifier chains, event emission |

#### 4.2.3 Implementation Approach

Rather than building each analyzer from scratch, create a shared base class
that extends `GenericTreeSitterAnalyzer` with the core capabilities
(function extraction, caller/callee graph, definition/reference collection,
multi-hop flow) and then add language-specific overrides:

```python
class EnhancedTreeSitterAnalyzer(GenericTreeSitterAnalyzer):
    """Base analyzer with C-family-like depth for any tree-sitter language."""

    def collect_evidence(self, request: AnalyzerRequest) -> AnalyzerEvidence:
        # 1. Parse with tree-sitter (inherited)
        # 2. Extract functions (new - language-aware node types)
        # 3. Build intra-file call graph (new)
        # 4. Build flow chain (new - adapted from CFamilyFlowMixin)
        # 5. Collect definitions and references (new)
        # 6. Apply language-specific patterns (override point)
        ...

class PythonTriageAnalyzer(EnhancedTreeSitterAnalyzer):
    def _get_function_node_types(self):
        return {"function_definition", "class_definition"}

    def _get_import_patterns(self):
        return {"import_statement", "import_from_statement"}
```

#### 4.2.4 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/analysis/generic_treesitter_analyzer.py` | Extend with shared rich analysis capabilities |
| `plugins/python_plugin.py` | Override `get_triage_analyzer_factory()` to return Python-specific analyzer |
| `plugins/typescript_plugin.py` | Override for TypeScript/JavaScript |
| `plugins/go_plugin.py` | Override for Go |
| `plugins/rust_plugin.py` | Override for Rust |
| `plugins/solidity_plugin.py` | Override for Solidity |
| New: `engine/analysis/python_analyzer.py` etc. | Language-specific analyzer implementations |

#### 4.2.5 Expected Impact

- **Direct:** Triage for Python/JS/Go/Rust/Solidity goes from lightweight structural
  pass to deep flow analysis. Dramatically reduces `inconclusive` verdicts for
  these languages.
- **Estimated improvement:** 2–4× for non-C/C++ codebases.

---

### 4.3 Confidence Calibration & Finding Deduplication

**Problem:**
The current system has two confidence issues:

1. **Uncalibrated confidence scores:** The LLM returns a `confidence` float (0.0–1.0)
   in `ReviewIssueModel`, but this value is not calibrated against ground truth.
   A confidence of 0.8 from the LLM doesn't necessarily mean 80% probability
   of being a true positive.

2. **Duplicate findings:** When `review_code()` reviews each file independently,
   the same root cause (e.g., a shared vulnerable utility function) may be
   reported multiple times from different callers. The results are simply
   concatenated without deduplication.

**Proposed solution:**

#### 4.3.1 Confidence Calibration

Build a calibration pipeline:

1. **Benchmark corpus:** Assemble a set of known-vulnerable codebases with
   ground truth labels:
   - NIST Juliet Test Suite (C/C++, Java)
   - OWASP Benchmark (Java)
   - Damn Vulnerable applications (Python, JS, PHP, Go)
   - Curated internal test cases

2. **Score distribution analysis:** Run Metis against the benchmark corpus
   and collect (predicted_confidence, actual_label) pairs.

3. **Calibration function:** Fit a calibration curve (Platt scaling or
   isotonic regression) that maps raw LLM confidence to calibrated probability.

4. **Per-category calibration:** Different vulnerability types may have
   different calibration curves (e.g., buffer overflow detection may be
   well-calibrated while logic bugs are not).

5. **Runtime application:** Apply the calibration function to every finding
   before returning it to the user.

#### 4.3.2 Finding Deduplication

After all file reviews complete, deduplicate findings:

1. **Exact match:** Identical (file, line, issue description) → merge.
2. **Root cause match:** Different files reporting the same vulnerable function
   → group under a single finding with multiple affected call sites.
3. **Similarity match:** Findings with >80% textual similarity in the same
   file region → merge, keeping the more detailed description.

#### 4.3.3 Severity Classification

Map findings to standardized severity using CWE and CVSS-like metrics:

| Dimension | Factors |
|-----------|---------|
| **Impact** | Confidentiality/Integrity/Availability effect, data sensitivity |
| **Exploitability** | Attack complexity, privileges required, user interaction needed |
| **Confidence** | Calibrated confidence score, evidence quality |

Produce a composite severity score: `Critical / High / Medium / Low / Info`.

#### 4.3.4 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/graphs/review.py: _post_process_reviews()` | Add calibration step |
| `engine/review_service.py: review_code()` | Add deduplication pass after all files |
| `engine/graphs/schemas/review.py: ReviewIssueModel` | Add `calibrated_confidence`, `severity` fields |
| New: `engine/calibration.py` | Calibration model loading and application |
| New: `engine/dedup.py` | Finding deduplication logic |

#### 4.3.5 Expected Impact

- **Direct:** Users can trust confidence scores. Duplicate noise is eliminated.
  Severity classification enables prioritization.
- **Estimated improvement:** 1.5–2× effective improvement (same detection, but
  much more actionable output).

---

### 4.4 Iterative Evidence Deepening for Triage

**Problem:**
The current triage evidence collection (`triage_node_collect_evidence()`) runs
once with fixed bounds:
- `MAX_SECTIONS = 28`
- `EVIDENCE_PACK_MAX_CHARS = 14000`
- `MAX_SYMBOL_TERMS = 3` (external) / `4` (Metis)
- `DEFAULT_MAX_FOLLOWUP_HITS = 12`

If the initial collection doesn't meet evidence obligations, the finding is
forced to `inconclusive` by the evidence gate. There is no retry with expanded
parameters.

Additionally, symbol resolution is effectively single-hop: `_gather_symbol_definition_hits()`
probes each symbol with grep in local path → fallback paths, but doesn't follow
the chain (if symbol A resolves to a wrapper around B, B is not further resolved).

**Proposed solution:**

#### 4.4.1 Adaptive Evidence Budget

Replace fixed bounds with an adaptive strategy:

```python
class EvidenceBudget:
    def __init__(self, complexity: str = "standard"):
        if complexity == "simple":
            self.max_sections = 16
            self.max_chars = 8000
            self.max_symbol_terms = 2
            self.max_hops = 1
        elif complexity == "standard":
            # Current defaults
            self.max_sections = 28
            self.max_chars = 14000
            self.max_symbol_terms = 4
            self.max_hops = 2
        elif complexity == "deep":
            self.max_sections = 48
            self.max_chars = 24000
            self.max_symbol_terms = 8
            self.max_hops = 4
```

Start with "standard" budget. If obligations are unmet after the first pass,
automatically retry with "deep" budget before falling back to `inconclusive`.

#### 4.4.2 Multi-Hop Symbol Resolution

Extend `_gather_symbol_definition_hits()` to follow resolution chains:

```
Symbol A → grep finds definition in file X
  → definition of A calls B → grep for B
    → B is defined in file Y → add to evidence
```

Configurable depth limit (default 3 hops). Track the full resolution chain
for the adjudication layer.

This directly addresses the common triage failure mode where a wrapper function
obscures the actual behavior:
```c
// user code
safe_alloc(size);

// wrapper (different file)
void* safe_alloc(size_t n) { return malloc(n); }
// → Now triage knows safe_alloc is malloc and can assess the finding properly
```

#### 4.4.3 Graph-Assisted Resolution

When the code graph index (§3.1) is available, use it for symbol resolution
instead of grep:

- Grep: `O(n)` scan of all files, regex-based, misses dynamic dispatch.
- Graph: `O(1)` lookup by function name, semantic edges, handles inheritance
  and interface implementations.

Fall back to grep when the graph is unavailable (e.g., `--ignore-index` mode).

#### 4.4.4 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/graphs/triage/constants.py` | Replace fixed constants with `EvidenceBudget` |
| `engine/graphs/triage/evidence.py: triage_node_collect_evidence()` | Add retry logic with expanded budget |
| `engine/graphs/triage/evidence_tools.py: _gather_symbol_definition_hits()` | Add multi-hop following |
| `engine/graphs/triage/graph.py` | Add conditional re-collect edge in StateGraph |

#### 4.4.5 Expected Impact

- **Direct:** Reduces `inconclusive` verdicts from ~30-40% to ~10-15%.
  Wrapper/alias chains no longer block triage decisions.
- **Estimated improvement:** 2–3× improvement in triage decisiveness.

---

## 5. Tier 3 — Refinements

These improvements provide 2–5× combined improvement through operational
excellence and integration.

### 5.1 Agentic Review Mode

**Problem:**
The current review pipeline feeds the LLM a fixed context (file content + RAG
results) and expects it to identify all vulnerabilities in one shot. The LLM
cannot ask for more information when it spots something suspicious but needs
to see a called function's implementation to confirm.

**Proposed solution:**
Add an optional **agentic review mode** where the LLM can request additional
code context during review:

#### 5.1.1 Tool-Augmented Review

Extend the review LangGraph to allow the LLM to call tools:

| Tool | Description |
|------|-------------|
| `get_function_body(name)` | Retrieve the implementation of a named function |
| `get_callers(name)` | Find all call sites of a function |
| `get_type_definition(name)` | Retrieve a struct/class/type definition |
| `search_pattern(pattern)` | Search for a code pattern across the codebase |

These tools are read-only and bounded (max N calls per review, timeout per call).

#### 5.1.2 Review Loop

```
build_prompt → LLM_review →
  if LLM requests tool → execute tool → feed result back → LLM_review (again)
  if LLM returns findings → parse → END
```

Max iterations: configurable (default 3). This prevents runaway cost while
allowing the LLM to drill down on suspicious patterns.

#### 5.1.3 When to Use

This mode is most valuable for:
- Large codebases where a single file's context is insufficient.
- Security-critical code where thoroughness matters more than speed.
- Complex vulnerability types (TOCTOU, race conditions, logic bugs) that
  require understanding multiple components.

Control via `--review-mode agentic` flag.

#### 5.1.4 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/graphs/review.py` | Add tool-call loop to the StateGraph |
| `engine/tools/registry.py` | Add `review_evidence` tool policy |
| `engine/tools/static_tools.py` | Add `get_function_body`, `get_callers` tools |
| `cli/commands.py` | Add `--review-mode` flag |

#### 5.1.5 Expected Impact

- **Direct:** Catches vulnerabilities that require multi-step reasoning across
  code boundaries.
- **Estimated improvement:** 2–3× for complex codebases.

---

### 5.2 SARIF-Integrated Feedback Loop

**Problem:**
Metis currently has no mechanism to learn from user feedback. When a security
engineer dismisses a finding as a false positive, that information is lost.
The next run will produce the same false positive.

**Proposed solution:**

#### 5.2.1 Feedback Collection

Extend SARIF output with feedback fields:

```json
{
  "properties": {
    "metisTriaged": true,
    "metisTriageStatus": "invalid",
    "userFeedback": "confirmed_false_positive",
    "userFeedbackReason": "Input is validated by middleware before reaching this function",
    "userFeedbackTimestamp": "2026-05-14T15:00:00Z"
  }
}
```

Provide a CLI command: `metis feedback <sarif_file>` that lets users annotate
findings interactively.

#### 5.2.2 Feedback-Informed Review

At review time, load historical feedback for the project:
- If a specific pattern has been consistently dismissed, reduce its priority
  in prompts or add a note: "Previous reviews of similar patterns in this
  codebase were marked as false positives because [reason]."
- If a specific file/function has confirmed vulnerabilities, increase
  scrutiny.

#### 5.2.3 Project Security Profile

Over time, build a per-project profile:
- Which CWE categories are most relevant.
- Which files/modules are most vulnerability-prone.
- What common false positive patterns exist.
- What security frameworks/libraries are in use (to avoid flagging correct
  usage of security libraries).

#### 5.2.4 Integration Points

| Current File | Change |
|-------------|--------|
| `sarif/triage.py` | Add feedback fields to SARIF annotations |
| New: `engine/feedback.py` | Feedback storage, retrieval, and profile building |
| `engine/graphs/review.py` | Incorporate project profile into prompts |
| `cli/commands.py` | Add `feedback` command |

#### 5.2.5 Expected Impact

- **Direct:** Eliminates recurring false positives. Adapts to project-specific
  security patterns over time.
- **Estimated improvement:** 1.5–2× improvement in precision over time.

---

### 5.3 Incremental / Diff-Aware Review

**Problem:**
The current `review_patch()` reviews only the changed lines in a diff. It
does not consider the **blast radius** — other code that depends on the
changed functions and may now be vulnerable due to the change.

**Proposed solution:**

#### 5.3.1 Blast Radius Analysis

When reviewing a patch:

1. Identify all functions that were modified.
2. Using the code graph (§3.1), find all callers of modified functions.
3. For each caller, assess whether the change could introduce a vulnerability
   at the call site (e.g., a function that previously validated input no
   longer does, and callers relied on that validation).
4. Include blast radius context in the review prompt.

#### 5.3.2 Change Impact Classification

Classify changes by security impact:

| Change Type | Security Relevance |
|------------|-------------------|
| New input validation | Positive (reducing risk) |
| Removed validation check | Critical (increasing risk) |
| Modified auth/crypto logic | Critical |
| New API endpoint | High (expanded attack surface) |
| Refactored utility function | Low (unless callers are security-critical) |
| Documentation change | None |

Focus LLM attention on high/critical changes.

#### 5.3.3 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/review_service.py: review_patch()` | Add blast radius analysis |
| `engine/diff_utils.py` | Add change impact classification |
| `engine/graphs/review.py` | Add blast-radius-aware prompt building |

#### 5.3.4 Expected Impact

- **Direct:** Catches security regressions introduced by changes that affect
  dependent code.
- **Estimated improvement:** 1.5–2× for patch review workflows.

---

### 5.4 Multi-Model Ensemble

**Problem:**
The current system uses a single model (`gpt-5.5`) for all review and triage.
Different models have different strengths — one model might catch buffer
overflows well but miss logic bugs, while another might excel at logic
reasoning but miss low-level memory issues.

**Proposed solution:**

#### 5.4.1 Parallel Multi-Model Review

Run the same review through 2–3 models simultaneously:

```
           ┌─ Model A ─┐
Input ──── ├─ Model B ─┤ ──── Merge ──── Output
           └─ Model C ─┘
```

#### 5.4.2 Finding Aggregation Strategies

| Strategy | Description | When to Use |
|----------|-------------|-------------|
| **Intersection** | Only keep findings reported by ≥2 models | High-precision mode (minimize FP) |
| **Union** | Keep all findings from all models | High-recall mode (minimize FN) |
| **Weighted vote** | Weight by model's calibrated accuracy per CWE | Balanced mode (default) |

#### 5.4.3 Temperature Diversity

Even with a single model, run at multiple temperatures (0.0, 0.3, 0.7) and
aggregate. Lower temperatures produce deterministic, high-confidence findings;
higher temperatures surface creative, less obvious vulnerabilities.

#### 5.4.4 Integration Points

| Current File | Change |
|-------------|--------|
| `engine/graphs/review.py: review_node_llm()` | Add multi-model invocation |
| New: `engine/ensemble.py` | Finding aggregation and voting logic |
| `metis.yaml` | Add `ensemble` configuration section |

#### 5.4.5 Expected Impact

- **Direct:** Increases recall (catches more vulnerabilities) while maintaining
  or improving precision through consensus.
- **Estimated improvement:** 1.5–2× improvement in recall.

---

### 5.5 Pre-Review Static Analysis Integration

**Problem:**
Traditional static analysis tools (Semgrep, CodeQL, Bandit, etc.) are fast and
precise for known patterns but miss novel or complex vulnerabilities. Metis uses
LLMs which are good at reasoning but may miss simple, well-known patterns.
Currently, the two approaches are independent.

**Proposed solution:**

#### 5.5.1 Static Analysis as Pre-Filter

Run lightweight static analyzers before LLM review and feed their results
as structured hints:

```
Static Analysis → hints[] → LLM Review (with hints) → findings[]
```

#### 5.5.2 Hint Integration

Add static analysis hints to the review prompt:

```
STATIC ANALYSIS HINTS (pre-screen by Semgrep):
- Line 42: Possible SQL injection (rule: python.flask.security.injection.sql-injection)
- Line 78: Hardcoded secret (rule: generic.secrets.gitleaks.generic-api-key)

Use these as starting points but perform your own independent analysis.
Confirm, refute, or expand on each hint with your reasoning.
```

This focuses the LLM's attention on areas where simple tools already see
risk, while letting the LLM provide deeper reasoning about whether the
flagged patterns are actually exploitable.

#### 5.5.3 Bi-Directional Value

- **Static → LLM:** Static tools point the LLM to suspicious code.
- **LLM → Static:** LLM findings that match known patterns validate both
  tools. LLM findings for novel patterns can be used to create new static
  analysis rules over time.

#### 5.5.4 Supported Tool Integration

| Tool | Languages | Integration Method |
|------|-----------|-------------------|
| **Semgrep** | All major languages | Run via CLI, parse JSON output |
| **Bandit** | Python | Run via CLI, parse JSON output |
| **ESLint security plugins** | JavaScript/TypeScript | Run via CLI, parse JSON output |
| **gosec** | Go | Run via CLI, parse JSON output |
| **cargo-audit** | Rust | Run via CLI, parse JSON output |

All these tools produce SARIF or JSON output that can be parsed into
hints.

#### 5.5.5 Integration Points

| Current File | Change |
|-------------|--------|
| New: `engine/static_analysis/` | Tool runner, output parser, hint formatter |
| `engine/graphs/review.py` | Add hints to prompt construction |
| `engine/review_service.py` | Add pre-review static analysis step |
| `cli/commands.py` | Add `--pre-scan` flag to enable static analysis hints |
| `metis.yaml` | Add `static_analysis` configuration section |

#### 5.5.6 Expected Impact

- **Direct:** Combines the speed and precision of static analysis with the
  depth and reasoning of LLMs. Simple vulnerabilities are caught reliably;
  complex ones get focused attention.
- **Estimated improvement:** 1.5–2× improvement in both recall and precision.

---

## 6. Improvement × Impact Matrix

| # | Improvement | Recall Gain | Precision Gain | Key Enabler | Complexity |
|---|-------------|:-----------:|:--------------:|:-----------:|:----------:|
| 3.1 | Semantic Code Graph Index | ★★★ | ★★ | Foundation | High |
| 3.2 | Multi-Pass Review Pipeline | ★★★★ | ★★★ | 3.1 | High |
| 3.3 | Cross-File Data Flow Tracing | ★★★★★ | ★★★ | 3.1 | High |
| 4.1 | Security-Focused Retrieval | ★★ | ★★★ | 3.1 | Medium |
| 4.2 | Rich Triage for All Languages | ★★★ | ★★★ | — | Medium |
| 4.3 | Confidence Calibration & Dedup | ★ | ★★★★ | — | Medium |
| 4.4 | Iterative Evidence Deepening | ★★ | ★★★ | — | Low |
| 5.1 | Agentic Review Mode | ★★★ | ★★ | 3.1 | Medium |
| 5.2 | SARIF Feedback Loop | ★ | ★★★ | — | Low |
| 5.3 | Diff-Aware Review | ★★ | ★★ | 3.1 | Low |
| 5.4 | Multi-Model Ensemble | ★★★ | ★★ | — | Low |
| 5.5 | Static Analysis Integration | ★★ | ★★★ | — | Low |

★ = incremental, ★★★★★ = transformative

## 7. Suggested Implementation Order

The improvements have dependencies and compounding effects. Suggested order:

### Wave 1: Foundation

1. **Semantic Code Graph Index (3.1)** — Everything else builds on this.
2. **Rich Triage for All Languages (4.2)** — Independent of 3.1, can be done
   in parallel. Immediate value for non-C/C++ users.

### Wave 2: Core Detection

3. **Cross-File Data Flow Tracing (3.3)** — Depends on 3.1. Highest single-item
   impact on vulnerability detection.
4. **Multi-Pass Review Pipeline (3.2)** — Depends on 3.1. Transforms review
   from single-pass to deep reasoning.
5. **Security-Focused Retrieval (4.1)** — Depends on 3.1. Enhances all
   retrieval-dependent operations.

### Wave 3: Quality & Precision

6. **Iterative Evidence Deepening (4.4)** — Independent. Quick win for triage.
7. **Confidence Calibration & Dedup (4.3)** — Independent. Improves output
   quality.
8. **Static Analysis Integration (5.5)** — Independent. Quick win for known
   patterns.

### Wave 4: Advanced Capabilities

9. **Agentic Review Mode (5.1)** — Depends on 3.1.
10. **Multi-Model Ensemble (5.4)** — Independent.
11. **Diff-Aware Review (5.3)** — Depends on 3.1.
12. **SARIF Feedback Loop (5.2)** — Independent. Long-term value.

---

**Compounding effect:** While each improvement provides 1.5–10× improvement in
isolation, they compound multiplicatively. The code graph enables richer
retrieval, which enables better multi-pass review, which produces higher-quality
findings, which triage can validate more decisively. The combined effect across
all tiers targets the 50× improvement goal.
