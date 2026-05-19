# Metis Performance Dev Plan — Gaps, Verifications, and Wave 3

> **Status:** Wave 1 + most of Wave 2 implemented. This document captures
> verification gaps in what's already landed, plus the remaining Wave 3 work.
> Companion to the original speedup plan in
> `~/.copilot/session-state/<session>/plan.md` and `speed-plan.md`.

---

## 1. Implemented So Far

| ID | Item | Status | Key locations |
|---|---|---|---|
| W1.1 | Per-command `review_max_workers` / `triage_max_workers` + CLI flags (`--review-max-workers`, `--triage-max-workers`) | ✅ Done | `metis.yaml`, `configuration.py`, `engine/core.py`, `cli/entry.py` |
| W1.2 | Configurable `embed_batch_size` (default 32 → 128), wired into OpenAI + Azure providers | ✅ Done | `metis.yaml`, `configuration._embedding_extra_kwargs`, `providers/openai_compatible.py`, `providers/azure_openai.py` |
| W1.3 | Skip already-embedded files in `/index` via docstore hash + FunctionIndex hash | ✅ Done (needs verification — see Gap G1) | `engine/indexing_service._docstore_hash_matches`, `_function_index_hash_matches`, `engine/code_index.py` |
| W1.4 | In-process retrieval cache with inflight de-dup | ✅ Done (needs bounds + invalidation check — see G2/G3) | `engine/retrieval_cache.py`, `engine/core._create_query_engines`, `engine/runtime.EngineState.retrieval_cache` |
| W2.5 | Parallel tree-sitter parsing | ✅ Done (review thread-locality — see G4) | `engine/helpers.prepare_nodes_iter` |
| W2.6 | `.metisignore` pre-filter before `SimpleDirectoryReader` | ✅ Done | `engine/indexing_service._collect_index_input_files` |
| W2.7 | Group triage findings by file with shared retrieval | ✅ Done | `engine/triage_service_exec._group_findings_by_file`, `_build_group_retrieval_context` |
| W2.8 | Shared `ThreadPoolExecutor` for triage tool calls | ⚠️ Partial — see Gap G5 | `engine/triage_service_exec._triage_findings_parallel` creates `tool_executor`, but consumers in `evidence_tools` may still spawn per-call threads |

---

## 2. Verification & Gap Backlog (must fix before declaring Wave 1/2 done)

### G1 — Verify hash-skip actually skips (`w1-skip-indexed`)
- `_docstore_hash_matches` calls `docstore.get_document_hash(doc_id)`. Confirm:
  - The hash recorded at index time matches the format LlamaIndex assigns to
    `Document(text=..., id_=...)` (`doc.hash` uses the same SHA1 over text +
    metadata). Mismatch ⇒ skip never triggers.
  - `FunctionIndex.file_hash_matches` is **populated on write** (the function
    index serializer must persist `file_hash` per file id; otherwise unchanged
    code files are always reparsed).
- Add an integration test: run `index`, run `index` again, assert
  `progress_callback` emits `skipped_count == total_files` on the second pass
  and zero new embeddings are requested (mock the embedding client).

### G2 — Bound the `RetrievalCache`
- `RetrievalCache._items` is unbounded; long-running TUI sessions could grow
  without limit.
- Add an LRU bound (e.g. `max_entries=1024`, configurable via
  `metis_engine.retrieval_cache_max_entries`).
- Track byte size of cached doc lists if memory pressure becomes a concern.

### G3 — Invalidate retrieval cache on `update_index`
- `IndexingService.index_finalize_embeddings` resets query engines + clears
  cache. Confirm `IndexingService.update_index` does the same at completion
  (currently it modifies the underlying index in place — without cache clear
  callers retrieve stale `Document` lists).
- Test: index → cache a query → run `update_index` that changes a file → same
  query must re-fetch (assert `RetrievalCache.__len__() == 0` after update).

### G4 — Thread-local splitter cache in `prepare_nodes_iter`
- For `worker_count > 1`, the code calls `plugin.get_splitter()` per document
  (bypassing `get_splitter_cached`) to dodge cross-thread issues with the
  cached splitter. This re-pays tree-sitter init per file.
- Replace with a `threading.local()` splitter cache keyed by plugin id —
  one init per thread per language.

### G5 — Make triage tool calls actually use the shared executor (`w2-triage-shared-pool`)
- `triage_service_exec` plumbs `triage_tool_executor` into the request, but
  unless `engine/graphs/triage/evidence_tools._invoke_with_deadline` accepts
  and uses it, the thread-per-call pattern persists.
- Required changes:
  - `_invoke_with_deadline(state, invoke)` reads `state.get("triage_tool_executor")`
    and, when present, submits `invoke` there with a timeout-aware `future.result(timeout=...)` instead of `threading.Thread + Queue`.
  - When the executor is full, fall back to inline execution (or queue) — must
    not deadlock when the same executor is the caller's pool.
  - Cancellation on timeout: best-effort `future.cancel()`; document that
    cooperative cancellation isn't possible (tools are subprocess-bound).
- Add unit test: when `tool_executor` provided, no new threads spawn per call
  (count via `threading.enumerate()` diff).

### G6 — Document the new tunables
- Update `README.md` "Global CLI Flags" with:
  - `--review-max-workers`, `--triage-max-workers`
  - YAML keys: `metis_engine.review_max_workers`, `triage_max_workers`,
    `embed_batch_size`, `retrieval_cache_max_entries` (after G2).
- `docs/CHANGELOG.md` entry summarizing perf changes.

### G7 — Bench regression check for perf
- The new `bench` subcommand measures recall/precision. Add a `--perf` mode
  (or a follow-up subcommand) that reports wall-clock + token usage per
  command, with a baseline file checked into `tests/benchmarks/perf-baseline.json`.
- CI: fail if `/index` or `/review_code` wall-clock regresses > 20% on the
  quick benchmark.

---

## 3. Wave 3 — Larger Refactors (planned, not yet started)

### W3.1 — Async LLM calls (`w3-async-llm`)
**Goal.** Replace thread-pool concurrency on LLM-bound work with `asyncio`
to reduce GIL contention and improve throughput at high concurrency.

**Scope.**
- Migrate `ReviewService.review_code` and `TriageService._triage_findings_parallel`
  to dispatch via `asyncio.gather(*coros, return_exceptions=True)` with a
  `Semaphore(max_workers)` for rate control.
- Use `chat.ainvoke` / embedding `aembed_*` instead of `invoke`.
- Keep the synchronous public API (`engine.review_code`) — internally run a
  dedicated event loop in a worker thread.
- LangGraph nodes must be made async or wrapped via `asyncio.to_thread`.

**Risks.**
- LangChain providers' async paths historically had different retry behavior;
  test rate-limit handling carefully.
- Callback / usage tracking (`submit_with_current_context`) needs an async
  equivalent using `contextvars`.

**Acceptance.**
- Bench shows ≥ 30% wall-clock improvement on `/review_code` at
  `max_workers=16`.
- All existing tests pass; new async tests exercise the semaphore + cancellation.

### W3.2 — Disk embedding cache (`w3-disk-embed-cache`)
**Goal.** Skip embedding API calls entirely for unchanged text across runs.

**Scope.**
- Wrap `embed_model_code` / `embed_model_docs` with a `CachedEmbedding`
  delegate that consults a SQLite/sidecar store keyed by
  `sha256(text) + ":" + model_name`.
- Store under `<chroma_dir>/embed_cache.sqlite` (or a configurable path for
  pgvector users).
- Eviction policy: TTL + max size (configurable in YAML).
- Concurrency-safe (WAL mode, single writer per process).
- Bypass when `--no-embed-cache` flag is set.

**Risks.**
- Cache poisoning if the embedding model is changed without bumping the key.
  Solution: include `model_name + ":" + embed_dim` in the key.
- Disk growth on large monorepos. Mitigation: prune oldest entries beyond
  `cache_max_mb`.

**Acceptance.**
- Re-running `/index` on an unchanged codebase makes zero embedding calls
  beyond cache reads.
- Cache hit ratio surfaced in `index` progress output.

### W3.3 — Batch `summarize_changes` for review_patch (`w3-batch-summary`)
**Goal.** Replace per-file summary LLM calls in `review_patch` with a single
end-of-run summary across all reviewed files.

**Scope.**
- Defer `summarize_changes` invocation until after all `review_patch` files
  complete.
- Construct one prompt that lists per-file issues, then ask the LLM for an
  aggregated `overall_changes` plus per-file deltas.
- Preserve API: each `review_dict` still gets its `changes_summary` field, but
  populated post-hoc from the batched response (or empty if model returns no
  delta for that file).
- Use streaming if available so the spinner shows progress.

**Risks.**
- If the batch prompt exceeds context window, fall back to per-file mode.
- LLM may omit some files in its response — must validate and re-prompt only
  for missing ones.

**Acceptance.**
- A `review_patch` over N files makes 1 + N (review) + 1 (summary) LLM calls
  instead of 1 + 2N.
- Output remains byte-identical in structure for downstream tooling.

### W3.4 — Tighten agentic review tool budgets (`w3-agentic-budget`)
**Goal.** Reduce wall-clock of agentic review by parallelizing tool calls
within an iteration and lowering default budgets.

**Scope.**
- In `engine/graphs/review.py` agentic loop:
  - When multiple tool calls are returned in one model response, dispatch them
    via `asyncio.gather` (or `ThreadPoolExecutor`) instead of sequentially.
  - Add a hard wall-clock budget per file (`review_agentic_wallclock_seconds`,
    default 60) — short-circuit further iterations on timeout.
  - Tighten defaults: `max_iterations=2` (was 3), `max_tool_calls=4` (was 6).
- Surface tool-call timing in usage stats.

**Risks.**
- Reducing iterations may hurt detection recall — must validate on the bench
  corpus before flipping defaults.
- Parallel tool execution can hit `grep_repo` filesystem contention; cap
  concurrent tool calls at 3.

**Acceptance.**
- Bench shows agentic `/review_code` wall-clock down ≥ 25% with recall delta
  within tolerance (≤ 2% drop).
- New flag `--review-agentic-wallclock SECONDS`.

---

## 4. Sequencing

```
Verification (G1, G3, G5)  ←  must come first (correctness)
        │
        ▼
G2 (bound cache) + G4 (thread-local splitters)  ←  small follow-ups
        │
        ▼
G6 (docs) + G7 (perf bench in CI)  ←  guards future work
        │
        ▼
W3.2 (disk embed cache)  ─►  builds on G1/G3 (index correctness)
W3.3 (batched summary)   ─►  independent, low risk
        │
        ▼
W3.1 (async LLM)         ─►  larger refactor, do once perf bench exists
        │
        ▼
W3.4 (agentic budget)    ─►  needs bench (G7) to validate defaults
```

Independent items can land in any order; the arrows mark hard dependencies.

---

## 5. Out of Scope (carry-over from original plan)

- Switching vector backends or embedding models.
- Changes to prompt content / review semantics (beyond W3.4 budget tweaks).
- New language plugins.
- Replacing LangGraph/LlamaIndex with bespoke orchestration.

---

## 6. Open Questions

1. Should `RetrievalCache` be shared **across** `MetisEngine` instances in TUI
   mode (when the user switches `--codebase-path`)? Current per-instance scope
   is safer but loses cache on context switch.
2. For W3.2, do we want the disk embed cache to be portable across machines
   (checked into the repo) or always local-only? Local-only is simpler;
   portable enables CI speedups.
3. For W3.1, do we standardize on `asyncio` everywhere, or only at the
   service-orchestration boundary? Full migration is large; partial keeps
   plugins synchronous.

---

## 7. Tracking

Todos for these items are mirrored in the session SQL database. Status as
of writing:

- **Done:** W1.1, W1.2, W1.3, W1.4, W2.5, W2.6, W2.7
- **Blocked (gap):** W2.8 (G5)
- **Pending:** W3.1, W3.2, W3.3, W3.4
- **New (this doc):** G1, G2, G3, G4, G6, G7
