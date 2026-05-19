# Metis Performance Dev Plan 2 — Remaining Wave 3 Work

> **Status:** Waves 1, 2, and all gap items (G1–G7) are verified complete.
> Only Wave 3 items remain — four independent workstreams described below.

---

## 1. Current State Summary

All 14 items from the original plan + gap backlog are done:

| ID | Item | Status |
|---|---|---|
| W1.1 | Per-command `max_workers` + CLI flags | ✅ |
| W1.2 | Configurable `embed_batch_size` (32→128) | ✅ |
| W1.3 | Skip already-embedded files in `/index` | ✅ |
| W1.4 | In-process retrieval cache (LRU, inflight dedup) | ✅ |
| W2.5 | Parallel tree-sitter parsing (thread-local splitter cache) | ✅ |
| W2.6 | `.metisignore` pre-filter before `SimpleDirectoryReader` | ✅ |
| W2.7 | Group triage findings by file with shared retrieval | ✅ |
| W2.8 | Shared `ThreadPoolExecutor` for triage tool calls | ✅ |
| G1 | Verify hash-skip correctness | ✅ |
| G2 | Bound `RetrievalCache` (LRU, `max_entries=1024`, configurable) | ✅ |
| G3 | Invalidate cache on `update_index` (via `finally` block) | ✅ |
| G4 | Thread-local splitter cache in parallel parsing | ✅ |
| G6 | Document new tunables (README, CHANGELOG, help text) | ✅ |
| G7 | Perf regression bench (`bench --perf`, baseline JSON, CI) | ✅ |

**What remains: 4 Wave 3 items** — all deferred-by-design, independent of each
other, and requiring larger refactors.

---

## 2. W3.1 — Async LLM Calls

### Problem
`review_code` and `triage` use `ThreadPoolExecutor` + synchronous `invoke()`
for all LLM calls. At high `max_workers` (8+), GIL contention on Python thread
scheduling and callback overhead become measurable. The thread pool model also
makes backpressure and cancellation hard to manage.

### Current code paths
- **Review:** `review_service.py:234` — `ThreadPoolExecutor(max_workers=review_max_workers)`,
  each future calls `self._invoke_review_file(...)` which enters the LangGraph
  `app.invoke(state)` in `graphs/review.py:618`.
- **Triage:** `triage_service_exec.py:312` — `ThreadPoolExecutor(max_workers)`,
  each future calls `_triage_one_finding_with_shared_context(...)` which enters
  `triage_graph.triage(req)` via `graphs/triage/graph.py:129`.
- **LLM calls within graphs:** `langchain_core` `ChatPromptTemplate | chat | StrOutputParser`
  chains, invoked via `.invoke()` (sync). Structured output via
  `chat.with_structured_output(Model).invoke(messages)`.

### Proposed changes

1. **Add async graph entry points.**
   - `ReviewGraph.areview(request)` — mirrors `review()` but calls `app.ainvoke(state)`.
   - `TriageGraph.atriage(request)` — mirrors `triage()` but calls `app.ainvoke(state)`.
   - LangGraph supports `ainvoke` natively; nodes become `async def` or are
     auto-wrapped via `asyncio.to_thread`.

2. **Convert graph nodes to async where they call LLM.**
   - `review_node_invoke` → `async def review_node_invoke` using `await runnable.ainvoke(payload)`.
   - `triage_node_llm` → `async def triage_node_llm` using `await decision_model.ainvoke(messages)`.
   - Retrieval nodes can stay sync (vector store calls are fast); wrap with
     `asyncio.to_thread` if needed.

3. **Replace `ThreadPoolExecutor` orchestration with `asyncio.gather`.**
   - `ReviewService.review_code`:
     ```python
     sem = asyncio.Semaphore(self._config.review_max_workers)
     async def _review_one(path):
         async with sem:
             return await self._review_graph_factory().areview(req)
     results = await asyncio.gather(*[_review_one(p) for p in files],
                                     return_exceptions=True)
     ```
   - Same pattern for `_triage_findings_parallel`.

4. **Keep sync public API.**
   - `MetisEngine.review_code()` remains sync; internally calls
     `asyncio.run(_async_review_code(...))` or uses a dedicated event loop
     thread to avoid "already running loop" issues.

5. **Usage context propagation.**
   - Replace `submit_with_current_context` (thread-based) with `contextvars`
     copy via `asyncio.create_task(copy_context().run(coro))`.
   - Verify `UsageHooks.callbacks` is `contextvar`-safe.

### Files to change
| File | Change |
|---|---|
| `engine/graphs/review.py` | Add `async def` variants of `review_node_invoke`, `review_node_agentic_invoke`; add `ReviewGraph.areview()` |
| `engine/graphs/triage/llm.py` | `async def triage_node_llm` |
| `engine/graphs/triage/graph.py` | Add `TriageGraph.atriage()` |
| `engine/review_service.py` | Replace `ThreadPoolExecutor` with `asyncio.gather` + `Semaphore` |
| `engine/triage_service_exec.py` | Same pattern for `_triage_findings_parallel` |
| `metis/usage/__init__.py` | Add `submit_with_current_context_async` using `contextvars` |

### Risks
- LangChain/LlamaIndex async paths may have different retry or rate-limit
  behavior. Must test against real provider rate limits.
- `asyncio.to_thread` fallback for sync nodes adds one thread per call — only
  net-positive if the majority of wall-clock is in truly async-capable LLM calls.
- Existing tests all use sync APIs — need parallel async test fixtures.

### Acceptance criteria
- `bench --perf` shows ≥30% wall-clock improvement on `/review_code` at
  `max_workers=16` vs current thread-pool baseline.
- All existing sync tests pass unchanged.
- New async-specific tests cover: semaphore limiting, cancellation,
  `contextvars` propagation, exception passthrough.

### Estimated complexity
High — touches core orchestration in review + triage pipelines, usage tracking,
and the graph execution layer. Recommend a feature flag (`--async-llm`) defaulting
to off until bench-validated.

---

## 3. W3.2 — Disk Embedding Cache

### Problem
Re-running `/index` on an unchanged (or partially changed) codebase still makes
embedding API calls for every node, even though the text hasn't changed. W1.3
skips files whose docstore hash matches, but if the index is rebuilt from scratch
(new schema, backend switch, ChromaDB directory deleted), all embeddings are
recomputed.

### Current code paths
- `indexing_service.index_finalize_embeddings` → `VectorStoreIndex(nodes, embed_model=..., ...)`.
- Under the hood, LlamaIndex calls `embed_model.get_text_embedding_batch(texts)`
  which dispatches to `OpenAIEmbedding._get_text_embeddings(texts)`.
- No caching layer between the node text and the embedding API call.

### Proposed changes

1. **New module: `engine/embed_cache.py`.**
   ```python
   class DiskEmbedCache:
       def __init__(self, path: str, model_key: str, max_mb: int = 500):
           # SQLite DB at `path` with WAL mode
           # Table: (text_hash TEXT PK, model_key TEXT, embedding BLOB, created_at REAL)
           # Composite key: sha256(text) + model_key
           ...
       def get_batch(self, texts: list[str]) -> list[list[float] | None]: ...
       def put_batch(self, texts: list[str], embeddings: list[list[float]]): ...
       def prune(self): ...  # evict entries exceeding max_mb
   ```

2. **Wrap embed models with cache-aware delegate.**
   ```python
   class CachedEmbedModel:
       def __init__(self, inner, cache: DiskEmbedCache): ...
       def get_text_embedding_batch(self, texts):
           cached = self._cache.get_batch(texts)
           misses = [(i, t) for i, (t, c) in enumerate(zip(texts, cached)) if c is None]
           if misses:
               miss_texts = [t for _, t in misses]
               fresh = self._inner.get_text_embedding_batch(miss_texts)
               self._cache.put_batch(miss_texts, fresh)
               for (i, _), emb in zip(misses, fresh):
                   cached[i] = emb
           return cached
   ```

3. **Wire into `MetisEngine`.**
   - In `core.py`, after `get_embed_model_code()` / `get_embed_model_docs()`,
     wrap with `CachedEmbedModel(model, cache)`.
   - Cache path: `<chroma_dir>/embed_cache.sqlite` (or `<project_schema>_embed_cache.sqlite`
     for pgvector).
   - Cache key includes `model_name + ":" + str(embed_dim)` to avoid cross-model
     poisoning.

4. **Configuration.**
   ```yaml
   metis_engine:
     embed_cache_enabled: true
     embed_cache_max_mb: 500
   ```
   - CLI flag: `--no-embed-cache` to bypass.

5. **Concurrency.**
   - SQLite WAL mode supports concurrent readers + single writer.
   - Batch `put` within a single transaction for performance.
   - Lock at the Python level per-process (threading.Lock around write path).

### Files to change
| File | Change |
|---|---|
| `engine/embed_cache.py` | New — `DiskEmbedCache`, `CachedEmbedModel` |
| `engine/core.py` | Wrap embed models after construction |
| `configuration.py` | Parse `embed_cache_enabled`, `embed_cache_max_mb` |
| `metis.yaml` | Add defaults |
| `cli/entry.py` | Add `--no-embed-cache` flag |

### Risks
- Cache poisoning if model name changes without key update. Mitigated by
  including model name + dim in key.
- Disk growth on monorepos. Mitigated by `max_mb` + `prune()` on startup.
- SQLite locking under high parallelism. Mitigated by WAL + batch writes.

### Acceptance criteria
- Re-running `/index` on unchanged codebase makes **zero** embedding API calls
  (all served from disk cache). Verified via mock.
- Cache hit ratio surfaced in `index` progress output (`cache_hits`, `cache_misses`).
- `--no-embed-cache` bypasses cleanly.
- `bench --perf` shows ≥50% wall-clock reduction on `/index` for warm cache.

### Estimated complexity
Medium — self-contained new module + thin wiring layer. No changes to
LangGraph/review/triage logic.

---

## 4. W3.3 — Batch `summarize_changes` for `review_patch`

### Problem
In `review_patch`, after each file is reviewed, a separate LLM call is made via
`summarize_changes()` to generate a per-file summary (`review_service.py:419-425`).
For a patch touching N files, this adds N extra LLM calls (one per file) on top
of the N review calls.

### Current code path
```
review_patch(patch_file)
  for file_diff in diff:
    review_dict = review_graph.review(req)       # LLM call 1 (review)
    summary = summarize_changes(llm, ...)         # LLM call 2 (per-file summary)
    overall_summaries.append(summary)
  overall_changes = "\n\n".join(overall_summaries) # concatenation only
```

### Proposed changes

1. **Defer summarization to end of `review_patch`.**
   - Collect all per-file issues into a single list.
   - After the file loop, make one LLM call with a batched prompt:
     ```
     Summarize the following security findings across {N} files in this patch.
     For each file, provide a one-paragraph summary. Then provide an overall summary.

     File: {path1}
     Issues: {issues1}

     File: {path2}
     Issues: {issues2}
     ...
     ```
   - Parse the response back into per-file summaries and an overall summary.

2. **Handle context window overflow.**
   - If the batched prompt exceeds `max_token_length * 0.8`, chunk files into
     groups and make multiple summary calls (still fewer than N).
   - Fall back to per-file mode if the model returns incomplete output.

3. **Preserve API.**
   - Each `review_dict` still gets `changes_summary` populated.
   - `overall_changes` still returned in the response dict.
   - Output format is identical for downstream SARIF/JSON consumers.

### Files to change
| File | Change |
|---|---|
| `engine/review_service.py` | Refactor `review_patch` to defer `summarize_changes`; add `_batch_summarize` |
| `engine/helpers.py` | Add `batch_summarize_changes(llm, file_issues_map, prompt)` |

### Risks
- LLM may omit or misattribute summaries when given many files at once.
  Mitigation: validate output contains all file paths; re-prompt for missing.
- Prompt size may exceed context window for large patches (50+ files).
  Mitigation: chunked fallback.

### Acceptance criteria
- `review_patch` over N files makes N+1 LLM calls total (N reviews + 1 summary)
  instead of 2N.
- Output structure unchanged (regression test on existing `test_engine_review` fixtures).
- For patches exceeding context window, graceful chunked fallback with no crash.

### Estimated complexity
Low-medium — localized to `review_service.py` and `helpers.py`. No graph changes.

---

## 5. W3.4 — Tighten Agentic Review Tool Budgets

### Problem
Agentic review mode (`--review-mode agentic`) allows the LLM to make tool calls
(e.g., `get_function_body`, `get_callers`, `grep_repo`) across multiple
iterations before producing findings. With defaults of `max_iterations=3` and
`max_tool_calls=6`, a single file review can make up to 3 LLM roundtrips + 6
tool calls, dominating wall-clock time.

### Current code path
- `graphs/review.py:296-370` — `review_node_exec_tool` processes tool calls
  **sequentially** within a single iteration (line 318: `for call in calls[:remaining_calls]`).
- No wall-clock budget — the only limits are iteration count and tool call count.
- Tool execution uses `_run_review_tool` which calls the toolbox sync API
  (`build_toolbox` with `tool_timeout_seconds` per individual tool).

### Proposed changes

1. **Parallel tool execution within an iteration.**
   - When `len(calls) > 1`, dispatch via `ThreadPoolExecutor(max_workers=3)`:
     ```python
     with ThreadPoolExecutor(max_workers=min(3, len(calls))) as pool:
         futures = {pool.submit(_run_review_tool, toolbox, c["name"], c["args"]): c
                    for c in calls[:remaining_calls]}
         for future in as_completed(futures):
             call = futures[future]
             output = future.result()  # or handle exception
             results.append(_format_tool_result(call["name"], call["args"], output))
     ```
   - Cap concurrent tool calls at 3 to avoid filesystem contention from `grep_repo`.

2. **Per-file wall-clock budget.**
   - New option: `ReviewAgenticOptions.wallclock_seconds: int = 60`.
   - Record `start_time = time.monotonic()` at entry to the agentic loop.
   - Before each iteration, check `elapsed > wallclock_seconds` → set
     `agentic_force_final = True` and break.

3. **Tighten defaults (behind bench validation).**
   - Reduce `max_iterations` from 3 to 2.
   - Reduce `max_tool_calls` from 6 to 4.
   - These changes gated behind `bench --perf` showing recall within tolerance.

4. **Surface tool timing in usage stats.**
   - Add `tool_wallclock_ms` per call in the `tool_trace` list.
   - Aggregate `total_tool_wallclock_ms` in review output for bench analysis.

### Files to change
| File | Change |
|---|---|
| `engine/options.py` | Add `wallclock_seconds` to `ReviewAgenticOptions` |
| `engine/graphs/review.py` | Parallel dispatch in `review_node_exec_tool`; wall-clock check before each iteration |
| `metis.yaml` | Add `review.agentic.wallclock_seconds: 60` |
| `configuration.py` | Parse new field |
| `cli/entry.py` | Add `--review-agentic-wallclock` flag |

### Risks
- Reducing iterations may hurt detection recall — must validate with `bench`.
- Parallel tool execution can hit `grep_repo` filesystem contention. Mitigated
  by capping at 3 concurrent calls.
- Wall-clock budget is not respected by the LLM call itself (only checked between
  iterations). A slow LLM response can still exceed the budget. Document this
  as best-effort.

### Acceptance criteria
- `bench --perf` shows agentic `/review_code` wall-clock down ≥25% with recall
  delta ≤2%.
- Tool calls within an iteration run concurrently (verified by timing assertions
  in tests).
- `--review-agentic-wallclock 30` forcibly ends file review after ~30s.
- New `tool_wallclock_ms` entries in review output.

### Estimated complexity
Medium — changes scoped to `review.py` graph node + options plumbing. No
triage changes. Must be validated empirically.

---

## 6. Sequencing & Dependencies

```
W3.2 (disk embed cache)  ──► independent, medium effort
W3.3 (batch summary)     ──► independent, low effort ← start here
W3.4 (agentic budget)    ──► needs bench validation (G7 ✅ done)
W3.1 (async LLM)         ──► largest effort, do last
```

Recommended order: **W3.3 → W3.2 → W3.4 → W3.1**

- W3.3 is smallest, safest, and delivers immediate LLM-cost savings.
- W3.2 is self-contained and delivers the biggest speedup for repeated `/index`.
- W3.4 needs `bench --perf` (already available) to validate default changes.
- W3.1 is the largest refactor and should come last, once the perf bench
  infrastructure is battle-tested.

---

## 7. Open Questions (carried from dev-plan.md)

1. **W3.1:** Standardize on `asyncio` everywhere, or only at service boundaries?
   Full migration is large; partial keeps plugins synchronous.
2. **W3.2:** Should disk embed cache be portable (checked in) or local-only?
   Local-only is simpler; portable enables CI speedups.
3. **W3.4:** Are default reductions (3→2 iterations, 6→4 tools) acceptable
   if bench shows ≤2% recall drop? Need team sign-off before flipping defaults.
