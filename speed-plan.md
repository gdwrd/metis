# Speedup Plan: `/index`, `/review_code`, `/triage`

## Problem
The three primary Metis commands are slower than they need to be:
- **`/index`** parses tree-sitter nodes single-threaded, embeds at a small batch
  size (32), and re-embeds files that haven't changed.
- **`/review_code`** is capped by `max_workers=5` and re-issues nearly identical
  retrieval queries per file with no caching.
- **`/triage`** runs retrieval and file I/O independently per finding, even when
  many findings target the same file; tool calls use a thread-per-call pattern.

## Approach
Three waves, ordered by ROI / risk:

### Wave 1 — Cheap config + caching wins (low risk)
1. Raise default `max_workers` and make per-command (`review_max_workers`,
   `triage_max_workers`) overrides in `metis.yaml` + CLI flags.
2. Make `embed_batch_size` configurable in `metis.yaml` and raise default
   (OpenAI accepts up to 2048 inputs / ~300K tokens per request).
3. Skip already-embedded files in `/index` by consulting docstore hashes before
   re-embedding (incremental full index).
4. Add an in-process retrieval cache around `get_relevant_documents` keyed by
   `(query_hash, top_k, retriever_id)`, shared across files / findings.

### Wave 2 — Structural speedups
5. Parallelize tree-sitter parsing in `prepare_nodes_iter` with a
   `ThreadPoolExecutor` (tree-sitter releases the GIL).
6. Pre-filter `.metisignore` paths **before** `SimpleDirectoryReader.load_data()`
   so ignored files aren't read/decoded.
7. Group `/triage` findings by `file_path`; share retrieval results + cached
   file content per group inside `_triage_findings_parallel`.
8. Replace `_invoke_with_deadline`'s thread-per-call pattern with a single
   shared `ThreadPoolExecutor` per triage run.

### Wave 3 — Larger refactors (optional, deferred)
9. Move LLM calls to async `ainvoke` + `asyncio.gather` instead of thread pools.
10. Disk cache for embeddings keyed by `sha256(text)+model` (skip embedding on
    re-runs entirely).
11. Batch per-patch `summarize_changes` into a single end-of-run summary call.
12. Tighten agentic review tool-call budgets / run tools in parallel within an
    iteration.

## Notes / Considerations
- Provider rate limits will become the new bottleneck after Wave 1 — make the
  worker count tunable and document defaults conservatively.
- Retrieval cache must be **per engine instance** (and cleared on `update`) to
  avoid serving stale results after index updates.
- Hash-based index skip must integrate with the existing `FunctionIndex` so
  symbol metadata stays consistent.
- All changes need to keep `--ignore-index` behavior intact (no retrieval path).
- Validate with existing tests + the `bench` command before/after each wave.

## Out of Scope
- Switching vector backends or embedding models.
- Changes to prompt content / review semantics.
- New language plugins.
