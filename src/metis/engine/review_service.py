# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import inspect
import logging
import os
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import unidiff  # type: ignore[import-untyped]

from metis.usage import submit_with_current_context, submit_with_current_context_async
from metis.utils import read_file_content

from .diff_utils import extract_added_line_ranges, process_diff_file, resolve_patch_path
from .graphs.types import ReviewRequest
from .helpers import apply_custom_guidance, batch_summarize_changes, summarize_changes
from .options import ReviewAgenticOptions, ReviewOptions, coerce_review_options
from .path_heuristics import is_test_path
from .repository import EngineRepository
from .runtime import EngineConfig

logger = logging.getLogger("metis")
_DEFAULT_SUMMARIZE_CHANGES = summarize_changes


def _run_coroutine_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(lambda: asyncio.run(coro)).result()


class ReviewService:
    def __init__(
        self,
        config: EngineConfig,
        repository: EngineRepository,
        get_query_engines: Callable[[], tuple[Any, Any]],
        review_graph_factory: Callable[[], Any],
    ):
        self._config = config
        self._repository = repository
        self._get_query_engines = get_query_engines
        self._review_graph_factory = review_graph_factory

    def _default_agentic_options(self) -> ReviewAgenticOptions:
        return ReviewAgenticOptions(
            max_iterations=self._config.review_agentic_max_iterations,
            max_tool_calls=self._config.review_agentic_max_tool_calls,
            tool_timeout_seconds=self._config.review_agentic_tool_timeout_seconds,
            max_extra_tokens=self._config.review_agentic_max_extra_tokens,
            wallclock_seconds=self._config.review_agentic_wallclock_seconds,
        )

    def _coerce_options(
        self,
        options: ReviewOptions | None,
        *,
        use_retrieval_context: bool | None = None,
    ) -> ReviewOptions:
        if options is None:
            return coerce_review_options(
                None,
                use_retrieval_context=use_retrieval_context,
                review_mode=self._config.review_mode,
                agentic=self._default_agentic_options(),
                skip_test_files=self._config.skip_test_files,
                extra_test_path_patterns=tuple(self._config.extra_test_path_patterns),
            )
        return coerce_review_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )

    def get_code_files(self, options: ReviewOptions | None = None):
        options = self._coerce_options(options)
        files = self._repository.get_code_files(
            include_suffixed_sources=not options.use_retrieval_context
        )
        return self._filter_test_paths(files, options)

    def _filter_test_paths(
        self,
        paths,
        options: ReviewOptions,
    ) -> list[str]:
        if not options.skip_test_files:
            return list(paths)
        return [
            path for path in paths if not self._is_test_path_for_options(path, options)
        ]

    def _is_test_path_for_options(
        self,
        path: str,
        options: ReviewOptions,
        plugin=None,
    ) -> bool:
        if not options.skip_test_files:
            return False
        match_path = self._repository.normalize_match_path(path)
        plugin = plugin or self._repository.get_plugin_for_path(path)
        language = None
        plugin_patterns: list[str] = []
        if plugin is not None:
            get_name = getattr(plugin, "get_name", None)
            if callable(get_name):
                language = str(get_name() or "")
            get_patterns = getattr(plugin, "get_test_path_patterns", None)
            if callable(get_patterns):
                plugin_patterns = [str(pattern) for pattern in get_patterns()]
        return is_test_path(
            match_path,
            language=language,
            extra_patterns=(
                *self._config.extra_test_path_patterns,
                *options.extra_test_path_patterns,
                *plugin_patterns,
            ),
        )

    def review_file(
        self,
        file_path,
        options: ReviewOptions | None = None,
        *,
        use_retrieval_context: bool | None = None,
    ):
        options = self._coerce_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )
        if self._is_test_path_for_options(file_path, options):
            return None
        qe_code = qe_docs = None
        function_index = None
        if options.use_retrieval_context:
            qe_code, qe_docs = self._get_query_engines()
            function_index = self._repository.load_function_index()
        base_path = os.path.abspath(self._config.codebase_path)
        snippet = read_file_content(file_path)
        if not snippet:
            return None

        plugin = self._repository.get_plugin_for_path(file_path)
        if not plugin:
            return None

        language_prompts = plugin.get_prompts()
        context_prompt_template = self._config.plugin_config.get(
            "general_prompts", {}
        ).get("retrieve_context", "")

        formatted_context_prompt = context_prompt_template.format(file_path=file_path)
        relative_path = os.path.relpath(file_path, base_path)

        try:
            req: ReviewRequest = {
                "file_path": file_path,
                "snippet": snippet,
                "retriever_code": qe_code,
                "retriever_docs": qe_docs,
                "function_index": function_index,
                "function_index_codebase_path": base_path,
                "snippet_start_line": 1,
                "context_prompt": formatted_context_prompt,
                "language_prompts": language_prompts,
                "default_prompt_key": "security_review_file",
                "relative_file": relative_path,
                "mode": "file",
                "use_retrieval_context": options.use_retrieval_context,
                "review_mode": options.review_mode,
                "agentic_options": options.agentic,
            }
            return self._review_graph_factory().review(req)
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            if options.review_mode == "agentic":
                raise
            return None

    async def review_file_async(
        self,
        file_path,
        options: ReviewOptions | None = None,
        *,
        use_retrieval_context: bool | None = None,
    ):
        options = self._coerce_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )
        if self._is_test_path_for_options(file_path, options):
            return None
        qe_code = qe_docs = None
        function_index = None
        if options.use_retrieval_context:
            qe_code, qe_docs = self._get_query_engines()
            function_index = self._repository.load_function_index()
        base_path = os.path.abspath(self._config.codebase_path)
        snippet = read_file_content(file_path)
        if not snippet:
            return None

        plugin = self._repository.get_plugin_for_path(file_path)
        if not plugin:
            return None

        language_prompts = plugin.get_prompts()
        context_prompt_template = self._config.plugin_config.get(
            "general_prompts", {}
        ).get("retrieve_context", "")

        formatted_context_prompt = context_prompt_template.format(file_path=file_path)
        relative_path = os.path.relpath(file_path, base_path)

        try:
            req: ReviewRequest = {
                "file_path": file_path,
                "snippet": snippet,
                "retriever_code": qe_code,
                "retriever_docs": qe_docs,
                "function_index": function_index,
                "function_index_codebase_path": base_path,
                "snippet_start_line": 1,
                "context_prompt": formatted_context_prompt,
                "language_prompts": language_prompts,
                "default_prompt_key": "security_review_file",
                "relative_file": relative_path,
                "mode": "file",
                "use_retrieval_context": options.use_retrieval_context,
                "review_mode": options.review_mode,
                "agentic_options": options.agentic,
            }
            return await self._review_graph_factory().areview(req)
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            if options.review_mode == "agentic":
                raise
            return None

    def _invoke_review_file(
        self,
        review_fn,
        path: str,
        options: ReviewOptions,
    ):
        try:
            signature = inspect.signature(review_fn)
        except (TypeError, ValueError):
            signature = None

        if signature is not None:
            params = signature.parameters
            if "options" in params or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
            ):
                return review_fn(path, options=options)
            if "use_retrieval_context" in params:
                return review_fn(
                    path,
                    use_retrieval_context=options.use_retrieval_context,
                )

        if options.use_retrieval_context:
            return review_fn(path)

        raise TypeError(
            "review_file_func must accept 'options' or 'use_retrieval_context' "
            "when retrieval context is disabled"
        )

    def review_code(
        self,
        review_file_func=None,
        get_code_files_func=None,
        options: ReviewOptions | None = None,
        *,
        use_retrieval_context: bool | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> Iterator[dict | None]:
        options = self._coerce_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )
        files = (
            get_code_files_func()
            if get_code_files_func is not None
            else self.get_code_files(options=options)
        )
        files = self._filter_test_paths(files, options)
        if not files:
            return
        if self._config.async_llm_enabled:
            for result in _run_coroutine_sync(
                self._review_code_async(
                    files,
                    review_file_func=review_file_func,
                    options=options,
                    progress_callback=progress_callback,
                )
            ):
                yield result
            return
        total = len(files)
        completed = 0
        skipped = 0
        finding_count = 0
        review_fn = review_file_func or self.review_file
        with ThreadPoolExecutor(
            max_workers=self._config.review_max_workers
        ) as executor:
            for path in files:
                if progress_callback is not None:
                    progress_callback(
                        {
                            "event": "review.file.started",
                            "message": f"Reviewing {path}",
                            "current_file": path,
                            "completed_count": completed,
                            "total_files": total,
                            "skipped_files": skipped,
                            "finding_count": finding_count,
                        }
                    )
            future_to_path = {
                submit_with_current_context(
                    executor,
                    self._invoke_review_file,
                    review_fn,
                    path,
                    options,
                ): path
                for path in files
            }
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                except Exception as e:
                    logger.error(f"Error reviewing file {path}: {e}")
                    if options.review_mode == "agentic":
                        raise
                    completed += 1
                    skipped += 1
                    if progress_callback is not None:
                        progress_callback(
                            {
                                "event": "review.file.skipped",
                                "message": f"Skipped {path}",
                                "current_file": path,
                                "completed_count": completed,
                                "total_files": total,
                                "skipped_files": skipped,
                                "finding_count": finding_count,
                            }
                        )
                    yield None
                    continue
                if result:
                    completed += 1
                    reviews = (
                        result.get("reviews") if isinstance(result, dict) else None
                    )
                    if isinstance(reviews, list):
                        finding_count += len(reviews)
                    if progress_callback is not None:
                        progress_callback(
                            {
                                "event": "review.file.finished",
                                "message": f"Reviewed {path}",
                                "current_file": path,
                                "completed_count": completed,
                                "total_files": total,
                                "skipped_files": skipped,
                                "finding_count": finding_count,
                            }
                        )
                    yield result
                else:
                    completed += 1
                    skipped += 1
                    if progress_callback is not None:
                        progress_callback(
                            {
                                "event": "review.file.skipped",
                                "message": f"Skipped {path}",
                                "current_file": path,
                                "completed_count": completed,
                                "total_files": total,
                                "skipped_files": skipped,
                                "finding_count": finding_count,
                            }
                        )
                    yield None

    async def _review_code_async(
        self,
        files,
        *,
        review_file_func=None,
        options: ReviewOptions,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> list[dict | None]:
        total = len(files)
        completed = 0
        skipped = 0
        finding_count = 0
        review_fn = review_file_func or self.review_file_async
        for path in files:
            if progress_callback is not None:
                progress_callback(
                    {
                        "event": "review.file.started",
                        "message": f"Reviewing {path}",
                        "current_file": path,
                        "completed_count": completed,
                        "total_files": total,
                        "skipped_files": skipped,
                        "finding_count": finding_count,
                    }
                )

        semaphore = asyncio.Semaphore(self._config.review_max_workers)

        async def _review_one(path):
            async with semaphore:
                if review_file_func is not None:
                    return await asyncio.to_thread(
                        self._invoke_review_file,
                        review_fn,
                        path,
                        options,
                    )
                return await submit_with_current_context_async(
                    review_fn,
                    path,
                    options=options,
                )

        async def _review_one_with_path(path):
            try:
                return path, await _review_one(path), None
            except Exception as exc:
                return path, None, exc

        tasks = [asyncio.create_task(_review_one_with_path(path)) for path in files]
        results: list[dict | None] = []
        for task in asyncio.as_completed(tasks):
            path, result, error = await task
            if error is not None:
                logger.error(f"Error reviewing file {path}: {error}")
                if options.review_mode == "agentic":
                    raise error
                result = None

            if result:
                completed += 1
                reviews = result.get("reviews") if isinstance(result, dict) else None
                if isinstance(reviews, list):
                    finding_count += len(reviews)
                if progress_callback is not None:
                    progress_callback(
                        {
                            "event": "review.file.finished",
                            "message": f"Reviewed {path}",
                            "current_file": path,
                            "completed_count": completed,
                            "total_files": total,
                            "skipped_files": skipped,
                            "finding_count": finding_count,
                        }
                    )
                results.append(result)
                continue

            completed += 1
            skipped += 1
            if progress_callback is not None:
                progress_callback(
                    {
                        "event": "review.file.skipped",
                        "message": f"Skipped {path}",
                        "current_file": path,
                        "completed_count": completed,
                        "total_files": total,
                        "skipped_files": skipped,
                        "finding_count": finding_count,
                    }
                )
            results.append(None)
        return results

    def review_patch(
        self,
        patch_file,
        options: ReviewOptions | None = None,
        *,
        use_retrieval_context: bool | None = None,
    ):
        options = self._coerce_options(
            options,
            use_retrieval_context=use_retrieval_context,
        )
        qe_code = qe_docs = None
        function_index = None
        if options.use_retrieval_context:
            qe_code, qe_docs = self._get_query_engines()
            function_index = self._repository.load_function_index()
        patch_text = read_file_content(patch_file)
        try:
            diff = unidiff.PatchSet.from_string(patch_text)
            logger.info("Parsed the patch file successfully.")
        except Exception as e:
            logger.error(f"Error parsing patch file: {e}")
            return {"reviews": [], "overall_changes": ""}
        file_reviews = []
        summary_inputs: dict[str, list[tuple[dict, str, str]]] = {}
        base_path = os.path.abspath(self._config.codebase_path)
        metisignore_spec = self._repository.load_metisignore()
        for file_diff in diff:
            if file_diff.is_removed_file or file_diff.is_binary_file:
                continue
            resolved_patch_path = resolve_patch_path(base_path, file_diff.path)
            if resolved_patch_path is None:
                logger.warning(
                    "Skipping patch path outside codebase: %s", file_diff.path
                )
                continue
            abs_path, relative_path = resolved_patch_path
            if self._repository.is_metisignored(abs_path, spec=metisignore_spec):
                continue
            plugin = self._repository.get_plugin_for_path(relative_path)
            if not plugin:
                continue
            if self._is_test_path_for_options(relative_path, options, plugin=plugin):
                continue
            snippet = process_diff_file(
                self._config.codebase_path,
                file_diff,
                self._config.max_token_length,
                original_file_path=abs_path,
            )
            if not snippet:
                continue
            context_prompt = self._config.plugin_config.get("general_prompts", {}).get(
                "retrieve_context", ""
            )
            formatted_context = context_prompt.format(file_path=file_diff.path)

            language_prompts = plugin.get_prompts()
            try:
                original_content = read_file_content(abs_path)
                snippet_line_ranges = extract_added_line_ranges(file_diff)
                req: ReviewRequest = {
                    "file_path": abs_path,
                    "snippet": snippet,
                    "retriever_code": qe_code,
                    "retriever_docs": qe_docs,
                    "function_index": function_index,
                    "function_index_codebase_path": base_path,
                    "snippet_line_ranges": snippet_line_ranges,
                    "context_prompt": formatted_context,
                    "language_prompts": language_prompts,
                    "default_prompt_key": "security_review",
                    "relative_file": relative_path,
                    "mode": "patch",
                    "original_file": original_content or "",
                    "use_retrieval_context": options.use_retrieval_context,
                    "review_mode": options.review_mode,
                    "agentic_options": options.agentic,
                }
                review_dict = self._review_graph_factory().review(req)
            except Exception as e:
                logger.error(f"Error processing review for {file_diff.path}: {e}")
                if options.review_mode == "agentic":
                    raise
                review_dict = None
            if review_dict:
                file_reviews.append(review_dict)
                issues = "\n".join(
                    issue.get("issue", "") for issue in review_dict.get("reviews", [])
                )
                if not issues.strip():
                    continue
                summary_prompt = language_prompts["snippet_security_summary"]
                summary_prompt = apply_custom_guidance(
                    summary_prompt,
                    self._config.custom_prompt_text,
                    self._config.custom_guidance_precedence,
                )
                summary_inputs.setdefault(summary_prompt, []).append(
                    (review_dict, file_diff.path, issues)
                )
        overall_summaries = []
        for summary_prompt, entries in summary_inputs.items():
            file_issues_map = {file_path: issues for _, file_path, issues in entries}
            if (
                len(entries) == 1
                and summarize_changes is not _DEFAULT_SUMMARIZE_CHANGES
            ):
                file_path = entries[0][1]
                summary = summarize_changes(
                    self._config.llm_provider,
                    file_path,
                    entries[0][2],
                    summary_prompt,
                    callbacks=self._config.usage_runtime.hooks.callbacks,
                )
                summaries = {
                    "files": {file_path: summary},
                    "overall_summary": summary,
                }
            else:
                summaries = batch_summarize_changes(
                    self._config.llm_provider,
                    file_issues_map,
                    summary_prompt,
                    callbacks=self._config.usage_runtime.hooks.callbacks,
                    max_prompt_chars=max(
                        4000, int(self._config.max_token_length * 3.2)
                    ),
                )
            file_summaries = summaries.get("files", {})
            if not isinstance(file_summaries, dict):
                file_summaries = {}
            for review_dict, file_path, _issues in entries:
                changes_summary = str(file_summaries.get(file_path) or "").strip()
                if changes_summary:
                    review_dict["changes_summary"] = changes_summary
            overall_summary = str(summaries.get("overall_summary") or "").strip()
            if overall_summary:
                overall_summaries.append(overall_summary)
        overall_changes = "\n\n".join(overall_summaries)
        return {"reviews": file_reviews, "overall_changes": overall_changes}
