# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os
from typing import TYPE_CHECKING, Any

from metis.engine.options import TriageOptions, coerce_triage_options
from metis.engine.graphs.triage.retrieval import _retrieve_context_deterministic
from metis.engine.graphs.types import TriageRequest
from metis.engine.path_heuristics import is_test_path
from metis.engine.graphs.utils import synthesize_context
from metis.sarif.triage import (
    apply_triage_result,
    extract_findings,
    load_sarif_file,
    save_sarif_file,
)
from metis.usage import submit_with_current_context, submit_with_current_context_async

logger = logging.getLogger("metis")

MAX_TRIAGE_GROUP_FINDINGS = 20
MAX_TRIAGE_GROUP_QUERY_CHARS = 12000


def _run_coroutine_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(lambda: asyncio.run(coro)).result()


class TriageServiceExecutionMixin:
    if TYPE_CHECKING:
        codebase_path: str
        extra_test_path_patterns: list[str]
        max_workers: int
        skip_test_files: bool
        triage_checkpoint_every: int

        def _get_plugin_for_extension(self, extension: str) -> Any: ...

        def _get_thread_triage_analyzer(self, file_path: str) -> Any: ...

        def _get_thread_triage_graph(self) -> Any: ...

        def _get_thread_triage_query_engines(self) -> tuple[Any, Any]: ...

    def _invoke_callback(self, callback, *args, **kwargs) -> None:
        if not callable(callback):
            return
        try:
            callback(*args, **kwargs)
        except Exception:
            pass

    def _emit_triage_progress(
        self, progress_callback, total: int, event: str, **kwargs
    ):
        self._invoke_callback(
            progress_callback, {"event": event, "total": total, **kwargs}
        )

    def _run_triage_checkpoint(
        self,
        checkpoint_callback,
        triaged_payload: dict,
        processed: int,
        total: int,
    ) -> None:
        self._invoke_callback(checkpoint_callback, triaged_payload, processed, total)

    def _build_triage_request(
        self,
        *,
        finding,
        retriever_code,
        retriever_docs,
        debug_callback,
        options: TriageOptions,
        shared_retrieval_context: str | None = None,
        shared_retrieval_query: str | None = None,
        tool_executor=None,
    ) -> TriageRequest:
        analyzer = self._get_thread_triage_analyzer(finding.file_path)
        return {
            "finding_message": finding.message,
            "finding_file_path": finding.file_path,
            "finding_line": finding.line,
            "finding_rule_id": finding.rule_id,
            "finding_snippet": finding.snippet,
            "finding_source_tool": getattr(finding, "source_tool", ""),
            "finding_is_metis": bool(getattr(finding, "is_metis_source", False)),
            "finding_explanation": getattr(finding, "explanation", ""),
            "retriever_code": retriever_code,
            "retriever_docs": retriever_docs,
            "debug_callback": debug_callback,
            "triage_analyzer": analyzer,
            "triage_codebase_path": self.codebase_path,
            "use_retrieval_context": options.use_retrieval_context,
            "triage_evidence_budget": options.triage_evidence_budget,
            "triage_evidence_retry_timeout_seconds": (
                options.triage_evidence_retry_timeout_seconds
            ),
            "triage_tool_executor": tool_executor,
            "shared_retrieval_context": shared_retrieval_context or "",
            "shared_retrieval_query": shared_retrieval_query or "",
        }

    def _triage_one_finding(
        self,
        finding,
        *,
        debug_callback,
        options: TriageOptions,
        shared_retrieval_context: str | None = None,
        shared_retrieval_query: str | None = None,
        tool_executor=None,
    ) -> dict:
        retriever_code = retriever_docs = None
        if options.use_retrieval_context and shared_retrieval_context is None:
            retriever_code, retriever_docs = self._get_thread_triage_query_engines()
        req = self._build_triage_request(
            finding=finding,
            retriever_code=retriever_code,
            retriever_docs=retriever_docs,
            debug_callback=debug_callback,
            options=options,
            shared_retrieval_context=shared_retrieval_context,
            shared_retrieval_query=shared_retrieval_query,
            tool_executor=tool_executor,
        )
        return self._get_thread_triage_graph().triage(req)

    def _build_group_retrieval_query(self, findings) -> str:
        return self._query_text_for_group(findings)

    def _build_group_retrieval_context(self, findings, options: TriageOptions):
        if not options.use_retrieval_context:
            return None, None
        retriever_code, retriever_docs = self._get_thread_triage_query_engines()
        query = self._build_group_retrieval_query(findings)
        code = _retrieve_context_deterministic(retriever_code, query)
        docs = _retrieve_context_deterministic(retriever_docs, query)
        return synthesize_context(code, docs), query

    def _triage_one_finding_with_shared_context(
        self,
        idx,
        finding,
        *,
        debug_callback,
        options: TriageOptions,
        shared_context,
        shared_query,
        tool_executor,
    ):
        try:
            decision = self._triage_one_finding(
                finding,
                debug_callback=debug_callback,
                options=options,
                shared_retrieval_context=shared_context,
                shared_retrieval_query=shared_query,
                tool_executor=tool_executor,
            )
            error = None
        except Exception as exc:
            decision = None
            error = exc
        return idx, finding, decision, error

    async def _triage_one_finding_with_shared_context_async(
        self,
        idx,
        finding,
        *,
        debug_callback,
        options: TriageOptions,
        shared_context,
        shared_query,
        tool_executor,
    ):
        try:
            decision = await self._triage_one_finding_async(
                finding,
                debug_callback=debug_callback,
                options=options,
                shared_retrieval_context=shared_context,
                shared_retrieval_query=shared_query,
                tool_executor=tool_executor,
            )
            error = None
        except Exception as exc:
            decision = None
            error = exc
        return idx, finding, decision, error

    async def _triage_one_finding_async(
        self,
        finding,
        *,
        debug_callback,
        options: TriageOptions,
        shared_retrieval_context: str | None = None,
        shared_retrieval_query: str | None = None,
        tool_executor=None,
    ) -> dict:
        retriever_code = retriever_docs = None
        if options.use_retrieval_context and shared_retrieval_context is None:
            retriever_code, retriever_docs = self._get_thread_triage_query_engines()
        req = self._build_triage_request(
            finding=finding,
            retriever_code=retriever_code,
            retriever_docs=retriever_docs,
            debug_callback=debug_callback,
            options=options,
            shared_retrieval_context=shared_retrieval_context,
            shared_retrieval_query=shared_retrieval_query,
            tool_executor=tool_executor,
        )
        graph = self._get_thread_triage_graph()
        atriage = getattr(graph, "atriage", None)
        if callable(atriage):
            return await atriage(req)
        return await asyncio.to_thread(graph.triage, req)

    @classmethod
    def _split_large_group(cls, group):
        chunk: list = []
        for item in group:
            candidate = [*chunk, item]
            if chunk and (
                len(candidate) > MAX_TRIAGE_GROUP_FINDINGS
                or len(cls._query_text_for_group(candidate))
                > MAX_TRIAGE_GROUP_QUERY_CHARS
            ):
                yield chunk
                chunk = [item]
                continue
            chunk = candidate
        if chunk:
            yield chunk

    @staticmethod
    def _query_text_for_group(group) -> str:
        first = group[0][1]
        lines = [
            "Triage all SARIF findings for this file using shared retrieval context.",
            f"File: {first.file_path}",
        ]
        for idx, finding in group:
            lines.append(
                (
                    f"Finding {idx}: rule={finding.rule_id}; "
                    f"line={finding.line}; message={finding.message}; "
                    f"snippet={finding.snippet}"
                )
            )
        lines.append(
            "Question: What local definitions, call paths, documentation, and nearby context help validate or reject these findings?"
        )
        return "\n".join(lines)

    @staticmethod
    def _group_findings_by_file(findings):
        groups = defaultdict(list)
        for idx, finding in enumerate(findings, start=1):
            groups[str(finding.file_path or "")].append((idx, finding))
        split_groups = []
        for group in groups.values():
            split_groups.extend(TriageServiceExecutionMixin._split_large_group(group))
        return split_groups

    def _is_test_path_finding(self, finding, options: TriageOptions) -> bool:
        if not options.skip_test_files:
            return False
        ext = os.path.splitext(finding.file_path or "")[1].lower()
        plugin = self._get_plugin_for_extension(ext) if ext else None
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
            finding.file_path,
            language=language,
            extra_patterns=(
                *self.extra_test_path_patterns,
                *options.extra_test_path_patterns,
                *plugin_patterns,
            ),
        )

    def _record_triage_success(self, triaged_payload: dict, finding, decision: dict):
        apply_triage_result(
            triaged_payload,
            run_index=finding.run_index,
            result_index=finding.result_index,
            status=decision["status"],
            reason=decision["reason"],
        )

    def _record_triage_failure(self, finding, exc):
        logger.warning(
            "Skipping triage annotation for run=%s result=%s due to failure: %s",
            finding.run_index,
            finding.result_index,
            exc,
        )

    def _handle_finding_result(
        self,
        *,
        triaged_payload: dict,
        finding,
        total: int,
        idx: int,
        decision: dict | None,
        error: Exception | None,
        progress_callback,
        checkpoint_callback,
        processed: int,
    ) -> int:
        if error is not None:
            self._record_triage_failure(finding, error)
            self._emit_triage_progress(
                progress_callback,
                total,
                "error",
                index=idx,
                finding=finding,
                error=str(error),
            )
        else:
            self._record_triage_success(triaged_payload, finding, decision or {})
            self._emit_triage_progress(
                progress_callback,
                total,
                "done",
                index=idx,
                finding=finding,
                decision=decision,
            )

        processed += 1
        self._run_triage_checkpoint(
            checkpoint_callback, triaged_payload, processed, total
        )
        return processed

    def _triage_findings_parallel(
        self,
        *,
        findings,
        triaged_payload: dict,
        total: int,
        progress_callback,
        debug_callback,
        checkpoint_callback,
        options: TriageOptions,
    ) -> None:
        if getattr(self, "async_llm_enabled", False):
            _run_coroutine_sync(
                self._triage_findings_async(
                    findings=findings,
                    triaged_payload=triaged_payload,
                    total=total,
                    progress_callback=progress_callback,
                    debug_callback=debug_callback,
                    checkpoint_callback=checkpoint_callback,
                    options=options,
                )
            )
            return
        processed = 0
        groups = self._group_findings_by_file(findings)
        with (
            ThreadPoolExecutor(max_workers=self.max_workers) as executor,
            ThreadPoolExecutor(max_workers=self.max_workers) as tool_executor,
        ):
            future_map = {}
            for group in groups:
                for idx, finding in group:
                    self._emit_triage_progress(
                        progress_callback,
                        total,
                        "start",
                        index=idx,
                        finding=finding,
                    )
                shared_context, shared_query = self._build_group_retrieval_context(
                    group,
                    options=options,
                )
                for idx, finding in group:
                    future = submit_with_current_context(
                        executor,
                        self._triage_one_finding_with_shared_context,
                        idx,
                        finding,
                        debug_callback=debug_callback,
                        options=options,
                        shared_context=shared_context,
                        shared_query=shared_query,
                        tool_executor=tool_executor,
                    )
                    future_map[future] = (idx, finding)

            for future in as_completed(future_map):
                idx, finding = future_map[future]
                try:
                    idx, finding, decision, error = future.result()
                except Exception as exc:
                    decision = None
                    error = exc
                processed = self._handle_finding_result(
                    triaged_payload=triaged_payload,
                    finding=finding,
                    total=total,
                    idx=idx,
                    decision=decision,
                    error=error,
                    progress_callback=progress_callback,
                    checkpoint_callback=checkpoint_callback,
                    processed=processed,
                )

    async def _triage_findings_async(
        self,
        *,
        findings,
        triaged_payload: dict,
        total: int,
        progress_callback,
        debug_callback,
        checkpoint_callback,
        options: TriageOptions,
    ) -> None:
        processed = 0
        groups = self._group_findings_by_file(findings)
        semaphore = asyncio.Semaphore(self.max_workers)
        with ThreadPoolExecutor(max_workers=self.max_workers) as tool_executor:
            tasks = []
            for group in groups:
                for idx, finding in group:
                    self._emit_triage_progress(
                        progress_callback,
                        total,
                        "start",
                        index=idx,
                        finding=finding,
                    )
                shared_context, shared_query = self._build_group_retrieval_context(
                    group,
                    options=options,
                )
                for idx, finding in group:

                    async def _run_one(
                        idx=idx,
                        finding=finding,
                        shared_context=shared_context,
                        shared_query=shared_query,
                    ):
                        async with semaphore:
                            return await submit_with_current_context_async(
                                self._triage_one_finding_with_shared_context_async,
                                idx,
                                finding,
                                debug_callback=debug_callback,
                                options=options,
                                shared_context=shared_context,
                                shared_query=shared_query,
                                tool_executor=tool_executor,
                            )

                    tasks.append(asyncio.create_task(_run_one()))

            for task in asyncio.as_completed(tasks):
                try:
                    idx, finding, decision, error = await task
                except Exception as exc:
                    idx = 0
                    finding = None
                    decision = None
                    error = exc
                if finding is None:
                    logger.warning(
                        "Skipping triage annotation due to failure: %s", error
                    )
                    continue
                processed = self._handle_finding_result(
                    triaged_payload=triaged_payload,
                    finding=finding,
                    total=total,
                    idx=idx,
                    decision=decision,
                    error=error,
                    progress_callback=progress_callback,
                    checkpoint_callback=checkpoint_callback,
                    processed=processed,
                )

    def triage_sarif_payload(
        self,
        payload: dict,
        progress_callback=None,
        debug_callback=None,
        checkpoint_callback=None,
        options: TriageOptions | None = None,
        include_triaged: bool | None = None,
        use_retrieval_context: bool | None = None,
    ) -> dict:
        options = coerce_triage_options(
            options,
            include_triaged=include_triaged,
            use_retrieval_context=use_retrieval_context,
            skip_test_files=self.skip_test_files if options is None else None,
            extra_test_path_patterns=(
                tuple(self.extra_test_path_patterns) if options is None else None
            ),
        )
        triaged = payload
        findings = extract_findings(
            triaged,
            include_triaged=options.include_triaged,
        )
        findings = [
            finding
            for finding in findings
            if not self._is_test_path_finding(finding, options)
        ]
        if not findings:
            return triaged

        total = len(findings)

        self._triage_findings_parallel(
            findings=findings,
            triaged_payload=triaged,
            total=total,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_callback=checkpoint_callback,
            options=options,
        )

        return triaged

    def triage_sarif_file(
        self,
        input_path: str,
        output_path: str | None = None,
        progress_callback=None,
        debug_callback=None,
        checkpoint_callback=None,
        checkpoint_every: int | None = None,
        options: TriageOptions | None = None,
        include_triaged: bool | None = None,
        use_retrieval_context: bool | None = None,
    ) -> str:
        options = coerce_triage_options(
            options,
            include_triaged=include_triaged,
            use_retrieval_context=use_retrieval_context,
            skip_test_files=self.skip_test_files if options is None else None,
            extra_test_path_patterns=(
                tuple(self.extra_test_path_patterns) if options is None else None
            ),
        )
        payload = load_sarif_file(input_path)
        target_path = output_path or input_path

        every = checkpoint_every
        if every is None:
            every = self.triage_checkpoint_every
        try:
            every = int(every)
        except Exception:
            every = 0
        if every < 1:
            every = 0

        def _checkpoint(triaged_payload: dict, processed: int, total: int):
            if every <= 0:
                return
            if processed >= total:
                return
            if processed % every != 0:
                return
            save_sarif_file(target_path, triaged_payload)
            self._invoke_callback(
                checkpoint_callback,
                triaged_payload,
                processed,
                total,
            )

        triaged = self.triage_sarif_payload(
            payload,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_callback=_checkpoint,
            options=options,
        )
        save_sarif_file(target_path, triaged)
        return target_path
