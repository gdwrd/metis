# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Mapping

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.utils import parse_json_output, retry_on_recursion_error

from .code_index import (
    FunctionIndex,
    ensure_embedding_safe_nodes,
    extract_function_nodes_from_document,
)

logger = logging.getLogger("metis")


def summarize_changes(llm_provider, file_path, issues, summary_prompt, callbacks=None):
    try:
        kwargs = {}
        if callbacks is not None:
            kwargs["callbacks"] = callbacks
        chat = llm_provider.get_chat_model(**kwargs)
        prompt_tmpl = ChatPromptTemplate.from_messages(
            [("system", "{system}"), ("user", "{input}")]
        )
        chain = prompt_tmpl | chat | StrOutputParser()
        return chain.invoke(
            {"system": summary_prompt or "", "input": issues or ""}
        ).strip()
    except Exception as e:
        logger.error(f"Error summarizing changes for {file_path}: {e}")
        return ""


def batch_summarize_changes(
    llm_provider,
    file_issues_map: Mapping[str, str],
    summary_prompt,
    callbacks=None,
    *,
    max_prompt_chars: int = 80000,
):
    pending = {
        str(file_path): str(issues or "")
        for file_path, issues in file_issues_map.items()
        if str(issues or "").strip()
    }
    if not pending:
        return {"files": {}, "overall_summary": ""}

    file_summaries: dict[str, str] = {}
    overall_summaries: list[str] = []
    for chunk in _chunk_summary_inputs(pending, max_prompt_chars=max_prompt_chars):
        parsed = _invoke_batch_summary(
            llm_provider,
            chunk,
            summary_prompt,
            callbacks=callbacks,
        )
        summaries = parsed.get("files", {})
        for file_path, summary in summaries.items():
            if str(summary or "").strip():
                file_summaries[str(file_path)] = str(summary).strip()
        overall = str(parsed.get("overall_summary") or "").strip()
        if overall:
            overall_summaries.append(overall)

    missing = [path for path in pending if path not in file_summaries]
    for path in missing:
        fallback = summarize_changes(
            llm_provider,
            path,
            pending[path],
            summary_prompt,
            callbacks=callbacks,
        )
        if fallback:
            file_summaries[path] = fallback

    overall_summary = "\n\n".join(overall_summaries).strip()
    if not overall_summary:
        overall_summary = "\n\n".join(
            file_summaries[path] for path in pending if file_summaries.get(path)
        ).strip()
    return {"files": file_summaries, "overall_summary": overall_summary}


def _chunk_summary_inputs(
    file_issues_map: Mapping[str, str],
    *,
    max_prompt_chars: int,
):
    limit = max(1000, int(max_prompt_chars or 80000))
    chunk: dict[str, str] = {}
    chunk_size = 0
    for file_path, issues in file_issues_map.items():
        entry_size = len(str(file_path)) + len(str(issues)) + 64
        if chunk and chunk_size + entry_size > limit:
            yield chunk
            chunk = {}
            chunk_size = 0
        chunk[file_path] = issues
        chunk_size += entry_size
    if chunk:
        yield chunk


def _invoke_batch_summary(
    llm_provider,
    file_issues_map: Mapping[str, str],
    summary_prompt,
    callbacks=None,
):
    try:
        kwargs = {}
        if callbacks is not None:
            kwargs["callbacks"] = callbacks
        chat = llm_provider.get_chat_model(**kwargs)
        prompt_tmpl = ChatPromptTemplate.from_messages(
            [("system", "{system}"), ("user", "{input}")]
        )
        chain = prompt_tmpl | chat | StrOutputParser()
        raw = chain.invoke(
            {
                "system": _batch_summary_system_prompt(summary_prompt),
                "input": _batch_summary_user_prompt(file_issues_map),
            }
        )
        return _parse_batch_summary_response(raw, file_issues_map.keys())
    except Exception as e:
        logger.error(f"Error batch summarizing changes: {e}")
        return {"files": {}, "overall_summary": ""}


def _batch_summary_system_prompt(summary_prompt) -> str:
    base = str(summary_prompt or "").strip()
    suffix = (
        "Summarize security findings across all files in one response. "
        "Return strict JSON with shape "
        '{"files":[{"file":"path","summary":"one paragraph"}],'
        '"overall_summary":"one paragraph"}. '
        "Use the exact file paths from the input and do not add markdown fences."
    )
    if not base:
        return suffix
    return f"{base}\n\n{suffix}"


def _batch_summary_user_prompt(file_issues_map: Mapping[str, str]) -> str:
    sections = []
    for file_path, issues in file_issues_map.items():
        sections.append(f"File: {file_path}\nIssues:\n{issues}")
    return "\n\n".join(sections)


def _parse_batch_summary_response(raw, expected_paths) -> dict[str, object]:
    parsed = parse_json_output(str(raw or ""))
    if not isinstance(parsed, dict):
        return {"files": {}, "overall_summary": str(raw or "").strip()}

    files = parsed.get("files", {})
    summaries: dict[str, str] = {}
    if isinstance(files, list):
        for item in files:
            if not isinstance(item, dict):
                continue
            path = str(item.get("file") or item.get("path") or "").strip()
            summary = str(item.get("summary") or "").strip()
            if path and summary:
                summaries[path] = summary
    elif isinstance(files, dict):
        summaries = {
            str(path): str(summary).strip()
            for path, summary in files.items()
            if str(summary or "").strip()
        }

    expected = {str(path) for path in expected_paths}
    summaries = {
        path: summary for path, summary in summaries.items() if path in expected
    }
    return {
        "files": summaries,
        "overall_summary": str(parsed.get("overall_summary") or "").strip(),
    }


def prepare_code_nodes_for_document(document, plugin, get_splitter_cached):
    function_nodes, function_index = extract_function_nodes_from_document(
        document, plugin
    )
    splitter = get_splitter_cached(plugin)
    splitter_nodes = retry_on_recursion_error(
        splitter.get_nodes_from_documents,
        [document],
    )
    if function_nodes:
        return function_nodes + splitter_nodes, function_index
    return splitter_nodes, function_index


def prepare_nodes_iter(
    code_docs,
    doc_docs,
    get_plugin_for_extension,
    get_splitter_cached,
    doc_splitter,
    *,
    max_workers: int = 1,
    base_function_index: FunctionIndex | None = None,
):
    """
    Generator that prepares nodes for code and docs
    """
    nodes_code = []
    nodes_docs = []
    function_index = base_function_index or FunctionIndex()
    code_documents = list(code_docs)
    worker_count = min(max(1, int(max_workers or 1)), max(1, len(code_documents)))
    thread_local = threading.local()

    def _plugin_splitter_key(plugin):
        get_name = getattr(plugin, "get_name", None)
        name = get_name() if callable(get_name) else plugin.__class__.__name__
        return f"{name}:{id(plugin)}"

    def _get_thread_splitter(plugin):
        cache = getattr(thread_local, "splitters", None)
        if cache is None:
            cache = {}
            thread_local.splitters = cache
        key = _plugin_splitter_key(plugin)
        splitter = cache.get(key)
        if splitter is None:
            splitter = plugin.get_splitter()
            cache[key] = splitter
        return splitter

    def _prepare_code_doc(document):
        ext = os.path.splitext(document.id_)[1].lower()
        plugin = get_plugin_for_extension(ext)
        if plugin:
            splitter_factory = (
                _get_thread_splitter if worker_count > 1 else get_splitter_cached
            )
            parsed_nodes, file_function_index = prepare_code_nodes_for_document(
                document,
                plugin,
                splitter_factory,
            )
            return document.id_, parsed_nodes, file_function_index
        return document.id_, [], FunctionIndex()

    if worker_count == 1:
        for d in code_documents:
            doc_id, parsed_nodes, file_function_index = _prepare_code_doc(d)
            function_index.remove_file(doc_id, rebuild=False)
            function_index.merge(file_function_index, rebuild=False)
            nodes_code.extend(ensure_embedding_safe_nodes(parsed_nodes))
            yield None
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(_prepare_code_doc, d) for d in code_documents]
            for future in futures:
                doc_id, parsed_nodes, file_function_index = future.result()
                function_index.remove_file(doc_id, rebuild=False)
                function_index.merge(file_function_index, rebuild=False)
                nodes_code.extend(ensure_embedding_safe_nodes(parsed_nodes))
                # yield regardless of success
                yield None

    function_index.rebuild_edges()

    for d in doc_docs:
        try:
            nodes_docs.extend(
                ensure_embedding_safe_nodes(doc_splitter.get_nodes_from_documents([d]))
            )
        except Exception as e:
            logger.warning(f"Could not parse docs for file {d.id_}: {e}")
        finally:
            yield None

    return nodes_code, nodes_docs, function_index


def apply_custom_guidance(base_prompt, custom_guidance, precedence_note):
    """Prepend precedence note and custom guidance to a base prompt.

    If custom_guidance is not set, returns base_prompt unchanged. The format is:
    [precedence_note]\n\nCustom Guidance:\n{custom_guidance}\n\n{base_prompt}
    """
    if not custom_guidance:
        return base_prompt
    guidance_block = f"Custom Guidance:\n{custom_guidance.strip()}"
    if precedence_note:
        return f"{precedence_note.strip()}\n\n{guidance_block}\n\n{base_prompt}"
    return f"{guidance_block}\n\n{base_prompt}"
