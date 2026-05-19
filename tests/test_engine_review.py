# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

import pytest

from metis.engine import MetisEngine
from metis.engine.options import ReviewOptions


def test_ask_question(engine):
    result = engine.ask_question("What is this?")
    assert "code" in result
    assert "docs" in result


def test_review_code_runs(engine):
    engine.review.review_file = Mock(
        return_value={"file": "test.py", "reviews": ["Issue"]}
    )
    results = list(engine.review.review_code())
    assert len(results) >= 1
    assert all("reviews" in r for r in results)


def test_review_code_async_mode_preserves_sync_iterator_contract(engine):
    engine._config.async_llm_enabled = True
    reviewed = []

    def _review_file(path, options=None):
        reviewed.append((path, options.use_retrieval_context))
        return {"file": path, "reviews": [{"issue": "Issue"}]}

    results = list(
        engine.review.review_code(
            review_file_func=_review_file,
            get_code_files_func=lambda: ["a.py", "b.py"],
            options=ReviewOptions(use_retrieval_context=False),
        )
    )

    assert sorted(item["file"] for item in results) == ["a.py", "b.py"]
    assert sorted(reviewed) == [("a.py", False), ("b.py", False)]


def test_review_patch_parses_and_reviews(engine, monkeypatch, tmp_path):
    patch = """--- a/test.py
+++ b/test.py
@@ -0,0 +1,2 @@
+print('Hello')
+print('World')
"""

    # Write patch to a temporary file because review_patch expects a file path
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch)

    # Stub the ReviewGraph used internally so we don't rely on LLMs
    class _DummyReviewGraph:
        def review(self, _req):
            return {"file": "test.py", "reviews": [{"issue": "Issue"}]}

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    # Ensure summaries are simple strings, not Mocks
    import metis.engine.review_service as review_service_mod

    monkeypatch.setattr(
        review_service_mod,
        "batch_summarize_changes",
        lambda *_a, **_k: {
            "files": {"test.py": "summary"},
            "overall_summary": "summary",
        },
    )

    result = engine.review.review_patch(str(patch_file))
    assert "reviews" in result and isinstance(result["reviews"], list)
    assert any(r.get("file") == "test.py" for r in result["reviews"])
    assert result["overall_changes"] == "summary"


def test_review_patch_batches_summaries_for_multiple_files(
    engine, monkeypatch, tmp_path
):
    patch = """--- a/one.py
+++ b/one.py
@@ -0,0 +1 @@
+print('one')
--- a/two.py
+++ b/two.py
@@ -0,0 +1 @@
+print('two')
"""
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch, encoding="utf-8")

    class _DummyReviewGraph:
        def __init__(self):
            self.calls = []

        def review(self, req):
            self.calls.append(req["relative_file"])
            return {
                "file": req["relative_file"],
                "reviews": [{"issue": f"Issue in {req['relative_file']}"}],
            }

    graph = _DummyReviewGraph()
    monkeypatch.setattr(engine, "_get_review_graph", lambda: graph)

    import metis.engine.review_service as review_service_mod

    calls = []

    def _batch(_llm, file_issues_map, _prompt, **_kwargs):
        calls.append(dict(file_issues_map))
        return {
            "files": {path: f"summary {path}" for path in file_issues_map},
            "overall_summary": "overall summary",
        }

    monkeypatch.setattr(review_service_mod, "batch_summarize_changes", _batch)

    result = engine.review.review_patch(str(patch_file), use_retrieval_context=False)

    assert graph.calls == ["one.py", "two.py"]
    assert calls == [{"one.py": "Issue in one.py", "two.py": "Issue in two.py"}]
    assert result["overall_changes"] == "overall summary"
    assert [item["changes_summary"] for item in result["reviews"]] == [
        "summary one.py",
        "summary two.py",
    ]


def test_review_patch_handles_parse_error(engine, tmp_path):
    bad_patch_file = tmp_path / "bad.diff"
    bad_patch_file.write_text("INVALID PATCH FORMAT")
    result = engine.review.review_patch(str(bad_patch_file))
    assert "reviews" in result
    assert result["reviews"] == []


def test_review_file_no_index_skips_query_engine_init(engine, monkeypatch, tmp_path):
    sample = tmp_path / "sample.c"
    sample.write_text("int main(){return 0;}", encoding="utf-8")

    class _DummyReviewGraph:
        def review(self, req):
            assert req["use_retrieval_context"] is False
            assert req["retriever_code"] is None
            assert req["retriever_docs"] is None
            return {"file": "sample.c", "reviews": []}

    engine.vector_backend.get_query_engines.reset_mock()
    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    result = engine.review.review_file(str(sample), use_retrieval_context=False)

    assert result["reviews"] == []
    engine.vector_backend.get_query_engines.assert_not_called()


def test_review_patch_no_index_skips_query_engine_init(engine, monkeypatch, tmp_path):
    patch = """--- a/test.py
+++ b/test.py
@@ -0,0 +1 @@
+print('Hello')
"""
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch, encoding="utf-8")

    class _DummyReviewGraph:
        def review(self, req):
            assert req["use_retrieval_context"] is False
            assert req["retriever_code"] is None
            assert req["retriever_docs"] is None
            return {"file": "test.py", "reviews": []}

    engine.vector_backend.get_query_engines.reset_mock()
    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    result = engine.review.review_patch(str(patch_file), use_retrieval_context=False)

    assert isinstance(result["reviews"], list)
    engine.vector_backend.get_query_engines.assert_not_called()


def test_review_patch_rejects_traversal_path_before_file_read(
    engine, monkeypatch, tmp_path
):
    secret = tmp_path / "secret.py"
    secret.write_text("print('do not leak')\n", encoding="utf-8")
    patch = """--- a/../secret.py
+++ b/../secret.py
@@ -0,0 +1 @@
+print('changed')
"""
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch, encoding="utf-8")

    class _DummyReviewGraph:
        def review(self, _req):
            raise AssertionError("out-of-repo patch path should not be reviewed")

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    result = engine.review.review_patch(str(patch_file), use_retrieval_context=False)

    assert result == {"reviews": [], "overall_changes": ""}


def test_review_patch_rejects_absolute_path_before_file_read(
    engine, monkeypatch, tmp_path
):
    secret = tmp_path / "secret.py"
    secret.write_text("print('do not leak')\n", encoding="utf-8")
    patch = f"""--- {secret}
+++ {secret}
@@ -0,0 +1 @@
+print('changed')
"""
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch, encoding="utf-8")

    class _DummyReviewGraph:
        def review(self, _req):
            raise AssertionError("absolute patch path should not be reviewed")

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    result = engine.review.review_patch(str(patch_file), use_retrieval_context=False)

    assert result == {"reviews": [], "overall_changes": ""}


def test_review_file_agentic_propagates_review_graph_failure(
    engine, monkeypatch, tmp_path
):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')\n", encoding="utf-8")

    class _RaisingReviewGraph:
        def review(self, _req):
            raise RuntimeError("provider unavailable")

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _RaisingReviewGraph())

    with pytest.raises(RuntimeError, match="provider unavailable"):
        engine.review.review_file(
            str(sample),
            options=ReviewOptions(use_retrieval_context=False, review_mode="agentic"),
        )


def test_review_patch_agentic_propagates_review_graph_failure(
    engine, monkeypatch, tmp_path
):
    patch = """--- a/test.py
+++ b/test.py
@@ -0,0 +1 @@
+print('Hello')
"""
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch, encoding="utf-8")

    class _RaisingReviewGraph:
        def review(self, _req):
            raise RuntimeError("provider unavailable")

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _RaisingReviewGraph())

    with pytest.raises(RuntimeError, match="provider unavailable"):
        engine.review.review_patch(
            str(patch_file),
            options=ReviewOptions(use_retrieval_context=False, review_mode="agentic"),
        )


def test_review_code_skips_test_files_when_enabled(tmp_path, dummy_backend, dummy_llm):
    codebase = tmp_path / "repo"
    (codebase / "src").mkdir(parents=True)
    (codebase / "tests").mkdir()
    (codebase / "src" / "app.py").write_text("print('prod')\n", encoding="utf-8")
    (codebase / "tests" / "test_app.py").write_text("print('test')\n", encoding="utf-8")
    engine = MetisEngine(
        codebase_path=str(codebase),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        skip_test_files=True,
    )
    reviewed = []

    def _review_file(path, options=None):
        reviewed.append(path)
        return {"file": path, "reviews": [{"issue": "Issue"}]}

    results = list(
        engine.review.review_code(
            review_file_func=_review_file,
            options=ReviewOptions(use_retrieval_context=False, skip_test_files=True),
        )
    )

    assert len(results) == 1
    assert reviewed == [str(codebase / "src" / "app.py")]


def test_review_file_skips_test_path_before_graph_call(engine, monkeypatch, tmp_path):
    sample = tmp_path / "tests" / "test_sample.py"
    sample.parent.mkdir()
    sample.write_text("print('test')\n", encoding="utf-8")

    class _RaisingReviewGraph:
        def review(self, _req):
            raise AssertionError("test file should not be reviewed")

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _RaisingReviewGraph())

    assert (
        engine.review.review_file(
            str(sample),
            options=ReviewOptions(use_retrieval_context=False, skip_test_files=True),
        )
        is None
    )
