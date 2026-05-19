# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
import sys
from unittest.mock import Mock

import metis.engine.indexing_service as indexing_service_mod
from llama_index.core.schema import Document, MetadataMode, TextNode
from metis.engine.code_index import (
    DEFAULT_EXCLUDED_EMBED_METADATA_KEYS,
    DEFAULT_EMBEDDING_TOKEN_LIMIT,
    FunctionEntry,
    FunctionIndex,
    _build_parent_map,
    _split_text_for_embedding,
    _text_nodes_for_entry,
    _walk,
    ensure_embedding_safe_nodes,
    extract_function_nodes_from_document,
    format_related_functions,
)
from metis.utils import count_tokens
from metis.engine import MetisEngine
from metis.engine.helpers import prepare_code_nodes_for_document, prepare_nodes_iter
from metis.engine.retrieval_cache import RetrievalCache
from metis.plugins.javascript_plugin import JavaScriptPlugin
from metis.plugins.python_plugin import PythonPlugin
from metis.plugins.typescript_plugin import TypeScriptPlugin


def test_python_function_index_extracts_callees_callers_and_round_trips(tmp_path):
    source = (
        "def validate(value):\n"
        "    return value > 0\n"
        "\n"
        "def handle(value):\n"
        "    return validate(value)\n"
    )
    document = SimpleNamespace(text=source, id_="repo/app.py")

    nodes, index = extract_function_nodes_from_document(document, PythonPlugin({}))

    assert len(nodes) == 2
    assert isinstance(nodes[0].metadata["callees"], str)
    assert {node.ref_doc_id for node in nodes} == {"repo/app.py"}
    assert "repo/app.py::handle" in index.functions
    assert index.functions["repo/app.py::handle"].callees == ["repo/app.py::validate"]
    assert index.functions["repo/app.py::validate"].callers == ["repo/app.py::handle"]
    assert index.by_name["validate"] == ["repo/app.py::validate"]

    index_path = tmp_path / "function_index.json"
    index.write(index_path)
    loaded = FunctionIndex.read(index_path)

    assert loaded.to_dict()["functions"] == index.to_dict()["functions"]


def test_python_function_index_resolves_self_method_calls():
    source = (
        "class Handler:\n"
        "    def validate(self, value):\n"
        "        return value > 0\n"
        "\n"
        "    def handle(self, value):\n"
        "        return self.validate(value)\n"
    )
    document = SimpleNamespace(text=source, id_="repo/app.py")

    _nodes, index = extract_function_nodes_from_document(document, PythonPlugin({}))

    assert index.functions["repo/app.py::handle"].callees == ["repo/app.py::validate"]


def test_javascript_function_index_handles_arrow_assignment():
    source = (
        "function validate(value) { return value > 0; }\n"
        "const handle = (value) => validate(value);\n"
    )
    document = SimpleNamespace(text=source, id_="repo/app.js")

    _nodes, index = extract_function_nodes_from_document(document, JavaScriptPlugin({}))

    assert sorted(index.by_name) == ["handle", "validate"]
    assert index.functions["repo/app.js::handle"].callees == ["repo/app.js::validate"]


def test_javascript_function_index_resolves_member_calls():
    source = (
        "function validate(value) { return value > 0; }\n"
        "function handle(value) { return validator.validate(value); }\n"
    )
    document = SimpleNamespace(text=source, id_="repo/app.js")

    _nodes, index = extract_function_nodes_from_document(document, JavaScriptPlugin({}))

    assert index.functions["repo/app.js::handle"].call_names == ["validate"]


def test_tsx_function_index_uses_tsx_parser_after_jsx():
    source = (
        "const View = () => <div />;\n"
        "\n"
        "function validate(value: number) {\n"
        "  return value > 0;\n"
        "}\n"
    )
    document = SimpleNamespace(text=source, id_="repo/view.tsx")

    _nodes, index = extract_function_nodes_from_document(document, TypeScriptPlugin({}))

    assert "repo/view.tsx::validate" in index.functions


def test_prepare_code_nodes_keeps_splitter_chunks_with_function_nodes():
    source = "def handle(value):\n    return value\n"
    document = SimpleNamespace(text=source, id_="repo/app.py")

    class _Splitter:
        def get_nodes_from_documents(self, _documents):
            return ["splitter-node"]

    nodes, index = prepare_code_nodes_for_document(
        document,
        PythonPlugin({}),
        lambda _plugin: _Splitter(),
    )

    assert "splitter-node" in nodes
    assert len(index.functions) == 1
    assert len(nodes) == 2


def test_prepare_code_nodes_supports_javascript_without_plugin_config():
    source = (
        "function validate(value) { return value > 0; }\n"
        "const handle = (value) => validate(value);\n"
    )
    document = Document(text=source, id_="repo/app.js")

    nodes, index = prepare_code_nodes_for_document(
        document,
        JavaScriptPlugin({}),
        lambda plugin: plugin.get_splitter(),
    )

    assert nodes
    assert "repo/app.js::handle" in index.functions
    assert index.functions["repo/app.js::handle"].callees == ["repo/app.js::validate"]


def test_prepare_code_nodes_supports_jsx_without_plugin_config():
    source = (
        "const View = () => <div onClick={() => handle()}>Hi</div>;\n"
        "function handle() { return 1; }\n"
    )
    document = Document(text=source, id_="repo/app.jsx")

    nodes, index = prepare_code_nodes_for_document(
        document,
        JavaScriptPlugin({}),
        lambda plugin: plugin.get_splitter(),
    )

    assert nodes
    assert "repo/app.jsx::handle" in index.functions
    assert "repo/app.jsx::{" not in index.functions


def test_prepare_code_nodes_preserves_splitter_failure_contract():
    source = "def handle(value):\n    return value\n"
    document = SimpleNamespace(text=source, id_="repo/app.py")

    class _BrokenSplitter:
        def get_nodes_from_documents(self, _documents):
            raise RuntimeError("splitter failed")

    try:
        prepare_code_nodes_for_document(
            document,
            PythonPlugin({}),
            lambda _plugin: _BrokenSplitter(),
        )
    except RuntimeError as exc:
        assert str(exc) == "splitter failed"
    else:
        raise AssertionError("splitter failure should propagate")


def test_prepare_code_nodes_retries_splitter_recursion_error():
    source = "def handle(value):\n    return value\n"
    document = SimpleNamespace(text=source, id_="repo/app.py")
    original_limit = sys.getrecursionlimit()

    class _DeepSplitter:
        def __init__(self):
            self.calls = 0

        def get_nodes_from_documents(self, _documents):
            self.calls += 1
            if sys.getrecursionlimit() <= original_limit:
                raise RecursionError("too deep")
            return ["splitter-node"]

    splitter = _DeepSplitter()

    nodes, index = prepare_code_nodes_for_document(
        document,
        PythonPlugin({}),
        lambda _plugin: splitter,
    )

    assert "splitter-node" in nodes
    assert len(index.functions) == 1
    assert splitter.calls == 2
    assert sys.getrecursionlimit() == original_limit


def test_function_index_persists_file_hashes(tmp_path):
    index = FunctionIndex()
    index.set_file_hash("repo/app.py", "hash-1")

    index_path = tmp_path / "function_index.json"
    index.write(index_path)
    loaded = FunctionIndex.read(index_path)

    assert loaded.file_hash_matches("repo/app.py", "hash-1")
    assert not loaded.file_hash_matches("repo/app.py", "hash-2")


def test_prepare_nodes_iter_reuses_thread_local_splitters_in_parallel():
    documents = [
        Document(text="alpha", id_="repo/a.demo"),
        Document(text="beta", id_="repo/b.demo"),
        Document(text="gamma", id_="repo/c.demo"),
        Document(text="delta", id_="repo/d.demo"),
    ]

    class _Splitter:
        def __init__(self, index):
            self.index = index

        def get_nodes_from_documents(self, docs):
            return [f"node-{self.index}:{docs[0].id_}"]

    class _Plugin:
        def __init__(self):
            self.created = 0

        def get_name(self):
            return "demo"

        def get_function_node_types(self):
            return {}

        def get_splitter(self):
            self.created += 1
            return _Splitter(self.created)

    plugin = _Plugin()
    iterator = prepare_nodes_iter(
        documents,
        [],
        lambda _ext: plugin,
        lambda _plugin: (_ for _ in ()).throw(
            AssertionError("parallel code parsing should not use cached splitters")
        ),
        object(),
        max_workers=2,
    )

    while True:
        try:
            next(iterator)
        except StopIteration as exc:
            nodes_code, nodes_docs, function_index = exc.value
            break

    assert nodes_docs == []
    assert {node.split(":", 1)[1] for node in nodes_code} == {
        "repo/a.demo",
        "repo/b.demo",
        "repo/c.demo",
        "repo/d.demo",
    }
    assert {node.split(":", 1)[0] for node in nodes_code} <= {"node-1", "node-2"}
    assert 1 <= plugin.created <= 2
    assert function_index.file_hash_matches("repo/a.demo", documents[0].hash)
    assert function_index.file_hash_matches("repo/b.demo", documents[1].hash)
    assert function_index.file_hash_matches("repo/c.demo", documents[2].hash)
    assert function_index.file_hash_matches("repo/d.demo", documents[3].hash)


def test_function_text_nodes_split_large_functions_under_embedding_token_limit():
    body = "def handle():\n" + ("    value += 1\n" * 3000)
    document_text = body + "\n"
    entry = FunctionEntry(
        qualified_name="repo/app.py::handle",
        name="handle",
        file="repo/app.py",
        start_line=1,
        end_line=len(document_text.splitlines()),
        signature="def handle():",
        language="python",
    )

    nodes = _text_nodes_for_entry(entry, document_text, source_doc_id="repo/app.py")

    assert len(nodes) > 1
    assert {node.metadata["qualified_name"] for node in nodes} == {
        "repo/app.py::handle"
    }
    assert [node.metadata["chunk_index"] for node in nodes] == list(range(len(nodes)))
    assert all(node.metadata["chunk_count"] == len(nodes) for node in nodes)
    assert all(
        count_tokens(node.text, model="text-embedding-3-large")
        <= DEFAULT_EMBEDDING_TOKEN_LIMIT
        for node in nodes
    )


def test_function_text_nodes_exclude_verbose_metadata_from_embeddings():
    signature = "function handle() {" + (" value += 1;" * 3000) + " }"
    document_text = signature + "\n"
    entry = FunctionEntry(
        qualified_name="repo/app.js::handle",
        name="handle",
        file="repo/app.js",
        start_line=1,
        end_line=1,
        signature=signature,
        language="javascript",
        callees=["repo/app.js::callee"] * 100,
    )

    nodes = _text_nodes_for_entry(entry, document_text, source_doc_id="repo/app.js")

    assert nodes
    assert nodes[0].metadata["signature"] == signature
    assert "signature" in nodes[0].excluded_embed_metadata_keys
    embed_content = nodes[0].get_content(metadata_mode=MetadataMode.EMBED)
    assert signature not in embed_content
    assert "callees:" not in embed_content


def test_embedding_splitter_handles_single_line_over_token_limit():
    chunks = _split_text_for_embedding("x " * (DEFAULT_EMBEDDING_TOKEN_LIMIT + 20))

    assert len(chunks) > 1
    assert all(
        count_tokens(chunk, model="text-embedding-3-large")
        <= DEFAULT_EMBEDDING_TOKEN_LIMIT
        for chunk in chunks
    )


def test_ensure_embedding_safe_nodes_splits_oversized_splitter_nodes():
    node = Document(
        text="token " * (DEFAULT_EMBEDDING_TOKEN_LIMIT + 300),
        id_="repo/large.js",
    )

    nodes = ensure_embedding_safe_nodes([node])

    assert len(nodes) > 1
    assert {chunk.metadata["embedding_chunk_count"] for chunk in nodes} == {len(nodes)}
    assert [chunk.metadata["embedding_chunk_index"] for chunk in nodes] == list(
        range(len(nodes))
    )
    assert all(
        count_tokens(
            chunk.get_content(metadata_mode=MetadataMode.EMBED),
            model="text-embedding-3-large",
        )
        <= DEFAULT_EMBEDDING_TOKEN_LIMIT
        for chunk in nodes
    )


def test_ensure_embedding_safe_nodes_excludes_metadata_when_metadata_exceeds_budget():
    huge_metadata = "token " * (DEFAULT_EMBEDDING_TOKEN_LIMIT + 300)
    node = TextNode(
        text="short text",
        id_="repo/large-metadata",
        metadata={"huge": huge_metadata},
    )

    nodes = ensure_embedding_safe_nodes([node])

    assert len(nodes) == 1
    assert nodes[0].metadata["huge"] == huge_metadata
    assert "huge" in nodes[0].excluded_embed_metadata_keys
    assert huge_metadata not in nodes[0].get_content(metadata_mode=MetadataMode.EMBED)
    assert (
        count_tokens(
            nodes[0].get_content(metadata_mode=MetadataMode.EMBED),
            model="text-embedding-3-large",
        )
        <= DEFAULT_EMBEDDING_TOKEN_LIMIT
    )


def test_minified_javascript_function_nodes_stay_embedding_safe():
    source = "function N(){" + ("this.value+=1;" * 12000) + "}\n"
    document = Document(text=source, id_="repo/jquery.min.js")

    function_nodes, _index = extract_function_nodes_from_document(
        document,
        JavaScriptPlugin({}),
    )
    safe_nodes = ensure_embedding_safe_nodes(function_nodes)

    assert function_nodes
    assert safe_nodes
    assert DEFAULT_EXCLUDED_EMBED_METADATA_KEYS[0] == "signature"
    assert all(
        count_tokens(
            node.get_content(metadata_mode=MetadataMode.EMBED),
            model="text-embedding-3-large",
        )
        <= DEFAULT_EMBEDDING_TOKEN_LIMIT
        for node in safe_nodes
    )


def test_prepare_nodes_iter_propagates_splitter_failures():
    source = "def handle(value):\n    return value\n"
    document = SimpleNamespace(text=source, id_="repo/app.py")

    class _BrokenSplitter:
        def get_nodes_from_documents(self, _documents):
            raise RuntimeError("splitter failed")

    iterator = prepare_nodes_iter(
        [document],
        [],
        lambda _ext: PythonPlugin({}),
        lambda _plugin: _BrokenSplitter(),
        object(),
    )

    try:
        next(iterator)
    except RuntimeError as exc:
        assert str(exc) == "splitter failed"
    else:
        raise AssertionError("splitter failure should propagate")


def test_tree_sitter_node_walkers_handle_deep_ast_without_recursion_error():
    class _Node:
        def __init__(self):
            self.children = []

    root = _Node()
    current = root
    depth = 1500
    for _ in range(depth):
        child = _Node()
        current.children = [child]
        current = child

    parent_map = {}
    _build_parent_map(root, parent_map, None)

    walked = list(_walk(root))
    assert len(walked) == depth + 1
    assert len(parent_map) == depth + 1
    assert parent_map[id(root)] is None
    assert parent_map[id(walked[-1])] is walked[-2]


def test_function_index_can_batch_merge_before_edge_rebuild():
    first = FunctionIndex()
    first.add(
        FunctionEntry(
            qualified_name="repo/a.py::caller",
            name="caller",
            file="repo/a.py",
            start_line=1,
            end_line=2,
            signature="def caller():",
            language="python",
            call_names=["callee"],
        )
    )
    second = FunctionIndex()
    second.add(
        FunctionEntry(
            qualified_name="repo/b.py::callee",
            name="callee",
            file="repo/b.py",
            start_line=1,
            end_line=2,
            signature="def callee():",
            language="python",
        )
    )
    merged = FunctionIndex()

    merged.merge(first, rebuild=False)
    merged.merge(second, rebuild=False)
    assert merged.functions["repo/a.py::caller"].callees == []

    merged.rebuild_edges()

    assert merged.functions["repo/a.py::caller"].callees == ["repo/b.py::callee"]


def test_related_function_context_is_bounded_and_labeled(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = (
        "def validate(value):\n"
        "    return value > 0\n"
        "\n"
        "def handle(value):\n"
        "    return validate(value)\n"
    )
    (repo / "app.py").write_text(source, encoding="utf-8")
    document = SimpleNamespace(text=source, id_="app.py")
    _nodes, index = extract_function_nodes_from_document(document, PythonPlugin({}))

    related = format_related_functions(
        index,
        codebase_path=str(repo),
        file_path="app.py",
        snippet="def handle(value):\n    return validate(value)\n",
        per_function_chars=200,
        total_chars=500,
    )

    assert related.startswith("RELATED_FUNCTIONS:")
    assert "app.py::validate" in related
    assert "def validate(value):" in related


def test_related_function_context_anchors_body_only_snippet_by_line_range(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = (
        "def validate(value):\n"
        "    return value > 0\n"
        "\n"
        "def handle(value):\n"
        "    return validate(value)\n"
    )
    (repo / "app.py").write_text(source, encoding="utf-8")
    document = SimpleNamespace(text=source, id_="app.py")
    _nodes, index = extract_function_nodes_from_document(document, PythonPlugin({}))

    related = format_related_functions(
        index,
        codebase_path=str(repo),
        file_path="app.py",
        snippet="    return validate(value)\n",
        line_ranges=[(5, 5)],
        per_function_chars=200,
        total_chars=500,
    )

    assert "app.py::validate" in related
    assert "def validate(value):" in related
    assert "app.py::handle" not in related


def test_related_function_context_does_not_anchor_bare_callee_name(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = (
        "def validate(value):\n"
        "    return value > 0\n"
        "\n"
        "def handle(value):\n"
        "    return validate(value)\n"
    )
    (repo / "app.py").write_text(source, encoding="utf-8")
    document = SimpleNamespace(text=source, id_="app.py")
    _nodes, index = extract_function_nodes_from_document(document, PythonPlugin({}))

    related = format_related_functions(
        index,
        codebase_path=str(repo),
        file_path="app.py",
        snippet="    return validate(value)\n",
    )

    assert related == ""


def test_related_function_context_rejects_out_of_repo_sidecar_paths(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("do not leak\n", encoding="utf-8")
    (repo / "app.py").write_text("def handle():\n    pass\n", encoding="utf-8")
    index = FunctionIndex()
    index.add(
        FunctionEntry(
            qualified_name="app.py::handle",
            name="handle",
            file="app.py",
            start_line=1,
            end_line=2,
            signature="def handle():",
            language="python",
            callees=["../secret.txt::secret"],
        )
    )
    index.add(
        FunctionEntry(
            qualified_name="../secret.txt::secret",
            name="secret",
            file="../secret.txt",
            start_line=1,
            end_line=1,
            signature="secret",
            language="text",
        )
    )

    related = format_related_functions(
        index,
        codebase_path=str(repo),
        file_path="app.py",
        snippet="def handle():\n",
    )

    assert "do not leak" not in related
    assert related == ""


def test_related_function_context_avoids_duplicate_basename_matches(tmp_path):
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "app.py").write_text("def validate():\n    return True\n", encoding="utf-8")
    (repo / "pkg" / "app.py").write_text(
        "def pkg_validate():\n    return False\n", encoding="utf-8"
    )
    index = FunctionIndex()
    index.add(
        FunctionEntry(
            qualified_name="repo/app.py::handle",
            name="handle",
            file="repo/app.py",
            start_line=1,
            end_line=1,
            signature="def handle():",
            language="python",
            callees=["repo/app.py::validate"],
        )
    )
    index.add(
        FunctionEntry(
            qualified_name="repo/app.py::validate",
            name="validate",
            file="repo/app.py",
            start_line=1,
            end_line=2,
            signature="def validate():",
            language="python",
        )
    )
    index.add(
        FunctionEntry(
            qualified_name="repo/pkg/app.py::handle",
            name="handle",
            file="repo/pkg/app.py",
            start_line=1,
            end_line=1,
            signature="def handle():",
            language="python",
            callees=["repo/pkg/app.py::pkg_validate"],
        )
    )
    index.add(
        FunctionEntry(
            qualified_name="repo/pkg/app.py::pkg_validate",
            name="pkg_validate",
            file="repo/pkg/app.py",
            start_line=1,
            end_line=2,
            signature="def pkg_validate():",
            language="python",
        )
    )

    related = format_related_functions(
        index,
        codebase_path=str(repo),
        file_path="app.py",
        snippet="def handle():\n",
    )

    assert "repo/app.py::validate" in related
    assert "repo/pkg/app.py::pkg_validate" not in related

    pkg_related = format_related_functions(
        index,
        codebase_path=str(repo),
        file_path="pkg/app.py",
        snippet="def handle():\n",
    )

    assert "repo/pkg/app.py::pkg_validate" in pkg_related
    assert "repo/app.py::validate" not in pkg_related


def test_update_index_rewrites_function_sidecar_for_changed_code(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    app = tmp_path / "app.py"
    app.write_text(
        "def validate(value):\n"
        "    return value > 0\n"
        "\n"
        "def handle(value):\n"
        "    return validate(value)\n",
        encoding="utf-8",
    )

    class _FakeIndex:
        def __init__(self):
            self.docstore = Mock(set_document_hash=Mock())

        @classmethod
        def from_vector_store(cls, *_args, **_kwargs):
            return cls()

        def delete_ref_doc(self, *_args, **_kwargs):
            return None

        def insert_nodes(self, nodes):
            self.nodes = nodes

        def refresh_ref_docs(self, _docs):
            raise AssertionError("code updates should use function-aware insert")

    monkeypatch.setattr(indexing_service_mod, "VectorStoreIndex", _FakeIndex)

    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    patch = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,5 @@
 def validate(value):
     return value > 0
+
+def handle(value):
+    return validate(value)
"""

    engine.indexing.update_index(patch)

    index = FunctionIndex.read(engine.repository.get_function_index_path())
    assert f"{tmp_path.name}/app.py::handle" in index.functions
    expected_doc = Document(
        text=app.read_text(encoding="utf-8"),
        metadata={"file_name": "app.py"},
        id_=f"{tmp_path.name}/app.py",
    )
    assert index.file_hash_matches(f"{tmp_path.name}/app.py", expected_doc.hash)
    assert index.functions[f"{tmp_path.name}/app.py::handle"].callees == [
        f"{tmp_path.name}/app.py::validate"
    ]


def test_update_index_inserts_embedding_safe_code_nodes(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    app = tmp_path / "app.js"
    app.write_text(
        "function N(){" + ("this.value+=1;" * 12000) + "}\n",
        encoding="utf-8",
    )
    inserted_nodes = []

    class _FakeIndex:
        def __init__(self):
            self.docstore = Mock(set_document_hash=Mock())

        @classmethod
        def from_vector_store(cls, *_args, **_kwargs):
            return cls()

        def delete_ref_doc(self, *_args, **_kwargs):
            return None

        def insert_nodes(self, nodes):
            inserted_nodes.extend(nodes)

    monkeypatch.setattr(indexing_service_mod, "VectorStoreIndex", _FakeIndex)
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    patch = """diff --git a/app.js b/app.js
index 1111111..2222222 100644
--- a/app.js
+++ b/app.js
@@ -1 +1 @@
-function N(){this.value+=1;}
+function N(){this.value+=2;}
"""

    engine.indexing.update_index(patch)

    assert inserted_nodes
    assert all(
        count_tokens(
            node.get_content(metadata_mode=MetadataMode.EMBED),
            model="text-embedding-3-large",
        )
        <= DEFAULT_EMBEDDING_TOKEN_LIMIT
        for node in inserted_nodes
    )


def test_update_index_resets_cached_query_engines(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    app = tmp_path / "app.py"
    app.write_text("def handle(value):\n    return value + 1\n", encoding="utf-8")

    class _FakeIndex:
        def __init__(self):
            self.docstore = Mock(set_document_hash=Mock())

        @classmethod
        def from_vector_store(cls, *_args, **_kwargs):
            return cls()

        def delete_ref_doc(self, *_args, **_kwargs):
            return None

        def insert_nodes(self, _nodes):
            return None

    monkeypatch.setattr(indexing_service_mod, "VectorStoreIndex", _FakeIndex)
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    engine._state.qe_code = object()
    engine._state.qe_docs = object()
    engine._state.retrieval_cache = RetrievalCache()
    cache_key = ("code", 3, "cached-query")
    assert engine._state.retrieval_cache.get_or_set(
        cache_key, lambda: ["cached-doc"]
    ) == ["cached-doc"]
    assert len(engine._state.retrieval_cache) == 1
    patch = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def handle(value):
-    return value
+    return value + 1
"""

    engine.indexing.update_index(patch)

    assert engine._state.qe_code is None
    assert engine._state.qe_docs is None
    assert len(engine._state.retrieval_cache) == 0


def test_update_index_propagates_splitter_failures(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    app = tmp_path / "app.py"
    app.write_text("def handle(value):\n    return value\n", encoding="utf-8")

    class _FakeIndex:
        def __init__(self):
            self.docstore = Mock(set_document_hash=Mock())

        @classmethod
        def from_vector_store(cls, *_args, **_kwargs):
            return cls()

        def delete_ref_doc(self, *_args, **_kwargs):
            return None

        def insert_nodes(self, _nodes):
            raise AssertionError("insert should not run after splitter failure")

    class _BrokenSplitter:
        def get_nodes_from_documents(self, _documents):
            raise RuntimeError("splitter failed")

    monkeypatch.setattr(indexing_service_mod, "VectorStoreIndex", _FakeIndex)
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    monkeypatch.setattr(
        engine.repository,
        "get_splitter_cached",
        lambda _plugin: _BrokenSplitter(),
    )
    patch = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def handle(value):
-    return value
+    return value + 1
"""

    try:
        engine.indexing.update_index(patch)
    except RuntimeError as exc:
        assert str(exc) == "splitter failed"
    else:
        raise AssertionError("splitter failure should propagate")


def test_update_index_propagates_delete_failures_before_insert_or_sidecar(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    app = tmp_path / "app.py"
    app.write_text("def handle(value):\n    return value\n", encoding="utf-8")

    class _FakeIndex:
        def __init__(self):
            self.docstore = Mock(set_document_hash=Mock())

        @classmethod
        def from_vector_store(cls, *_args, **_kwargs):
            return cls()

        def delete_ref_doc(self, *_args, **_kwargs):
            raise RuntimeError("backend delete failed")

        def insert_nodes(self, _nodes):
            raise AssertionError("insert should not run after delete failure")

    monkeypatch.setattr(indexing_service_mod, "VectorStoreIndex", _FakeIndex)
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    engine._state.qe_code = object()
    engine._state.qe_docs = object()
    patch = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def handle(value):
-    return value
+    return value + 1
"""

    try:
        engine.indexing.update_index(patch)
    except RuntimeError as exc:
        assert str(exc) == "backend delete failed"
    else:
        raise AssertionError("delete failure should propagate")

    assert not (tmp_path / ".metis" / "function_index.json").exists()
    assert engine._state.qe_code is None
    assert engine._state.qe_docs is None


def test_update_index_rejects_patch_paths_outside_codebase(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    secret = tmp_path.parent / "secret.py"
    secret.write_text("def leak():\n    return 'secret'\n", encoding="utf-8")

    class _FakeIndex:
        docstore = Mock(set_document_hash=Mock())

        @classmethod
        def from_vector_store(cls, *_args, **_kwargs):
            return cls()

        def delete_ref_doc(self, *_args, **_kwargs):
            raise AssertionError("outside paths should be skipped before delete")

        def insert_nodes(self, _nodes):
            raise AssertionError("outside paths should be skipped before insert")

        def refresh_ref_docs(self, _docs):
            raise AssertionError("outside paths should be skipped before refresh")

    monkeypatch.setattr(indexing_service_mod, "VectorStoreIndex", _FakeIndex)
    monkeypatch.setattr(
        indexing_service_mod,
        "read_file_content",
        Mock(side_effect=AssertionError("outside file should not be read")),
    )
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    patch = """diff --git a/../secret.py b/../secret.py
index 1111111..2222222 100644
--- a/../secret.py
+++ b/../secret.py
@@ -1,2 +1,2 @@
 def leak():
-    return 'old'
+    return 'secret'
"""

    engine.indexing.update_index(patch)

    assert not (tmp_path / ".metis" / "function_index.json").exists()


def test_full_index_writes_function_sidecar_after_embedding_finalize(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    function_index = FunctionIndex()
    function_index.add(
        FunctionEntry(
            qualified_name=f"{tmp_path.name}/app.py::handle",
            name="handle",
            file=f"{tmp_path.name}/app.py",
            start_line=1,
            end_line=2,
            signature="def handle():",
            language="python",
        )
    )

    class _DummyReader:
        def __init__(self, **_kwargs):
            pass

        def load_data(self):
            return []

    def _fake_prepare_nodes_iter(*_args, **_kwargs):
        if False:
            yield None
        return (["code-node"], ["doc-node"], function_index)

    class _FakeVectorStoreIndex:
        def __init__(self, *_args, **_kwargs):
            pass

    monkeypatch.setattr(indexing_service_mod, "SimpleDirectoryReader", _DummyReader)
    monkeypatch.setattr(
        indexing_service_mod, "prepare_nodes_iter", _fake_prepare_nodes_iter
    )
    monkeypatch.setattr(indexing_service_mod, "VectorStoreIndex", _FakeVectorStoreIndex)

    engine.indexing.index_prepare_nodes()

    sidecar_path = tmp_path / ".metis" / "function_index.json"
    assert not sidecar_path.exists()
    assert engine._state.pending_function_index is function_index

    engine.indexing.index_finalize_embeddings()

    assert sidecar_path.exists()
    assert engine._state.pending_function_index is None


def test_full_index_skips_unchanged_docstore_hashes_and_keeps_sidecar(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    from llama_index.core.schema import Document

    app = tmp_path / "app.py"
    app.write_text("def handle():\n    return 1\n", encoding="utf-8")
    doc = Document(text=app.read_text(encoding="utf-8"), id_=str(app))
    normalized_id = f"{tmp_path.name}/app.py"

    existing = FunctionIndex()
    existing.set_file_hash(normalized_id, doc.hash)
    existing.add(
        FunctionEntry(
            qualified_name=f"{normalized_id}::handle",
            name="handle",
            file=normalized_id,
            start_line=1,
            end_line=2,
            signature="def handle():",
            language="python",
        )
    )
    existing.add(
        FunctionEntry(
            qualified_name=f"{tmp_path.name}/deleted.py::old",
            name="old",
            file=f"{tmp_path.name}/deleted.py",
            start_line=1,
            end_line=2,
            signature="def old():",
            language="python",
        )
    )
    existing.write(tmp_path / ".metis" / "function_index.json")

    class _Docstore:
        def get_document_hash(self, doc_id):
            if doc_id == normalized_id:
                return doc.hash
            return None

    storage_context = Mock()
    storage_context.docstore = _Docstore()
    storage_context.vector_store = Mock()
    storage_context.index_struct = Mock()
    dummy_backend.get_storage_contexts.return_value = (storage_context, storage_context)

    class _DummyReader:
        def __init__(self, **_kwargs):
            pass

        def load_data(self):
            return [doc]

    def _unexpected_vector_store_index(*_args, **_kwargs):
        raise AssertionError("unchanged documents should not be embedded")

    monkeypatch.setattr(indexing_service_mod, "SimpleDirectoryReader", _DummyReader)
    monkeypatch.setattr(
        indexing_service_mod, "VectorStoreIndex", _unexpected_vector_store_index
    )

    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine.indexing.index_codebase()

    index = FunctionIndex.read(engine.repository.get_function_index_path())
    assert f"{normalized_id}::handle" in index.functions
    assert index.file_hash_matches(normalized_id, doc.hash)
    assert f"{tmp_path.name}/deleted.py::old" not in index.functions


def test_full_index_reprocesses_unchanged_code_when_sidecar_hash_is_stale(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    from llama_index.core.schema import Document

    app = tmp_path / "app.py"
    app.write_text("def handle():\n    return 1\n", encoding="utf-8")
    doc = Document(text=app.read_text(encoding="utf-8"), id_=str(app))
    normalized_id = f"{tmp_path.name}/app.py"

    existing = FunctionIndex()
    existing.set_file_hash(normalized_id, "old-hash")
    existing.add(
        FunctionEntry(
            qualified_name=f"{normalized_id}::handle",
            name="handle",
            file=normalized_id,
            start_line=1,
            end_line=2,
            signature="def handle():",
            language="python",
        )
    )
    existing.write(tmp_path / ".metis" / "function_index.json")

    class _Docstore:
        def get_document_hash(self, doc_id):
            if doc_id == normalized_id:
                return doc.hash
            return None

        def set_document_hash(self, *_args):
            return None

    storage_context = Mock()
    storage_context.docstore = _Docstore()
    storage_context.vector_store = Mock()
    storage_context.index_struct = Mock()
    dummy_backend.get_storage_contexts.return_value = (storage_context, storage_context)

    class _DummyReader:
        def __init__(self, **_kwargs):
            pass

        def load_data(self):
            return [doc]

    captured = {}

    def _fake_prepare_nodes_iter(code_docs, doc_docs, *_args, **_kwargs):
        captured["code_ids"] = [item.id_ for item in code_docs]
        function_index = FunctionIndex()
        function_index.set_file_hash(normalized_id, doc.hash)
        if False:
            yield None
        return (["code-node"], [], function_index)

    class _FakeVectorStoreIndex:
        def __init__(self, nodes, *_args, **_kwargs):
            captured.setdefault("embedded", []).append(list(nodes))

    monkeypatch.setattr(indexing_service_mod, "SimpleDirectoryReader", _DummyReader)
    monkeypatch.setattr(
        indexing_service_mod, "prepare_nodes_iter", _fake_prepare_nodes_iter
    )
    monkeypatch.setattr(indexing_service_mod, "VectorStoreIndex", _FakeVectorStoreIndex)

    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine.indexing.index_codebase()

    assert captured["code_ids"] == [normalized_id]
    assert captured["embedded"] == [["code-node"], []]
    index = FunctionIndex.read(engine.repository.get_function_index_path())
    assert index.file_hash_matches(normalized_id, doc.hash)


def test_full_index_reprocesses_unchanged_code_when_sidecar_missing(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    from llama_index.core.schema import Document

    app = tmp_path / "app.py"
    app.write_text("def handle():\n    return 1\n", encoding="utf-8")
    doc = Document(text=app.read_text(encoding="utf-8"), id_=str(app))
    normalized_id = f"{tmp_path.name}/app.py"

    class _Docstore:
        def get_document_hash(self, doc_id):
            if doc_id == normalized_id:
                return doc.hash
            return None

        def set_document_hash(self, *_args):
            return None

    storage_context = Mock()
    storage_context.docstore = _Docstore()
    storage_context.vector_store = Mock()
    storage_context.index_struct = Mock()
    dummy_backend.get_storage_contexts.return_value = (storage_context, storage_context)

    class _DummyReader:
        def __init__(self, **_kwargs):
            pass

        def load_data(self):
            return [doc]

    captured = {}

    def _fake_prepare_nodes_iter(code_docs, doc_docs, *_args, **_kwargs):
        captured["code_ids"] = [item.id_ for item in code_docs]
        if False:
            yield None
        return (["code-node"], [])

    class _FakeVectorStoreIndex:
        def __init__(self, nodes, *_args, **_kwargs):
            captured.setdefault("embedded", []).append(list(nodes))

    monkeypatch.setattr(indexing_service_mod, "SimpleDirectoryReader", _DummyReader)
    monkeypatch.setattr(
        indexing_service_mod, "prepare_nodes_iter", _fake_prepare_nodes_iter
    )
    monkeypatch.setattr(indexing_service_mod, "VectorStoreIndex", _FakeVectorStoreIndex)

    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine.indexing.index_codebase()

    assert captured["code_ids"] == [normalized_id]
    assert captured["embedded"] == [["code-node"], []]
