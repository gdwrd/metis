# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.code_index import FunctionEntry, FunctionIndex
from metis.engine.research.security_graph import SecurityGraphBuilder
from metis.engine.research.security_graph import _hash_file
from metis.engine.research.security_graph import _resolve_graph_file


def _write_fixture_repo(tmp_path, engine):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = (
        "import os\n"
        "import requests\n"
        "from flask import request\n"
        "\n"
        "def route(path):\n"
        "    def decorator(func):\n"
        "        return func\n"
        "    return decorator\n"
        "\n"
        "def require_project_member(func):\n"
        "    return func\n"
        "\n"
        "def sanitize_name(value):\n"
        "    return value\n"
        "\n"
        "def db_execute(value):\n"
        "    return value\n"
        "\n"
        "@route('/projects/<project_id>')\n"
        "@require_project_member\n"
        "def get_project(project_id):\n"
        "    name = request.args.get('name')\n"
        "    clean = sanitize_name(name)\n"
        "    os.environ.get('PROJECT_MODE')\n"
        "    return db_execute(clean)\n"
    )
    (repo / "app.py").write_text(source, encoding="utf-8")
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)
    file_id = "app.py"
    index = FunctionIndex()
    index.set_file_hash(file_id, "hash-1")
    index.add(
        FunctionEntry(
            qualified_name=f"{file_id}::get_project",
            name="get_project",
            file=file_id,
            start_line=21,
            end_line=25,
            signature="def get_project(project_id):",
            language="python",
            call_names=[
                "request.args.get",
                "sanitize_name",
                "os.environ.get",
                "db_execute",
            ],
        )
    )
    index.add(
        FunctionEntry(
            qualified_name=f"{file_id}::sanitize_name",
            name="sanitize_name",
            file=file_id,
            start_line=13,
            end_line=14,
            signature="def sanitize_name(value):",
            language="python",
        )
    )
    index.add(
        FunctionEntry(
            qualified_name=f"{file_id}::db_execute",
            name="db_execute",
            file=file_id,
            start_line=16,
            end_line=17,
            signature="def db_execute(value):",
            language="python",
        )
    )
    index.rebuild_edges()
    index.write(engine.repository.get_function_index_path())
    return repo, file_id, index


def _write_two_subroot_repo(tmp_path, engine):
    codebase = tmp_path / "codebase"
    case_a = codebase / "case_a"
    case_b = codebase / "case_b"
    case_a.mkdir(parents=True)
    case_b.mkdir(parents=True)
    (case_a / "app.py").write_text("@route('/a')\ndef handle_a():\n    return 1\n")
    (case_b / "app.py").write_text("@route('/b')\ndef handle_b():\n    return 2\n")
    engine.codebase_path = str(codebase)
    engine._config.codebase_path = str(codebase)
    file_a = "case_a/app.py"
    file_b = "case_b/app.py"
    index = FunctionIndex()
    index.set_file_hash(file_a, "hash-a")
    index.set_file_hash(file_b, "hash-b")
    index.add(
        FunctionEntry(
            qualified_name=f"{file_a}::handle_a",
            name="handle_a",
            file=file_a,
            start_line=2,
            end_line=3,
            signature="def handle_a():",
            language="python",
        )
    )
    index.add(
        FunctionEntry(
            qualified_name=f"{file_b}::handle_b",
            name="handle_b",
            file=file_b,
            start_line=2,
            end_line=3,
            signature="def handle_b():",
            language="python",
        )
    )
    index.write(engine.repository.get_function_index_path())
    return case_a, case_b, file_a, file_b


def _write_stale_index_repo(tmp_path, engine):
    codebase = tmp_path / "codebase"
    codebase.mkdir()
    app = codebase / "app.py"
    app.write_text("@route('/old')\ndef handle():\n    return 1\n")
    engine.codebase_path = str(codebase)
    engine._config.codebase_path = str(codebase)
    file_id = "app.py"
    index = FunctionIndex()
    index.set_file_hash(file_id, "stale-index-hash")
    index.add(
        FunctionEntry(
            qualified_name=f"{file_id}::handle",
            name="handle",
            file=file_id,
            start_line=2,
            end_line=3,
            signature="def handle():",
            language="python",
        )
    )
    index.write(engine.repository.get_function_index_path())
    return codebase, app, file_id


def test_resolve_graph_file_prefers_codebase_relative_path_on_parent_collision(
    tmp_path,
):
    codebase = tmp_path / "repo"
    codebase.mkdir()
    outside = tmp_path / "app.py"
    inside = codebase / "app.py"
    outside.write_text("outside", encoding="utf-8")
    inside.write_text("inside", encoding="utf-8")

    assert _resolve_graph_file("app.py", codebase) == inside.resolve()
    assert _resolve_graph_file("repo/app.py", codebase) == inside.resolve()


def test_security_graph_builds_phase2_fields_and_persists(engine, tmp_path):
    repo, file_id, _index = _write_fixture_repo(tmp_path, engine)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    assert (repo / ".metis" / "security_graph.json").exists()
    assert graph.file_hashes == {file_id: _hash_file(repo / "app.py")}
    assert graph.file_hashes[file_id] != "hash-1"
    get_project = next(
        node for node in graph.nodes if node.id == f"function:{file_id}::get_project"
    )
    assert get_project.parameters == ["project_id"]
    assert get_project.returns == ["value"]
    tag_kinds = {tag.kind for tag in get_project.tags}
    assert {
        "entrypoint",
        "framework",
        "source",
        "sink",
        "guard",
        "sanitizer",
    } <= tag_kinds
    assert any(node.type == "import" and node.symbol == "requests" for node in graph.nodes)
    assert any(node.type == "route" for node in graph.nodes)
    assert any(node.type == "config" for node in graph.nodes)
    assert {"call", "import", "framework_registration", "configuration"} <= {
        edge.kind for edge in graph.edges
    }


def test_security_graph_uses_source_hash_before_changed_index_hash(engine, tmp_path):
    repo, file_id, index = _write_fixture_repo(tmp_path, engine)
    builder = SecurityGraphBuilder(engine.repository)
    first = builder.load_or_build(repo)

    index.set_file_hash(file_id, "hash-2")
    index.write(engine.repository.get_function_index_path())
    second = builder.load_or_build(repo)

    assert first.project_root_hash == second.project_root_hash
    assert second.file_hashes[file_id] == _hash_file(repo / "app.py")
    assert second.file_hashes[file_id] != "hash-2"


def test_security_graph_cache_is_scoped_to_requested_root(engine, tmp_path):
    case_a, case_b, file_a, file_b = _write_two_subroot_repo(tmp_path, engine)
    builder = SecurityGraphBuilder(engine.repository)

    graph_a = builder.load_or_build(case_a)
    graph_b = builder.load_or_build(case_b)

    assert graph_a.analysis_root == str(case_a.resolve())
    assert graph_b.analysis_root == str(case_b.resolve())
    assert graph_a.file_hashes == {file_a: _hash_file(case_a / "app.py")}
    assert graph_b.file_hashes == {file_b: _hash_file(case_b / "app.py")}
    assert graph_a.file_hashes[file_a] != "hash-a"
    assert graph_b.file_hashes[file_b] != "hash-b"
    assert {node.metadata.get("route_path") for node in graph_a.nodes} == {"/a"}
    assert {node.metadata.get("route_path") for node in graph_b.nodes} == {"/b"}


def test_security_graph_rejects_direct_outside_root_before_writing(engine, tmp_path):
    codebase = tmp_path / "codebase"
    codebase.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text("@route('/outside')\ndef handle():\n    return 1\n")
    engine.codebase_path = str(codebase)
    engine._config.codebase_path = str(codebase)

    with pytest.raises(ValueError, match="inside the configured codebase path"):
        SecurityGraphBuilder(engine.repository).load_or_build(outside)

    assert not (codebase / ".metis" / "security_graph.json").exists()


def test_security_graph_uses_current_source_hash_before_stale_index_hash(
    engine,
    tmp_path,
):
    codebase, app, file_id = _write_stale_index_repo(tmp_path, engine)
    builder = SecurityGraphBuilder(engine.repository)
    first = builder.load_or_build(codebase)
    app.write_text(
        "@route('/new')\n"
        "def handle():\n"
        "    name = request.args.get('name')\n"
        "    return db_execute(name)\n"
    )

    second = builder.load_or_build(codebase)

    assert first.project_root_hash != second.project_root_hash
    assert {node.metadata.get("route_path") for node in second.nodes} == {"/new"}
    assert second.file_hashes[file_id] != "stale-index-hash"
    handle = next(node for node in second.nodes if node.symbol == "handle")
    assert {"source", "sink"} <= {tag.kind for tag in handle.tags}


def test_security_graph_models_php_and_perl_server_script_sources_and_sinks(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "search.php").write_text(
        "<?php\n"
        "$id = $_GET['id'];\n"
        "$sql = \"SELECT * FROM users WHERE id='$id'\";\n"
        "$db->query($sql);\n",
        encoding="utf-8",
    )
    (repo / "update_mix.pl").write_text(
        "#!/usr/bin/perl\n"
        "$uniqueid=$ARGV[0];\n"
        "$query=\"INSERT INTO recordings VALUES('$uniqueid')\";\n"
        "$dbh->do($query);\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    php_node = next(node for node in graph.nodes if node.file == "search.php")
    perl_node = next(node for node in graph.nodes if node.file == "update_mix.pl")
    assert php_node.language == "php"
    assert perl_node.language == "perl"
    assert {"source", "sink"} <= {tag.kind for tag in php_node.tags}
    assert {"source", "sink"} <= {tag.kind for tag in perl_node.tags}
    assert any(tag.value == "sql_query" for tag in php_node.tags)
    assert any(tag.value == "sql_query" for tag in perl_node.tags)


def test_security_graph_models_parser_backed_language_sources_and_sinks(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "handler.js").write_text(
        "function run(req) {\n"
        "  child_process.exec(req.query.cmd);\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "Vault.sol").write_text(
        "contract Vault {\n"
        "  function withdraw(address target) public {\n"
        "    target.call(abi.encode(msg.sender));\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "task.rb").write_text(
        "def run(req)\n"
        "  system(req[:cmd])\n"
        "end\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    nodes_by_file = {node.file: node for node in graph.nodes if node.type == "function"}
    assert graph.metadata["source"] == "function_index+python_ast+text+plugin_treesitter"
    js_node = nodes_by_file["handler.js"]
    solidity_node = nodes_by_file["Vault.sol"]
    ruby_node = nodes_by_file["task.rb"]
    assert js_node.language == "javascript"
    assert solidity_node.language == "solidity"
    assert ruby_node.language == "ruby"
    assert {"source", "sink"} <= {tag.kind for tag in js_node.tags}
    assert {"source", "sink"} <= {tag.kind for tag in solidity_node.tags}
    assert {"source", "sink"} <= {tag.kind for tag in ruby_node.tags}
    assert any(tag.value == "exec" for tag in js_node.tags)
    assert any(tag.value == "call" for tag in solidity_node.tags)
    assert any(tag.value == "system" for tag in ruby_node.tags)


def test_security_graph_does_not_keep_deleted_index_entries(engine, tmp_path):
    repo, _file_id, _index = _write_fixture_repo(tmp_path, engine)
    builder = SecurityGraphBuilder(engine.repository)
    first = builder.load_or_build(repo)
    (repo / "app.py").unlink()

    second = builder.load_or_build(repo)

    assert first.project_root_hash != second.project_root_hash
    assert not any(node.symbol == "get_project" for node in second.nodes)
