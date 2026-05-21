# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
import shutil

import pytest

from metis.engine.code_index import FunctionEntry, FunctionIndex
from metis.engine.research.models import SECURITY_GRAPH_SCHEMA_VERSION
from metis.engine.research.security_graph import SecurityGraphBuilder
from metis.engine.research.security_graph import _hash_file
from metis.engine.research.security_graph import _resolve_graph_file


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "research"


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


def _copy_research_fixture(repo, name: str) -> None:
    shutil.copytree(FIXTURES_DIR / name, repo / name)


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
    assert any(
        node.type == "import" and node.symbol == "requests" for node in graph.nodes
    )
    assert any(node.type == "route" for node in graph.nodes)
    assert any(node.type == "config" for node in graph.nodes)
    assert {"call", "import", "framework_registration", "configuration"} <= {
        edge.kind for edge in graph.edges
    }


def test_security_graph_applies_declarative_rules_to_parser_metadata(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        "function run(req, child_process) {\n"
        "  const command = req.query.command;\n"
        "  return child_process.exec(command);\n"
        "}\n"
        "\n"
        "function search(req, db) {\n"
        "  const term = req.query.term;\n"
        "  return db.query('SELECT * FROM users WHERE name=' + term);\n"
        "}\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    by_symbol = {node.symbol: node for node in graph.nodes if node.type == "function"}
    run_tags = {(tag.kind, tag.value) for tag in by_symbol["run"].tags}
    search_tags = {(tag.kind, tag.value) for tag in by_symbol["search"].tags}
    assert ("source", "req") in run_tags
    assert ("sink", "child_process") in run_tags
    assert ("source", "req") in search_tags
    assert ("sink", "db.query") in search_tags


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


def test_security_graph_cache_rebuilds_on_capability_fingerprint_change(
    engine,
    tmp_path,
):
    repo, _file_id, _index = _write_fixture_repo(tmp_path, engine)
    builder = SecurityGraphBuilder(engine.repository)
    first = builder.load_or_build(repo)
    graph_path = repo / ".metis" / "security_graph.json"
    payload = json.loads(graph_path.read_text(encoding="utf-8"))
    payload["schema_version"] = SECURITY_GRAPH_SCHEMA_VERSION
    payload["metadata"]["capability_fingerprint"] = "stale-capabilities"
    graph_path.write_text(json.dumps(payload), encoding="utf-8")

    second = builder.load_or_build(repo)

    assert first.file_hashes == second.file_hashes
    assert second.metadata["capability_fingerprint"] != "stale-capabilities"
    assert second.metadata["capability_version"] == "parser_config_resource_v4"


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
    assert {"entrypoint", "framework"} <= {tag.kind for tag in php_node.tags}
    assert {"entrypoint", "framework"} <= {tag.kind for tag in perl_node.tags}
    assert any(tag.value == "sql_query" for tag in php_node.tags)
    assert any(tag.value == "sql_query" for tag in perl_node.tags)
    assert any(
        node.type == "route" and node.metadata.get("route_path") == "/search.php"
        for node in graph.nodes
    )
    assert any(
        node.type == "route" and node.metadata.get("route_path") == "/update_mix.pl"
        for node in graph.nodes
    )


def test_security_graph_extracts_cross_language_framework_entrypoints(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        "function show(req, res) {\n"
        "  return res.send(req.query.id);\n"
        "}\n"
        "app.get('/users/:id', show);\n",
        encoding="utf-8",
    )
    (repo / "server.go").write_text(
        "package main\n"
        'import "net/http"\n'
        "func run(w http.ResponseWriter, r *http.Request) {\n"
        '  cmd := r.URL.Query().Get("cmd")\n'
        "  _ = cmd\n"
        "}\n"
        "func init() {\n"
        '  http.HandleFunc("/run", run)\n'
        "}\n",
        encoding="utf-8",
    )
    (repo / "Api.java").write_text(
        "class Api {\n"
        '  @GetMapping("/items/{id}")\n'
        "  public String getItem(Request request) {\n"
        '    return request.getParameter("q");\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "Controller.cs").write_text(
        "class Controller {\n"
        '  [HttpPost("/upload")]\n'
        "  public IActionResult Upload(HttpRequest request) {\n"
        '    return Ok(request.Query["name"]);\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "main.rs").write_text(
        '#[get("/health")]\n'
        "async fn health(query: Query<HealthQuery>) -> String {\n"
        "    return query.name.clone();\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "routes.rb").write_text(
        "get '/profiles/:id', to: 'profiles#show'\ndef show\n  raw(params[:id])\nend\n",
        encoding="utf-8",
    )
    (repo / "tool.sh").write_text(
        'run() {\n  env | grep QUERY_STRING\n  eval "$QUERY_STRING"\n}\n',
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    route_paths = {
        node.metadata.get("route_path") for node in graph.nodes if node.type == "route"
    }
    assert {
        "/users/:id",
        "/run",
        "/items/{id}",
        "/upload",
        "/health",
        "/profiles/:id",
        "/run",
    } <= route_paths

    by_function = {
        (node.file, node.symbol): node
        for node in graph.nodes
        if node.type == "function"
    }
    for key in {
        ("app.js", "show"),
        ("server.go", "run"),
        ("Api.java", "getItem"),
        ("Controller.cs", "Upload"),
        ("main.rs", "health"),
        ("tool.sh", "run"),
    }:
        assert "entrypoint" in {tag.kind for tag in by_function[key].tags}


def test_security_graph_extracts_phase2_fixture_entrypoints(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for fixture in (
        "entrypoints_js_ts",
        "entrypoints_php",
        "entrypoints_go",
        "entrypoints_java_csharp",
        "entrypoints_ruby_rust",
        "entrypoints_cli_scripts",
        "entrypoints_config_iac",
    ):
        _copy_research_fixture(repo, fixture)
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    route_nodes = [node for node in graph.nodes if node.type == "route"]
    route_paths = {node.metadata.get("route_path") for node in route_nodes}
    assert {
        "/users/:id",
        "/fast/:id",
        "/koa/:id",
        "/nest/:id",
        "/user",
        "/entrypoints_php/index.php",
        "/run",
        "/gin",
        "/cobraRun",
        "/items/{id}",
        "/doGet",
        "/upload",
        "/minimal",
        "/profiles/:id",
        "/sinatra/:id",
        "/health",
        "/axum/:id",
        "/run_cli",
        "/handle",
        "/entrypoints_cli_scripts/tool.pl",
    } <= route_paths
    assert all("detector" in node.metadata for node in route_nodes)
    assert all("detector_confidence" in node.metadata for node in route_nodes)

    by_function = {
        (node.file, node.symbol): node
        for node in graph.nodes
        if node.type == "function"
    }
    for key in {
        ("entrypoints_js_ts/app.ts", "show"),
        ("entrypoints_js_ts/app.ts", "fastifyShow"),
        ("entrypoints_js_ts/app.ts", "koaShow"),
        ("entrypoints_js_ts/app.ts", "nestShow"),
        ("entrypoints_js_ts/pages/api/user.ts", "handler"),
        ("entrypoints_go/server.go", "run"),
        ("entrypoints_go/server.go", "ginHandler"),
        ("entrypoints_go/server.go", "cobraRun"),
        ("entrypoints_java_csharp/Api.java", "getItem"),
        ("entrypoints_java_csharp/Api.java", "doGet"),
        ("entrypoints_java_csharp/Controller.cs", "Upload"),
        ("entrypoints_java_csharp/Controller.cs", "MinimalHandler"),
        ("entrypoints_ruby_rust/routes.rb", "show"),
        ("entrypoints_ruby_rust/routes.rb", "sinatra"),
        ("entrypoints_ruby_rust/main.rs", "health"),
        ("entrypoints_ruby_rust/main.rs", "axum_handler"),
        ("entrypoints_cli_scripts/tool.sh", "run_cli"),
        ("entrypoints_cli_scripts/tool.lua", "handle"),
        ("entrypoints_cli_scripts/tool.pl", "__script__"),
    }:
        assert "entrypoint" in {tag.kind for tag in by_function[key].tags}

    source_tags = [
        tag
        for node in graph.nodes
        for tag in node.tags
        if tag.kind in {"source", "sink"}
    ]
    assert source_tags
    assert all(tag.detail and "detector=" in tag.detail for tag in source_tags)

    config_nodes = {
        (node.file, node.symbol): node
        for node in graph.nodes
        if node.file and node.file.startswith("entrypoints_config_iac/")
    }
    assert {
        "source",
        "sink",
    } <= {tag.kind for node in config_nodes.values() for tag in node.tags}
    docker_expose = config_nodes[("entrypoints_config_iac/Dockerfile", "expose_2")]
    assert "source" in {tag.kind for tag in docker_expose.tags}


def test_security_graph_keeps_entrypoint_route_inference_conservative(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    (repo / "pages" / "api").mkdir(parents=True)
    repo.mkdir(exist_ok=True)
    (repo / "Api.java").write_text(
        "class Api {\n"
        '  @GetMapping("/items/{id}")\n'
        "  public String getItem(Request request) {\n"
        '    return request.getParameter("q");\n'
        "  }\n"
        "  public String helper(Request request) {\n"
        '    return request.getParameter("debug");\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "search.php").write_text(
        "<?php\n$top = $_GET['top'];\nfunction search() {\n  return $_GET['q'];\n}\n",
        encoding="utf-8",
    )
    (repo / "lib.inc").write_text(
        "<?php\n$value = $_GET['value'];\n",
        encoding="utf-8",
    )
    (repo / "Module.pm").write_text(
        "package Module;\nmy $value = $ARGV[0];\n1;\n",
        encoding="utf-8",
    )
    (repo / "pages" / "api" / "user.js").write_text(
        "function parseQuery(req) {\n"
        "  return req.query.id;\n"
        "}\n"
        "export default async function handler(req, res) {\n"
        "  return res.send(req.query.id);\n"
        "}\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    by_symbol = {
        (node.file, node.symbol): node
        for node in graph.nodes
        if node.type == "function"
    }
    assert "entrypoint" in {tag.kind for tag in by_symbol[("Api.java", "getItem")].tags}
    assert "entrypoint" not in {
        tag.kind for tag in by_symbol[("Api.java", "helper")].tags
    }
    assert ("search.php", "search") in by_symbol
    assert ("search.php", "__script__") in by_symbol
    assert (
        by_symbol[("search.php", "search")].id
        != by_symbol[("search.php", "__script__")].id
    )
    assert "entrypoint" not in {
        tag.kind for tag in by_symbol[("pages/api/user.js", "parseQuery")].tags
    }
    assert "entrypoint" in {
        tag.kind for tag in by_symbol[("pages/api/user.js", "handler")].tags
    }

    route_paths = {
        node.metadata.get("route_path") for node in graph.nodes if node.type == "route"
    }
    assert "/search.php" in route_paths
    assert "/user" in route_paths
    assert "/lib.inc" not in route_paths
    assert "/Module.pm" not in route_paths


def test_security_graph_models_parser_backed_language_sources_and_sinks(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "handler.js").write_text(
        "function run(req) {\n  child_process.exec(req.query.cmd);\n}\n",
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
        "def run(req)\n  system(req[:cmd])\nend\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    nodes_by_file = {node.file: node for node in graph.nodes if node.type == "function"}
    assert (
        graph.metadata["source"]
        == "function_index+python_ast+text+plugin_treesitter+config_resource"
    )
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


def test_security_graph_models_new_parser_backed_languages(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "App.java").write_text(
        "class App {\n"
        "  String run(String input) throws Exception {\n"
        "    return Runtime.getRuntime().exec(input).toString();\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "Worker.cs").write_text(
        "class Worker {\n"
        "  object Run(string input) {\n"
        "    var cmd = input;\n"
        "    return System.Diagnostics.Process.Start(cmd);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "job.sh").write_text(
        'run_job() {\n  input="$1"\n  sh -c "$input"\n}\n',
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    by_file = {node.file: node for node in graph.nodes if node.type == "function"}
    assert by_file["App.java"].language == "java"
    assert by_file["Worker.cs"].language == "csharp"
    assert by_file["job.sh"].language == "bash"
    for rel_path in ("App.java", "Worker.cs", "job.sh"):
        assert {"source", "sink"} <= {tag.kind for tag in by_file[rel_path].tags}


def test_security_graph_normalizes_phase3_sinks_and_mitigations_without_overmatch(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import subprocess\n\n"
        "def harmless(request):\n"
        "    value = request.args.get('cmd')\n"
        "    preexecute(value)\n"
        "    safeexec(value)\n"
        "    querystringify(value)\n\n"
        "def run_command(request):\n"
        "    cmd = request.args.get('cmd')\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    (repo / "Worker.cs").write_text(
        "class Worker {\n"
        "  void Run(string input) {\n"
        "    System.Diagnostics.Process.Start(input);\n"
        "  }\n"
        "  void SearchSafe(string input) {\n"
        '    var cmd = new SqlCommand("SELECT * FROM users WHERE id=@id", conn);\n'
        '    cmd.Parameters.AddWithValue("@id", input);\n'
        "    cmd.ExecuteReader();\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    by_symbol = {
        (node.file, node.symbol): node
        for node in graph.nodes
        if node.type == "function"
    }
    harmless_tags = {
        (tag.kind, tag.value) for tag in by_symbol[("app.py", "harmless")].tags
    }
    assert ("source", "request") in harmless_tags
    assert not any(kind == "sink" for kind, _value in harmless_tags)

    command_tags = {
        (tag.kind, tag.value) for tag in by_symbol[("app.py", "run_command")].tags
    }
    assert ("sink", "subprocess.run") in command_tags

    csharp_run_tags = {
        (tag.kind, tag.value) for tag in by_symbol[("Worker.cs", "Run")].tags
    }
    assert ("sink", "process.start") in csharp_run_tags

    sql_safe_tags = {
        (tag.kind, tag.value) for tag in by_symbol[("Worker.cs", "SearchSafe")].tags
    }
    assert ("sink", "sqlcommand") in sql_safe_tags
    assert ("sink", "executereader") in sql_safe_tags
    assert ("sanitizer", "addwithvalue") in sql_safe_tags


def test_security_graph_models_config_and_resource_surfaces(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text(
        'resource "aws_security_group" "public_web" {\n'
        "  ingress {\n"
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "deployment.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "spec:\n"
        "  containers:\n"
        "  - name: app\n"
        "    securityContext:\n"
        "      privileged: true\n",
        encoding="utf-8",
    )
    (repo / "secrets.json").write_text(
        '{"api_key": "example", "public": true}\n',
        encoding="utf-8",
    )
    (repo / "Dockerfile").write_text(
        "FROM alpine\nRUN curl https://example.invalid/install.sh | sh\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    graph = SecurityGraphBuilder(engine.repository).load_or_build(repo)

    tf_node = next(node for node in graph.nodes if node.file == "main.tf")
    yaml_node = next(node for node in graph.nodes if node.file == "deployment.yaml")
    json_node = next(node for node in graph.nodes if node.file == "secrets.json")
    docker_node = next(
        node
        for node in graph.nodes
        if node.file == "Dockerfile" and node.symbol == "run_2"
    )
    assert tf_node.type == "resource"
    assert yaml_node.type == "config"
    assert json_node.type == "config"
    assert docker_node.type == "config"
    assert {"source"} <= {tag.kind for tag in tf_node.tags}
    assert {"source"} <= {tag.kind for tag in yaml_node.tags}
    assert {"source"} <= {tag.kind for tag in json_node.tags}
    assert {"sink"} <= {tag.kind for tag in docker_node.tags}
    assert "Dockerfile" in graph.file_hashes


def test_security_graph_does_not_keep_deleted_index_entries(engine, tmp_path):
    repo, _file_id, _index = _write_fixture_repo(tmp_path, engine)
    builder = SecurityGraphBuilder(engine.repository)
    first = builder.load_or_build(repo)
    (repo / "app.py").unlink()

    second = builder.load_or_build(repo)

    assert first.project_root_hash != second.project_root_hash
    assert not any(node.symbol == "get_project" for node in second.nodes)
