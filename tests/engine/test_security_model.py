# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil
import json

import pytest

from metis.engine.research.security_graph import SecurityGraphBuilder
from metis.engine.research.security_graph import _hash_file
from metis.engine.research.models import SecurityGraph
from metis.engine.research.security_model import ProjectSecurityModelService

from tests.engine.test_security_graph import (
    _write_stale_index_repo,
    _write_two_subroot_repo,
    _write_fixture_repo,
)


def test_project_security_model_builds_from_graph_and_persists(engine, tmp_path):
    repo, file_id, _index = _write_fixture_repo(tmp_path, engine)
    graph_builder = SecurityGraphBuilder(engine.repository)
    service = ProjectSecurityModelService(engine.repository, graph_builder)

    model = service.load_or_build(repo)

    assert (repo / ".metis" / "security_model.json").exists()
    assert model.file_hashes == {file_id: _hash_file(repo / "app.py")}
    assert model.file_hashes[file_id] != "hash-1"
    assert any(entry.name == "/projects/<project_id>" for entry in model.entrypoints)
    assert any(entry.name == "projects" for entry in model.assets)
    assert any(entry.name == "require_project_member" for entry in model.guards)
    assert any(entry.name == "request.args.get" for entry in model.sources)
    assert any(entry.name == "request.args.get" for entry in model.trust_boundaries)
    assert any(entry.name == "db_execute" for entry in model.sinks)
    assert any(entry.name == "sanitize_name" for entry in model.sanitizers)
    assert any(entry.name == "route" for entry in model.frameworks)
    assert model.metadata["graph_capability_fingerprint"]
    entrypoint = next(
        entry for entry in model.entrypoints if entry.name == "/projects/<project_id>"
    )
    assert entrypoint.metadata["guards"] == ["require_project_member"]


def test_project_security_model_uses_source_hash_before_changed_index_hash(
    engine,
    tmp_path,
):
    repo, file_id, index = _write_fixture_repo(tmp_path, engine)
    graph_builder = SecurityGraphBuilder(engine.repository)
    service = ProjectSecurityModelService(engine.repository, graph_builder)
    first = service.load_or_build(repo)

    index.set_file_hash(file_id, "hash-2")
    index.write(engine.repository.get_function_index_path())
    second = service.load_or_build(repo)

    assert first.project_root_hash == second.project_root_hash
    assert second.file_hashes[file_id] == _hash_file(repo / "app.py")
    assert second.file_hashes[file_id] != "hash-2"


def test_project_security_model_cache_rebuilds_on_graph_capability_change(
    engine,
    tmp_path,
):
    repo, _file_id, _index = _write_fixture_repo(tmp_path, engine)
    service = ProjectSecurityModelService(engine.repository)
    first = service.load_or_build(repo)
    model_path = repo / ".metis" / "security_model.json"
    payload = json.loads(model_path.read_text(encoding="utf-8"))
    payload["metadata"]["graph_capability_fingerprint"] = "stale-capabilities"
    model_path.write_text(json.dumps(payload), encoding="utf-8")

    second = service.load_or_build(repo)

    assert first.file_hashes == second.file_hashes
    assert second.metadata["graph_capability_fingerprint"] != "stale-capabilities"


def test_project_security_model_cache_is_scoped_to_requested_root(engine, tmp_path):
    case_a, case_b, _file_a, _file_b = _write_two_subroot_repo(tmp_path, engine)
    graph_builder = SecurityGraphBuilder(engine.repository)
    service = ProjectSecurityModelService(engine.repository, graph_builder)

    model_a = service.load_or_build(case_a)
    model_b = service.load_or_build(case_b)

    assert model_a.analysis_root == str(case_a.resolve())
    assert model_b.analysis_root == str(case_b.resolve())
    assert [entry.name for entry in model_a.entrypoints] == ["/a"]
    assert [entry.name for entry in model_b.entrypoints] == ["/b"]


def test_project_security_model_rejects_direct_outside_root_before_writing(
    engine,
    tmp_path,
):
    codebase = tmp_path / "codebase"
    codebase.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text("@route('/outside')\ndef handle():\n    return 1\n")
    engine.codebase_path = str(codebase)
    engine._config.codebase_path = str(codebase)
    service = ProjectSecurityModelService(engine.repository)

    with pytest.raises(ValueError, match="inside the configured codebase path"):
        service.load_or_build(outside)

    with pytest.raises(ValueError, match="inside the configured codebase path"):
        service.load_or_build(
            graph=SecurityGraph(
                analysis_root=str(outside.resolve()),
                project_root_hash="hash",
            )
        )

    assert not (codebase / ".metis" / "security_model.json").exists()


def test_project_security_model_uses_current_source_hash_before_stale_index_hash(
    engine,
    tmp_path,
):
    codebase, app, file_id = _write_stale_index_repo(tmp_path, engine)
    service = ProjectSecurityModelService(engine.repository)
    first = service.load_or_build(codebase)
    app.write_text("@route('/new')\ndef handle():\n    return 1\n")

    second = service.load_or_build(codebase)

    assert first.project_root_hash != second.project_root_hash
    assert second.file_hashes[file_id] != "stale-index-hash"
    assert [entry.name for entry in second.entrypoints] == ["/new"]


def test_project_security_model_includes_native_and_hardware_tags(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copytree(
        "tests/fixtures/research/memory_lifetime_app",
        repo / "native",
    )
    shutil.copytree(
        "tests/fixtures/research/hardware_security_app",
        repo / "hardware",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    model = ProjectSecurityModelService(engine.repository).load_or_build(repo)

    assert any(entry.name == "free" for entry in model.sinks)
    assert any(entry.name == "host_wdata" for entry in model.sources)
    assert any(entry.name == "is_privileged" for entry in model.guards)
    assert any(entry.name == "boot_key" for entry in model.sinks)
