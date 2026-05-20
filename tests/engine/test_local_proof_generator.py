# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from metis.engine.research import (
    HypothesisStatus,
    LocalProofGenerator,
    ResearchOptions,
)


FIXTURE = "tests/fixtures/research/authz_outlier_app"


def test_research_service_generates_local_proof_artifact_and_references_it(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    result = engine.research.run(
        repo,
        options=ResearchOptions(persist=True, proof_artifacts=True),
    )

    assert len(result.proven) == 1
    artifact_paths = [Path(path) for path in result.proof_artifact_paths]
    assert {path.name for path in artifact_paths} == {
        "test_static_proof.py",
        "test_mocked_handler_proof.py",
    }
    for artifact_path in artifact_paths:
        assert artifact_path.exists()
        assert artifact_path.parent.name == result.proven[0].id

    proof_entries = [
        entry
        for entry in result.proven[0].evidence
        if entry.kind == "proof_artifact"
    ]
    assert {entry.file for entry in proof_entries} == {
        f".metis/research/proofs/{result.proven[0].id}/test_static_proof.py",
        (
            f".metis/research/proofs/{result.proven[0].id}/"
            "test_mocked_handler_proof.py"
        ),
    }

    evidence_payloads = [
        json.loads(line)
        for line in (tmp_path / ".metis" / "research" / "evidence.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    persisted_proof_files = {
        item["file"] for item in evidence_payloads if item["kind"] == "proof_artifact"
    }
    assert persisted_proof_files == {entry.file for entry in proof_entries}

    sarif = json.loads(
        (tmp_path / ".metis" / "research" / "results.sarif").read_text(
            encoding="utf-8"
        )
    )
    props = sarif["runs"][0]["results"][0]["properties"]
    assert set(props["metisProofArtifacts"]) == {entry.file for entry in proof_entries}

    for artifact_path in artifact_paths:
        _run_pytest_artifact(artifact_path)


def test_research_service_generates_local_proofs_without_persistence(
    engine,
    tmp_path,
):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    result = engine.research.run(
        repo,
        options=ResearchOptions(persist=False, proof_artifacts=True),
    )

    artifact_paths = [Path(path) for path in result.proof_artifact_paths]
    assert {path.name for path in artifact_paths} == {
        "test_static_proof.py",
        "test_mocked_handler_proof.py",
    }
    for artifact_path in artifact_paths:
        assert artifact_path.exists()
        _run_pytest_artifact(artifact_path)
    assert not (tmp_path / ".metis" / "research" / "evidence.jsonl").exists()


@pytest.mark.parametrize(
    ("fixture", "hunter"),
    [
        ("tests/fixtures/research/memory_lifetime_app", "memory_lifetime"),
        ("tests/fixtures/research/hardware_security_app", "hardware_security"),
    ],
)
def test_research_service_generates_static_source_proofs_for_native_and_hardware(
    engine,
    tmp_path,
    fixture,
    hunter,
):
    repo = tmp_path / "repo"
    shutil.copytree(fixture, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    result = engine.research.run(
        repo,
        options=ResearchOptions(
            persist=True,
            proof_artifacts=True,
            hunters=[hunter],
        ),
    )

    assert len(result.proven) == 1
    artifact_paths = [Path(path) for path in result.proof_artifact_paths]
    assert {path.name for path in artifact_paths} == {"test_static_source_proof.py"}
    proof_entries = [
        entry
        for entry in result.proven[0].evidence
        if entry.kind == "proof_artifact"
    ]
    assert len(proof_entries) == 1
    assert proof_entries[0].file.endswith("/test_static_source_proof.py")
    _run_pytest_artifact(artifact_paths[0])


def test_local_proof_generator_skips_non_proven_hypotheses(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)
    result = engine.research.run(repo, options=ResearchOptions(persist=False))

    proof_result = LocalProofGenerator(engine.repository).generate_for_hypotheses(
        result.generated,
        root=repo,
        proofs_dir=tmp_path / ".metis" / "research" / "proofs",
    )

    skipped = [
        decision
        for decision in proof_result.decisions
        if decision.status == "skipped"
    ]
    assert len(skipped) == 2
    assert {item.reason for item in skipped} == {
        "status is killed",
        "status is unresolved",
    }


def test_local_proof_generator_refuses_unsafe_network_targets(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)
    result = engine.research.run(repo, options=ResearchOptions(persist=False))
    unsafe = result.proven[0].model_copy(
        update={
            "source": "https://example.com/projects/1",
            "status": HypothesisStatus.PROVEN,
        }
    )

    proof_result = LocalProofGenerator(engine.repository).generate_for_hypotheses(
        [unsafe],
        root=repo,
        proofs_dir=tmp_path / ".metis" / "research" / "proofs",
    )

    assert proof_result.artifact_paths == []
    assert proof_result.decisions[0].status == "refused"
    assert proof_result.decisions[0].reason == (
        "proof would reference a non-local network target"
    )


@pytest.mark.parametrize(
    "hypothesis_id",
    [
        "../../../src/metis/engine/research",
        "nested/hypothesis",
        "/tmp/proof-target",
    ],
)
def test_local_proof_generator_refuses_unsafe_hypothesis_ids(
    engine,
    tmp_path,
    hypothesis_id,
):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)
    result = engine.research.run(repo, options=ResearchOptions(persist=False))
    unsafe = result.proven[0].model_copy(update={"id": hypothesis_id})

    proof_result = LocalProofGenerator(engine.repository).generate_for_hypotheses(
        [unsafe],
        root=repo,
        proofs_dir=tmp_path / ".metis" / "research" / "proofs",
    )

    assert proof_result.artifact_paths == []
    assert proof_result.decisions[0].status == "refused"
    assert proof_result.decisions[0].reason == (
        "hypothesis id is not safe for a proof artifact path"
    )
    assert not (tmp_path / "src" / "metis" / "engine" / "research").exists()


def test_local_proof_generator_refuses_ambiguous_source_resolution(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    nested = repo / "repo"
    nested.mkdir()
    shutil.copy2(repo / "app.py", nested / "app.py")
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)
    result = engine.research.run(repo, options=ResearchOptions(persist=False))
    location = result.proven[0].locations[0].model_copy(
        update={"file": f"{repo.name}/app.py"}
    )
    ambiguous = result.proven[0].model_copy(
        update={"locations": [location], "path": [location]}
    )

    proof_result = LocalProofGenerator(engine.repository).generate_for_hypotheses(
        [ambiguous],
        root=repo,
        proofs_dir=tmp_path / ".metis" / "research" / "proofs",
    )

    assert proof_result.artifact_paths == []
    assert proof_result.decisions[0].status == "refused"
    assert proof_result.decisions[0].reason == (
        "Proof source path is ambiguous inside research root"
    )


def _run_pytest_artifact(artifact_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(artifact_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout
