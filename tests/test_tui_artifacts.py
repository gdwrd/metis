# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from metis.tui.artifacts import (
    TuiArtifactStore,
    find_latest_review_sarif,
    find_latest_triage_sarif,
)
from metis.tui.events import TuiEvent


def test_artifact_store_writes_manifest_and_command_log(tmp_path):
    store = TuiArtifactStore(
        run_id="run-1",
        codebase_path="/repo",
        base_dir=tmp_path,
    )
    log_path = store.command_log_path(1, "review_code")
    store.record_command(
        command_id="001-review_code",
        command_name="review_code",
        raw="/review_code",
        log_path=log_path,
    )
    event = TuiEvent(
        run_id="run-1",
        command_id="001-review_code",
        sequence=1,
        type="command.started",
        timestamp="2026-05-12T00:00:00Z",
        level="info",
        message="Started",
        payload={},
    )
    store.append_event(log_path, event)
    store.finish_command("001-review_code", "succeeded")
    store.set_latest_review_sarif_source("current-run")

    manifest = json.loads(store.paths.manifest.read_text(encoding="utf-8"))
    assert manifest["run_id"] == "run-1"
    assert manifest["commands"][0]["status"] == "succeeded"
    assert manifest["artifacts"]["research_report"].endswith("research-report.json")
    assert manifest["artifacts"]["research_sarif"].endswith("research.sarif")
    assert manifest["artifacts"]["security_report"].endswith("security-report.md")
    assert manifest["latest_review_sarif_source"] == "current-run"
    assert log_path.read_text(encoding="utf-8").count("command.started") == 1


def test_artifact_store_sanitizes_event_log_payloads(tmp_path):
    store = TuiArtifactStore(
        run_id="run-secret",
        codebase_path="/repo",
        base_dir=tmp_path,
    )
    log_path = store.command_log_path(1, "review_code")
    event = TuiEvent(
        run_id="run-secret",
        command_id="001-review_code",
        sequence=1,
        type="command.failed",
        timestamp="2026-05-12T00:00:00Z",
        level="error",
        message="failed with api key: sk-testsecret123",
        payload={
            "default_headers": {"Authorization": "Bearer abc.def"},
            "x-api-key": "raw-secret",
        },
    )

    store.append_event(log_path, event)

    text = log_path.read_text(encoding="utf-8")
    assert "sk-testsecret123" not in text
    assert "abc.def" not in text
    assert "raw-secret" not in text
    assert "<redacted>" in text


def test_find_latest_review_sarif_uses_newest_succeeded_manifest_timestamp(tmp_path):
    older = TuiArtifactStore(run_id="older", codebase_path="/repo", base_dir=tmp_path)
    newer = TuiArtifactStore(run_id="newer", codebase_path="/repo", base_dir=tmp_path)
    older.paths.review_sarif.write_text("{}", encoding="utf-8")
    newer.paths.review_sarif.write_text("{}", encoding="utf-8")
    older.set_status("succeeded")
    newer.set_status("succeeded")
    older_manifest = json.loads(older.paths.manifest.read_text(encoding="utf-8"))
    older_manifest["updated_at"] = "2026-05-12T10:00:00Z"
    older.paths.manifest.write_text(json.dumps(older_manifest), encoding="utf-8")
    newer_manifest = json.loads(newer.paths.manifest.read_text(encoding="utf-8"))
    newer_manifest["updated_at"] = "2026-05-12T11:00:00Z"
    newer.paths.manifest.write_text(json.dumps(newer_manifest), encoding="utf-8")

    resolved = find_latest_review_sarif(tmp_path)

    assert resolved == (newer.paths.review_sarif, "manifest-scan")


def test_find_latest_review_sarif_ignores_arbitrary_sarif_and_running_manifest(
    tmp_path,
):
    (tmp_path / "random.sarif").write_text("{}", encoding="utf-8")
    running = TuiArtifactStore(
        run_id="running", codebase_path="/repo", base_dir=tmp_path
    )
    running.paths.review_sarif.write_text("{}", encoding="utf-8")

    assert find_latest_review_sarif(tmp_path) is None


def test_find_latest_triage_sarif_uses_newest_succeeded_manifest_timestamp(tmp_path):
    older = TuiArtifactStore(run_id="older", codebase_path="/repo", base_dir=tmp_path)
    newer = TuiArtifactStore(run_id="newer", codebase_path="/repo", base_dir=tmp_path)
    older.paths.triage_sarif.write_text("{}", encoding="utf-8")
    newer.paths.triage_sarif.write_text("{}", encoding="utf-8")
    older.set_status("succeeded")
    newer.set_status("succeeded")
    older_manifest = json.loads(older.paths.manifest.read_text(encoding="utf-8"))
    older_manifest["updated_at"] = "2026-05-12T10:00:00Z"
    older.paths.manifest.write_text(json.dumps(older_manifest), encoding="utf-8")
    newer_manifest = json.loads(newer.paths.manifest.read_text(encoding="utf-8"))
    newer_manifest["updated_at"] = "2026-05-12T11:00:00Z"
    newer.paths.manifest.write_text(json.dumps(newer_manifest), encoding="utf-8")

    resolved = find_latest_triage_sarif(tmp_path)

    assert resolved == (newer.paths.triage_sarif, "manifest-scan")
