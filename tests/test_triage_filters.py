# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.options import TriageOptions
from metis.sarif.triage import METIS_TRIAGED_KEY


def _result(uri: str) -> dict:
    return {
        "ruleId": "CWE-79",
        "message": {"text": "xss"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1, "snippet": {"text": "bad();"}},
                }
            }
        ],
    }


def test_triage_skips_test_path_findings_when_enabled(engine, monkeypatch):
    calls = []

    class _Graph:
        def triage(self, req):
            calls.append(req["finding_file_path"])
            return {"status": "valid", "reason": "kept"}

    monkeypatch.setattr(
        engine._triage_service,
        "_get_thread_triage_graph",
        lambda: _Graph(),
    )
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Metis"}},
                "results": [
                    _result("tests/test_app.py"),
                    _result("src/app.py"),
                ],
            }
        ],
    }

    result = engine.triage_sarif_payload(
        payload,
        options=TriageOptions(
            use_retrieval_context=False,
            skip_test_files=True,
        ),
    )

    assert calls == ["src/app.py"]
    assert METIS_TRIAGED_KEY not in result["runs"][0]["results"][0].get(
        "properties", {}
    )
    assert result["runs"][0]["results"][1]["properties"][METIS_TRIAGED_KEY] is True


def test_triage_options_can_disable_configured_test_filter(engine, monkeypatch):
    calls = []
    engine._triage_service.skip_test_files = True

    class _Graph:
        def triage(self, req):
            calls.append(req["finding_file_path"])
            return {"status": "valid", "reason": "kept"}

    monkeypatch.setattr(
        engine._triage_service,
        "_get_thread_triage_graph",
        lambda: _Graph(),
    )
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Metis"}},
                "results": [_result("tests/test_app.py")],
            }
        ],
    }

    result = engine.triage_sarif_payload(
        payload,
        options=TriageOptions(
            use_retrieval_context=False,
            skip_test_files=False,
        ),
    )

    assert calls == ["tests/test_app.py"]
    assert result["runs"][0]["results"][0]["properties"][METIS_TRIAGED_KEY] is True
