# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.tui.security_report import (
    build_attack_chain_candidates,
    build_cross_batch_attack_chain_candidates,
    extract_security_findings,
    format_attack_chain_candidate,
)


def test_extract_security_findings_tags_sources_sinks_and_trust_boundaries():
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "CWE-89",
                                "help": {
                                    "text": "SQL injection from request parameter into raw SQL query."
                                },
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "CWE-89",
                        "level": "error",
                        "message": {
                            "text": "Unauthenticated request parameter reaches SQL query"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/auth/login.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                        "properties": {"triage_status": "true_positive"},
                    }
                ],
            }
        ]
    }

    findings = extract_security_findings(payload)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_id == "F-0001"
    assert finding.component == "src/auth"
    assert "sql_injection" in finding.primitive_tags
    assert "request_input" in finding.source_tags
    assert "sql_sink" in finding.sink_tags
    assert "unauthenticated" in finding.trust_tags
    assert finding.score_hint >= 8.0


def test_build_attack_chain_candidates_groups_related_component_findings():
    payload = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CWE-862",
                        "message": {"text": "Missing authorization on upload endpoint"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/files/api.py"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "CWE-22",
                        "message": {
                            "text": "Path traversal lets uploaded file control target path"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/files/storage.py"},
                                    "region": {"startLine": 55},
                                }
                            }
                        ],
                    },
                ]
            }
        ]
    }
    findings = extract_security_findings(payload)

    candidates = build_attack_chain_candidates(findings)

    assert candidates
    assert candidates[0].title == "Multi-Stage Attack Chain in src/files"
    assert set(candidates[0].attack_families) >= {"auth_bypass", "path_traversal"}
    grouped = [candidate for candidate in candidates if len(candidate.findings) == 2]
    assert grouped
    context = format_attack_chain_candidate(grouped[0])
    assert "CHAIN-" in context
    assert "F-0001" in context
    assert "F-0002" in context
    assert "src/files" in context


def test_build_cross_batch_attack_chain_candidates_joins_file_write_to_rce():
    payload = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CWE-434",
                        "level": "error",
                        "message": {
                            "text": "Unauthenticated upload can write arbitrary PHP file with attacker-controlled path"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/upload/api.py"},
                                    "region": {"startLine": 20},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "CWE-78",
                        "level": "error",
                        "message": {
                            "text": "Command execution loads plugin file from writable plugin directory"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/runtime/load.py"},
                                    "region": {"startLine": 90},
                                }
                            }
                        ],
                    },
                ]
            }
        ]
    }
    findings = extract_security_findings(payload)
    candidates = build_attack_chain_candidates(findings)

    cross_batch = build_cross_batch_attack_chain_candidates(candidates)

    assert cross_batch
    joined = cross_batch[0]
    assert joined.chain_id.startswith("XCHAIN-")
    assert set(joined.source_candidate_ids)
    assert {finding.finding_id for finding in joined.findings} == {"F-0001", "F-0002"}
    assert "filesystem" in joined.relation_reason.lower()
    assert "code_execution" in joined.postconditions
    context = format_attack_chain_candidate(joined)
    assert "Source candidates:" in context
    assert "Bridge hooks:" in context
