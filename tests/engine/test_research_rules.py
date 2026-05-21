# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research.rules import (
    GUARD_KEYWORDS,
    SANITIZER_KEYWORDS,
    SINK_KEYWORDS,
    SOURCE_KEYWORDS,
    VULNERABILITY_RULES,
    markers_for,
    rule_for_family,
)


def test_research_rules_cover_high_impact_vulnerability_families():
    families = {rule.family for rule in VULNERABILITY_RULES}

    assert {
        "command_injection",
        "code_injection",
        "sql_injection",
        "nosql_injection",
        "template_injection",
        "path_traversal",
        "ssrf",
        "deserialization",
        "xxe",
        "xss",
        "secrets_exposure",
        "memory_lifetime",
        "evm_external_call",
        "iac_exposure",
        "hardware_security",
    } <= families


def test_research_rules_keep_existing_graph_marker_compatibility():
    assert "request" in SOURCE_KEYWORDS
    assert "$_get" in SOURCE_KEYWORDS
    assert "system" in SINK_KEYWORDS
    assert "db.query" in SINK_KEYWORDS
    assert "call" in SINK_KEYWORDS
    assert "safe_join" in SANITIZER_KEYWORDS
    assert "authorize" in GUARD_KEYWORDS


def test_research_rules_return_family_specific_markers():
    assert rule_for_family("sqli").family == "sql_injection"
    assert "db.query" in markers_for("sink", families=("sql_injection",))
    assert "system" not in markers_for("sink", families=("sql_injection",))
    assert "system" in markers_for("sink", families=("command_injection",))
    assert "eval" in markers_for("sink", families=("code_injection",))
    assert "escapeshellarg" in markers_for(
        "sanitizer",
        families=("command_injection",),
    )
    assert rule_for_family("secrets").family == "secrets_exposure"


def test_research_rules_normalize_phase3_high_impact_markers():
    command_sinks = markers_for("sink", families=("command_injection",))
    code_sinks = markers_for("sink", families=("code_injection",))
    sql_sinks = markers_for("sink", families=("sql_injection",))
    sql_sanitizers = markers_for("sanitizer", families=("sql_injection",))

    assert "subprocess.run" in command_sinks
    assert "child_process.exec" in command_sinks
    assert "runtime.exec" in command_sinks
    assert "process.start" in command_sinks
    assert "exec.command" in command_sinks
    assert "command::new" in command_sinks
    assert "vm.runinnewcontext" in code_sinks
    assert "method.invoke" in code_sinks
    assert "assembly.load" in code_sinks
    assert "pdo::query" in sql_sinks
    assert "statement.execute" in sql_sinks
    assert "sqlcommand" in sql_sinks
    assert "executereader" in sql_sinks
    assert "parameters.addwithvalue" in sql_sanitizers
    assert "preparedstatement" in sql_sanitizers
