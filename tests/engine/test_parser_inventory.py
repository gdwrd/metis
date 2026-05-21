# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import yaml

from metis.engine.research import build_parser_inventory
from metis.plugin_loader import load_plugins


def test_parser_inventory_reports_new_language_and_config_graph_modes():
    config = yaml.safe_load(
        Path("src/metis/plugins/plugins.yaml").read_text(encoding="utf-8")
    )

    inventory = build_parser_inventory(load_plugins(config))
    by_name = {item["name"]: item for item in inventory["languages"]}

    for name in {
        "bash",
        "csharp",
        "java",
        "kotlin",
        "lua",
        "perl",
        "scala",
        "swift",
    }:
        assert by_name[name]["parser"]["available"] is True
        assert by_name[name]["research_graph_mode"] == "ast"
        assert by_name[name]["analyzer"]["function_node_types"]
        assert by_name[name]["analyzer"]["call_node_types"]

    for name in {"dockerfile", "json", "yaml"}:
        assert by_name[name]["parser"]["available"] is True
        assert by_name[name]["research_graph_mode"] == "config_resource"

    assert ".hcl" in by_name["terraform"]["extensions"]
    assert by_name["terraform"]["parser"]["runtime_by_extension"][".hcl"] == "hcl"
    assert by_name["terraform"]["parser"]["runtime_by_extension"][".tf"] == "terraform"
    assert by_name["csharp"]["parser"]["language"] == "csharp"
    assert by_name["systemverilog"]["parser"]["language"] == "verilog"
    assert by_name["systemverilog"]["parser"]["alias_source"] == "runtime_alias"
    assert by_name["systemverilog"]["parser"]["available"] is True
