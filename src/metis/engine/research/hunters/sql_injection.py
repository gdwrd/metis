# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.research.hunters.graph_pattern import (
    GraphPatternHunter,
    GraphPatternSpec,
)


class SqlInjectionHunter(GraphPatternHunter):
    name = "sql_injection"
    vulnerability_class = "CWE-89"

    def __init__(self) -> None:
        super().__init__(
            GraphPatternSpec(
                name=self.name,
                vulnerability_class=self.vulnerability_class,
                title="SQL injection path",
                sink_obligation="sql_sink",
                missing_mitigation_obligation="missing_parameterization",
                mitigation_label="SQL parameterization or escaping",
                sink_markers=(
                    "sql_query",
                    "query",
                    "queryrow",
                    "mysql_query",
                    "mysqli_query",
                    "pg_query",
                    "sqlite_query",
                    "pdo.query",
                    "pdo.exec",
                    "db.query",
                    "db.exec",
                    "dbh.do",
                    "execute",
                    "exec",
                ),
                mitigation_markers=(
                    "prepare",
                    "bind_param",
                    "bindvalue",
                    "quote",
                    "escape",
                    "real_escape_string",
                    "intval",
                    "filter_input",
                    "parameterize",
                ),
                impact=(
                    "Attacker-controlled input may reach a SQL interpreter "
                    "without parameterization or escaping."
                ),
                supported_languages=("python", "php", "perl"),
            )
        )
