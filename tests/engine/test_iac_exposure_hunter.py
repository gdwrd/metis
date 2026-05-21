# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HypothesisStatus, ResearchOptions


def test_iac_exposure_hunter_reports_public_terraform_resources(engine, tmp_path):
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
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("iac_exposure",), rebuild=True),
    )

    assert result.proven
    assert result.proven[0].status == HypothesisStatus.PROVEN
    assert result.proven[0].vulnerability_class == "CWE-284"
