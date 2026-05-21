# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.research import HunterRegistry, HypothesisStatus, ResearchOptions


def test_crypto_misuse_hunter_reports_weak_crypto_paths(engine, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def hmac(value):\n"
        "    return value\n\n"
        "def md5(value):\n"
        "    return value\n\n"
        "def hash_user_token(request):\n"
        "    token = request.args.get('token')\n"
        "    return md5(token)\n\n"
        "def hash_safe_token(request):\n"
        "    token = hmac(request.args.get('token'))\n"
        "    return md5(token)\n",
        encoding="utf-8",
    )
    engine.codebase_path = str(repo)
    engine._config.codebase_path = str(repo)

    result = engine.research.run(
        repo,
        options=ResearchOptions(hunters=("crypto_misuse",), rebuild=True),
    )

    by_symbol = {item.locations[0].symbol: item for item in result.generated}
    assert by_symbol["hash_user_token"].status == HypothesisStatus.PROVEN
    assert by_symbol["hash_user_token"].vulnerability_class == "CWE-327"
    assert by_symbol["hash_safe_token"].status == HypothesisStatus.KILLED


def test_crypto_misuse_hunter_is_promoted():
    metadata = HunterRegistry.default().metadata_for("crypto_misuse")

    assert metadata.default_enabled is True
    assert metadata.experimental is False
    assert metadata.promotion_status == "promoted"
