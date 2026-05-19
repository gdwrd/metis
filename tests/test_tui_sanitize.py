# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.tui.sanitize import sanitize_text, sanitize_value


def test_sanitize_text_redacts_common_secret_shapes():
    text = (
        "api key: sk-testsecret123 Authorization=Bearer abc.def "
        "token=my-token secret: plain"
    )

    cleaned = sanitize_text(text)

    assert "sk-testsecret123" not in cleaned
    assert "abc.def" not in cleaned
    assert "my-token" not in cleaned
    assert "plain" not in cleaned
    assert "<redacted>" in cleaned


def test_sanitize_text_redacts_quoted_config_reprs():
    text = (
        '{"api_key": "plain-secret", "default_headers": "header-secret"} '
        "{'x-api-key': 'other-secret'}"
    )

    cleaned = sanitize_text(text)

    assert "plain-secret" not in cleaned
    assert "header-secret" not in cleaned
    assert "other-secret" not in cleaned
    assert cleaned.count("<redacted>") == 3


def test_sanitize_value_redacts_nested_header_and_provider_config_shapes():
    payload = {
        "default_headers": {"Authorization": "Bearer nested.secret"},
        "config": {"x-api-key": "header-secret", "plain": "visible"},
    }

    cleaned = sanitize_value(payload)

    assert cleaned["default_headers"] == "<redacted>"
    assert cleaned["config"]["x-api-key"] == "<redacted>"
    assert cleaned["config"]["plain"] == "visible"
