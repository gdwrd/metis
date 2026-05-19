# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.configuration import load_metis_config
from metis.configuration import load_runtime_config


def test_load_metis_config_uses_yml_when_yaml_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "metis.yml").write_text("selected: yml\n", encoding="utf-8")

    config = load_metis_config()

    assert config == {"selected": "yml"}


def test_load_metis_config_prefers_yaml_over_yml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "metis.yaml").write_text("selected: yaml\n", encoding="utf-8")
    (tmp_path / "metis.yml").write_text("selected: yml\n", encoding="utf-8")

    config = load_metis_config()

    assert config == {"selected": "yaml"}


def test_load_runtime_config_reads_query_reasoning_effort(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
metis_engine:
  max_workers: 2
query:
  reasoning_effort: high
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llama_query_reasoning_effort"] == "high"


def test_load_runtime_config_openai_uses_openai_base_url_env(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://config.example.test/v1
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://env.example.test/v1")

    runtime = load_runtime_config(config_path)

    assert runtime["openai_api_base"] == "https://env.example.test/v1"


def test_load_runtime_config_openai_falls_back_to_config_base_url(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://config.example.test/v1
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    runtime = load_runtime_config(config_path)

    assert runtime["openai_api_base"] == "https://config.example.test/v1"


def test_load_runtime_config_accepts_query_reasoning_level_alias(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
query:
  reasoning_level: low
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llama_query_reasoning_effort"] == "low"


def test_load_runtime_config_reads_provider_reasoning_effort(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  reasoning_effort: xhigh
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
query:
  max_tokens: 1000
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llama_query_reasoning_effort"] == "xhigh"


def test_load_runtime_config_query_reasoning_overrides_provider(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  reasoning_effort: low
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
query:
  reasoning_effort: high
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llama_query_reasoning_effort"] == "high"


def test_load_runtime_config_reads_review_agentic_options(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
review:
  mode: agentic
  agentic:
    max_iterations: 2
    max_tool_calls: 4
    tool_timeout_seconds: 7
    max_extra_tokens: 1234
    wallclock_seconds: 30
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["review_mode"] == "agentic"
    assert runtime["review_agentic_max_iterations"] == 2
    assert runtime["review_agentic_max_tool_calls"] == 4
    assert runtime["review_agentic_tool_timeout_seconds"] == 7
    assert runtime["review_agentic_max_extra_tokens"] == 1234
    assert runtime["review_agentic_wallclock_seconds"] == 30.0


def test_load_runtime_config_reads_filters(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
filters:
  skip_test_files: true
  extra_test_path_patterns:
    - fixtures/**
    - samples/vulnerable/**
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["skip_test_files"] is True
    assert runtime["extra_test_path_patterns"] == [
        "fixtures/**",
        "samples/vulnerable/**",
    ]


def test_load_runtime_config_reads_speed_tunables(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
metis_engine:
  max_workers: 9
  review_max_workers: 11
  triage_max_workers: 13
  embed_batch_size: 256
  embed_cache_enabled: false
  embed_cache_max_mb: 42
  async_llm_enabled: true
  retrieval_cache_max_entries: 321
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["max_workers"] == 9
    assert runtime["review_max_workers"] == 11
    assert runtime["triage_max_workers"] == 13
    assert runtime["embed_batch_size"] == 256
    assert runtime["embed_cache_enabled"] is False
    assert runtime["embed_cache_max_mb"] == 42
    assert runtime["async_llm_enabled"] is True
    assert runtime["retrieval_cache_max_entries"] == 321
    assert runtime["code_embedding_extra_kwargs"]["embed_batch_size"] == 256
    assert runtime["docs_embedding_extra_kwargs"]["embed_batch_size"] == 256


def test_load_runtime_config_preserves_explicit_embedding_kwargs(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
  code_embedding_extra_kwargs:
    embed_batch_size: 7
metis_engine:
  embed_batch_size: 256
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["code_embedding_extra_kwargs"]["embed_batch_size"] == 7
    assert runtime["docs_embedding_extra_kwargs"]["embed_batch_size"] == 256
