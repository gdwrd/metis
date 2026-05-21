# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
import logging
import yaml  # type: ignore[import-untyped]

from importlib.resources import files, as_file
from pathlib import Path

logger = logging.getLogger("metis")
DEFAULT_RESEARCH_HUNTERS = (
    "authz_outlier",
    "command_injection",
    "code_injection",
    "crypto_misuse",
    "template_injection",
    "sql_injection",
    "injection_path",
    "nosql_injection",
    "path_traversal",
    "ssrf",
    "deserialization",
    "xss",
    "xxe",
    "iac_exposure",
    "memory_lifetime",
    "hardware_security",
)

DEFAULT_EMBED_BATCH_SIZE = 16


def _embedding_extra_kwargs(raw: object, embed_batch_size: int) -> dict[str, object]:
    kwargs: dict[str, object] = dict(raw) if isinstance(raw, dict) else {}
    kwargs.setdefault("embed_batch_size", embed_batch_size)
    return kwargs


def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_runtime_config(config_path=None, enable_psql=False):
    cfg = load_metis_config(config_path)
    engine_cfg = cfg.get("metis_engine", {})
    embed_batch_size = int(engine_cfg.get("embed_batch_size", DEFAULT_EMBED_BATCH_SIZE))

    runtime: dict[str, object] = {}
    if enable_psql:
        db_cfg = cfg.get("psql_database", {})
        provider = db_cfg.get("provider", "config")
        if provider == "env":
            secrets = dict(
                username=os.environ["PGUSER"],
                password=os.environ["PGPASSWORD"],
                host=os.environ.get("PGHOST", "localhost"),
                port=int(os.environ.get("PGPORT", 5432)),
                database_name=os.environ.get("PGDATABASE", "metis_db"),
            )
        elif provider == "config":
            secrets = db_cfg.get("credentials", {})
        else:
            raise ValueError(f"Unknown database config provider: {provider}")

        runtime.update(
            pg_username=secrets.get("username"),
            pg_password=secrets.get("password"),
            pg_host=secrets.get("host"),
            pg_port=secrets.get("port"),
            pg_db_name=secrets.get("database_name"),
        )

    llm_cfg = cfg.get("llm_provider", {})
    runtime["code_embedding_model"] = llm_cfg.get("code_embedding_model", "")
    runtime["docs_embedding_model"] = llm_cfg.get("docs_embedding_model", "")
    runtime["embed_batch_size"] = embed_batch_size
    runtime["code_embedding_extra_kwargs"] = _embedding_extra_kwargs(
        llm_cfg.get("code_embedding_extra_kwargs", {}),
        embed_batch_size,
    )
    runtime["docs_embedding_extra_kwargs"] = _embedding_extra_kwargs(
        llm_cfg.get("docs_embedding_extra_kwargs", {}),
        embed_batch_size,
    )

    llm_provider_name = cfg.get("llm_provider", {}).get("name", "").lower()
    runtime["llm_provider_name"] = llm_provider_name
    if llm_provider_name == "openai":
        llm_api_key = os.environ.get("OPENAI_API_KEY")
        if not llm_api_key:
            raise RuntimeError(
                "OPENAI_API_KEY environment variable is required for OpenAI provider but not set."
            )
        runtime["llm_api_key"] = llm_api_key
        runtime["model"] = llm_cfg.get("model", "")
        runtime["openai_api_base"] = os.environ.get("OPENAI_BASE_URL") or llm_cfg.get(
            "base_url", ""
        )
    elif llm_provider_name == "azure_openai":
        llm_api_key = os.environ.get("AZURE_OPENAI_API_KEY")
        if not llm_api_key:
            raise RuntimeError(
                "AZURE_OPENAI_API_KEY environment variable is required for Azure OpenAI provider but not set."
            )
        runtime["llm_api_key"] = llm_api_key
        runtime["azure_endpoint"] = llm_cfg.get("azure_endpoint", "")
        runtime["azure_api_version"] = llm_cfg.get("azure_api_version", "")
        runtime["engine"] = llm_cfg.get("engine", "")
        runtime["chat_deployment_model"] = llm_cfg.get("chat_deployment_model", "")
        runtime["code_embedding_deployment"] = llm_cfg.get(
            "code_embedding_deployment", ""
        )
        runtime["docs_embedding_deployment"] = llm_cfg.get(
            "docs_embedding_deployment", ""
        )
        runtime["model_token_param"] = llm_cfg.get(
            "model_token_param", "max_completion_tokens"
        )
        runtime["supports_temperature"] = llm_cfg.get("supports_temperature", False)
    elif llm_provider_name == "vllm":
        runtime["llm_api_key"] = llm_cfg.get("api_key")
        api_key_env = llm_cfg.get("api_key_env")
        if not runtime["llm_api_key"] and api_key_env:
            runtime["llm_api_key"] = os.environ.get(api_key_env)
        if not runtime["llm_api_key"]:
            runtime["llm_api_key"] = os.environ.get("VLLM_API_KEY")
        runtime["openai_api_base"] = llm_cfg.get("base_url", "")
        runtime["openai_default_headers"] = llm_cfg.get("default_headers", {})
        runtime["model"] = llm_cfg.get("model", "")
    elif llm_provider_name == "ollama":
        runtime["llm_api_key"] = llm_cfg.get("api_key") or ""
        api_key_env = llm_cfg.get("api_key_env")
        if not runtime["llm_api_key"] and api_key_env:
            runtime["llm_api_key"] = os.environ.get(api_key_env, "")
        runtime["openai_api_base"] = llm_cfg.get(
            "base_url", "http://localhost:11434/v1"
        )
        runtime["openai_default_headers"] = llm_cfg.get("default_headers", {})
        runtime["model"] = llm_cfg.get("model", "")
        runtime["force_openai_like"] = True
    else:
        raise ValueError(f"Unsupported LLM provider: {llm_provider_name}")

    # Engine/vector store settings
    runtime["max_token_length"] = engine_cfg.get("max_token_length", 100000)
    runtime["max_workers"] = engine_cfg.get("max_workers", 8)
    runtime["review_max_workers"] = int(
        engine_cfg.get("review_max_workers", runtime["max_workers"])
    )
    runtime["triage_max_workers"] = int(
        engine_cfg.get("triage_max_workers", runtime["max_workers"])
    )
    runtime["retrieval_cache_max_entries"] = int(
        engine_cfg.get("retrieval_cache_max_entries", 1024)
    )
    runtime["embed_cache_enabled"] = bool(engine_cfg.get("embed_cache_enabled", True))
    runtime["embed_cache_max_mb"] = int(engine_cfg.get("embed_cache_max_mb", 500))
    runtime["async_llm_enabled"] = bool(engine_cfg.get("async_llm_enabled", False))
    runtime["embed_dim"] = engine_cfg.get("embed_dim", 1536)
    runtime["doc_chunk_size"] = engine_cfg.get("doc_chunk_size", 1024)
    runtime["doc_chunk_overlap"] = engine_cfg.get("doc_chunk_overlap", 200)
    runtime["triage_checkpoint_every"] = engine_cfg.get("triage_checkpoint_every", 50)
    runtime["triage_tool_timeout_seconds"] = engine_cfg.get(
        "triage_tool_timeout_seconds", 12
    )
    runtime["hnsw_kwargs"] = engine_cfg.get(
        "hnsw_kwargs",
        {
            "hnsw_m": 16,
            "hnsw_ef_construction": 64,
            "hnsw_ef_search": 40,
            "hnsw_dist_method": "vector_cosine_ops",
        },
    )
    runtime["metisignore_file"] = engine_cfg.get("metisignore_file", None)
    runtime["review_code_include_paths"] = engine_cfg.get(
        "review_code_include_paths", []
    )
    runtime["review_code_exclude_paths"] = engine_cfg.get(
        "review_code_exclude_paths", []
    )

    filters_cfg = cfg.get("filters", {}) or {}
    runtime["skip_test_files"] = bool(filters_cfg.get("skip_test_files", False))
    extra_test_patterns = filters_cfg.get("extra_test_path_patterns", []) or []
    runtime["extra_test_path_patterns"] = [
        str(pattern) for pattern in extra_test_patterns if str(pattern or "").strip()
    ]

    review_cfg = cfg.get("review", {}) or {}
    agentic_cfg = review_cfg.get("agentic", {}) or {}
    runtime["review_mode"] = str(review_cfg.get("mode", "standard") or "standard")
    runtime["review_agentic_max_iterations"] = int(agentic_cfg.get("max_iterations", 2))
    runtime["review_agentic_max_tool_calls"] = int(agentic_cfg.get("max_tool_calls", 4))
    runtime["review_agentic_tool_timeout_seconds"] = int(
        agentic_cfg.get("tool_timeout_seconds", 5)
    )
    runtime["review_agentic_max_extra_tokens"] = int(
        agentic_cfg.get("max_extra_tokens", 8000)
    )
    runtime["review_agentic_wallclock_seconds"] = float(
        agentic_cfg.get("wallclock_seconds", 60.0)
    )

    research_cfg = cfg.get("research", {}) or {}
    research_hunters = research_cfg.get("hunters", DEFAULT_RESEARCH_HUNTERS)
    if isinstance(research_hunters, str):
        runtime["research_hunters"] = research_hunters
    else:
        runtime["research_hunters"] = ",".join(
            str(hunter).strip()
            for hunter in research_hunters
            if str(hunter or "").strip()
        )
    runtime["research_budget"] = str(
        research_cfg.get("budget", research_cfg.get("research_budget", "standard"))
        or "standard"
    )
    runtime["research_emit_killed"] = bool(research_cfg.get("emit_killed", False))
    runtime["research_emit_unresolved"] = bool(
        research_cfg.get("emit_unresolved", False)
    )
    runtime["research_proof_artifacts"] = bool(
        research_cfg.get("proof_artifacts", False)
    )
    runtime["research_evidence_policy"] = str(
        research_cfg.get("evidence_policy", "triage_evidence") or "triage_evidence"
    )

    # Query config
    query_cfg = cfg.get("query", {})
    runtime["llama_query_model"] = query_cfg.get("model") or runtime.get("model", "")
    runtime["llama_query_temperature"] = query_cfg.get("temperature", 0.0)
    runtime["llama_query_max_tokens"] = query_cfg.get("max_tokens", 500)
    runtime["llama_query_reasoning_effort"] = (
        query_cfg.get("reasoning_effort")
        or query_cfg.get("reasoning_level")
        or llm_cfg.get("reasoning_effort")
        or llm_cfg.get("reasoning_level")
    )
    runtime["similarity_top_k"] = query_cfg.get("similarity_top_k", 5)
    runtime["triage_similarity_top_k"] = query_cfg.get("triage_similarity_top_k", 3)
    runtime["response_mode"] = query_cfg.get("response_mode", "compact")

    return runtime


def load_plugin_config(plugins_path: str | Path | None = None):
    return config_path_fallback("plugins.yaml", "metis.plugins", plugins_path)


def load_metis_config(config_path: str | Path | None = None):
    return config_path_fallback(
        "metis.yaml",
        "metis",
        config_path,
        alt_filenames=("metis.yml",),
    )


def config_path_fallback(
    filename: str,
    anchor: str,
    config_path: str | Path | None = None,
    alt_filenames: tuple[str, ...] = (),
):
    """
    Loads the config from either a given path, the current working
    directory or from the packaged resource directory.
    """
    candidate_filenames = (filename, *alt_filenames)

    if config_path is not None:
        config_path = Path(config_path)
        if not config_path.is_file():
            raise FileNotFoundError(f"Config not found: {config_path}")
        logger.info(f"Loading {config_path.name} from {config_path}")
        return load_yaml(config_path)

    for candidate_filename in candidate_filenames:
        cwd_path = Path.cwd() / candidate_filename
        if cwd_path.is_file():
            logger.info(f"Loading {candidate_filename} from {cwd_path}")
            return load_yaml(cwd_path)

    for candidate_filename in candidate_filenames:
        resource = files(anchor) / candidate_filename
        if not resource.is_file():
            continue

        # ensure we have a real path
        with as_file(resource) as real_path:
            logger.info(f"Loading default {candidate_filename}")
            return load_yaml(real_path)

    supported_names = ", ".join(candidate_filenames)
    raise FileNotFoundError(
        f"No config file ({supported_names}) found in CWD or package resources"
    )
