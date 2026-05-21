# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


RESEARCH_SCHEMA_VERSION = "1"
SECURITY_GRAPH_SCHEMA_VERSION = "2"
PROJECT_SECURITY_MODEL_SCHEMA_VERSION = "2"
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


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def build_hypothesis_id(*parts: Any) -> str:
    normalized = "|".join(str(part or "").strip() for part in parts)
    digest = sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"hyp-{digest}"


class HypothesisStatus(str, Enum):
    CANDIDATE = "candidate"
    PROVEN = "proven"
    KILLED = "killed"
    UNRESOLVED = "unresolved"


class EvidenceStatus(str, Enum):
    SATISFIED = "satisfied"
    FAILED = "failed"
    MISSING = "missing"
    NOT_APPLICABLE = "not_applicable"


class EvidenceKind(str, Enum):
    DEFINITION = "definition"
    CALL_PATH = "call_path"
    GUARD_CHECK = "guard_check"
    SANITIZER_CHECK = "sanitizer_check"
    CONFIG_CHECK = "config_check"
    ROUTE_REGISTRATION = "route_registration"
    TYPE_CONSTRAINT = "type_constraint"
    RUNTIME_FIXTURE = "runtime_fixture"
    STATIC_TRACE = "static_trace"
    NEGATIVE_EVIDENCE = "negative_evidence"
    PROOF_ARTIFACT = "proof_artifact"


class SourceTrust(str, Enum):
    CODE = "code"
    CONFIG = "config"
    TEST = "test"
    TOOL_OUTPUT = "tool_output"
    MODEL = "model"


class ResearchPriority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ResearchRunMode(str, Enum):
    RESEARCH = "research"
    VARIANTS = "variants"


class ResearchRunState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ResearchLessonType(str, Enum):
    SOURCE_PATTERN = "source_pattern"
    SINK_PATTERN = "sink_pattern"
    GUARD_PATTERN = "guard_pattern"
    SANITIZER_PATTERN = "sanitizer_pattern"
    ROUTE_GROUPING_RULE = "route_grouping_rule"
    FRAMEWORK_REGISTRATION_RULE = "framework_registration_rule"
    FALSE_POSITIVE_SUPPRESSION = "false_positive_suppression"
    PROJECT_SPECIFIC_ASSET_RULE = "project_specific_asset_rule"


class ResearchLessonSource(str, Enum):
    PROVEN_HYPOTHESIS = "proven_hypothesis"
    KILLED_HYPOTHESIS = "killed_hypothesis"
    USER_CONFIRMED_FALSE_POSITIVE = "user_confirmed_false_positive"
    USER_CONFIRMED_TRUE_POSITIVE = "user_confirmed_true_positive"
    FIXED_VARIANT = "fixed_variant"


class ResearchLessonStatus(str, Enum):
    ACTIVE = "active"
    INVALIDATED = "invalidated"


class FlowStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    line: int | None = None
    symbol: str | None = None
    role: str
    detail: str | None = None

    @field_validator("line")
    @classmethod
    def _line_must_be_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("line must be positive")
        return value


class EvidenceObligation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str | None = None
    required: bool = True


class EvidenceLedgerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    entry_id: str = Field(default_factory=lambda: f"ev-{uuid4().hex[:16]}")
    obligation: str
    status: EvidenceStatus
    kind: EvidenceKind
    claim: str
    evidence: list[str] = Field(default_factory=list)
    file: str | None = None
    line: int | None = None
    symbol: str | None = None
    tool: str | None = None
    tool_input: str | None = None
    tool_output_excerpt: str | None = None
    source_trust: SourceTrust = SourceTrust.CODE
    created_at: str = Field(default_factory=utc_now)

    @field_validator("line")
    @classmethod
    def _line_must_be_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("line must be positive")
        return value


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    hunter: str
    vulnerability_class: str
    title: str
    source: str
    path: list[FlowStep] = Field(default_factory=list)
    sink: str | None = None
    asset: str | None = None
    expected_guard: str | None = None
    observed_guard: str | None = None
    missing_guard: str | None = None
    impact: str
    evidence_obligations: list[EvidenceObligation] = Field(default_factory=list)
    evidence: list[EvidenceLedgerEntry] = Field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.CANDIDATE
    kill_reason: str | None = None
    unresolved_reason: str | None = None
    confidence: float = 0.0
    locations: list[FlowStep] = Field(default_factory=list)
    sarif_rule_id: str | None = None
    lesson_refs: list[str] = Field(default_factory=list)
    priority: ResearchPriority = ResearchPriority.MEDIUM
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)
    engine_version: str | None = None
    schema_version: str = RESEARCH_SCHEMA_VERSION

    @field_validator("confidence")
    @classmethod
    def _confidence_range(cls, value: float) -> float:
        if value < 0.0 or value > 1.0:
            raise ValueError("confidence must be between 0 and 1")
        return value

    @model_validator(mode="after")
    def _status_has_required_evidence(self) -> "Hypothesis":
        if self.status == HypothesisStatus.PROVEN:
            satisfied = {
                entry.obligation
                for entry in self.evidence
                if entry.status == EvidenceStatus.SATISFIED
            }
            required = {
                obligation.name
                for obligation in self.evidence_obligations
                if obligation.required
            }
            if not satisfied:
                raise ValueError("proven hypotheses require satisfied evidence")
            missing = sorted(required - satisfied)
            if missing:
                raise ValueError(
                    "proven hypotheses are missing required evidence: "
                    + ", ".join(missing)
                )
            if any(
                entry.status == EvidenceStatus.MISSING and entry.obligation in required
                for entry in self.evidence
            ):
                raise ValueError(
                    "proven hypotheses cannot contain missing required evidence"
                )
        if self.status == HypothesisStatus.KILLED and not self.kill_reason:
            raise ValueError("killed hypotheses require kill_reason")
        if self.status == HypothesisStatus.UNRESOLVED and not self.unresolved_reason:
            raise ValueError("unresolved hypotheses require unresolved_reason")
        return self


class VariantPattern(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source: str
    source_path: str | None = None
    vulnerability_class: str
    original_vulnerability_shape: str
    fixed_guard: str | None = None
    fixed_sanitizer: str | None = None
    fixed_invariant: str | None = None
    search_predicates: list[str] = Field(default_factory=list)
    negative_examples: list[FlowStep] = Field(default_factory=list)
    changed_sinks: list[str] = Field(default_factory=list)
    added_guards: list[str] = Field(default_factory=list)
    added_sanitizers: list[str] = Field(default_factory=list)
    added_bounds_checks: list[str] = Field(default_factory=list)
    changed_route_access_policy: list[str] = Field(default_factory=list)
    changed_lifetime_or_privilege_invariants: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)
    schema_version: str = RESEARCH_SCHEMA_VERSION


class ResearchLesson(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: ResearchLessonType
    source: ResearchLessonSource
    summary: str
    pattern: str
    hunter: str | None = None
    vulnerability_class: str | None = None
    hypothesis_id: str | None = None
    file: str | None = None
    line: int | None = None
    symbol: str | None = None
    source_file_hashes: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: ResearchLessonStatus = ResearchLessonStatus.ACTIVE
    times_reused: int = 0
    last_seen_at: str | None = None
    invalidated_at: str | None = None
    invalidation_reason: str | None = None
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)
    schema_version: str = RESEARCH_SCHEMA_VERSION

    @field_validator("line")
    @classmethod
    def _line_must_be_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("line must be positive")
        return value

    @field_validator("times_reused")
    @classmethod
    def _times_reused_must_be_nonnegative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("times_reused must be non-negative")
        return value


class ResearchRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated: list[Hypothesis] = Field(default_factory=list)
    proven: list[Hypothesis] = Field(default_factory=list)
    killed: list[Hypothesis] = Field(default_factory=list)
    unresolved: list[Hypothesis] = Field(default_factory=list)
    evidence: list[EvidenceLedgerEntry] = Field(default_factory=list)
    evidence_ledger_path: str | None = None
    hypotheses_path: str | None = None
    sarif_path: str | None = None
    research_report_path: str | None = None
    proof_artifact_paths: list[str] = Field(default_factory=list)
    metric_summary: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_hypotheses(
        cls,
        hypotheses: list[Hypothesis],
        *,
        evidence_ledger_path: str | None = None,
        hypotheses_path: str | None = None,
        metric_summary: dict[str, Any] | None = None,
    ) -> "ResearchRunResult":
        return cls(
            generated=list(hypotheses),
            proven=[
                item for item in hypotheses if item.status == HypothesisStatus.PROVEN
            ],
            killed=[
                item for item in hypotheses if item.status == HypothesisStatus.KILLED
            ],
            unresolved=[
                item
                for item in hypotheses
                if item.status == HypothesisStatus.UNRESOLVED
            ],
            evidence=[
                entry for hypothesis in hypotheses for entry in hypothesis.evidence
            ],
            evidence_ledger_path=evidence_ledger_path,
            hypotheses_path=hypotheses_path,
            metric_summary=metric_summary or {},
        )


class ResearchRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    root: str | None = None
    mode: ResearchRunMode = ResearchRunMode.RESEARCH
    hunters: tuple[str, ...] = DEFAULT_RESEARCH_HUNTERS
    persist: bool = False
    rebuild: bool = False
    research_budget: str = "standard"
    emit_killed: bool = False
    emit_unresolved: bool = False
    proof_artifacts: bool = False
    evidence_policy: str = "triage_evidence"
    hypotheses_path: str | None = None
    evidence_ledger_path: str | None = None
    sarif_path: str | None = None
    research_report_path: str | None = None
    from_fix: str | None = None
    from_sarif: str | None = None
    from_report: str | None = None

    @field_validator("hunters", mode="before")
    @classmethod
    def _coerce_hunters(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return DEFAULT_RESEARCH_HUNTERS
        if isinstance(value, str):
            items = tuple(item.strip() for item in value.split(",") if item.strip())
            return items or DEFAULT_RESEARCH_HUNTERS
        items = tuple(str(item).strip() for item in value if str(item).strip())
        return items or DEFAULT_RESEARCH_HUNTERS

    @field_validator("research_budget")
    @classmethod
    def _research_budget_non_empty(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if not normalized:
            raise ValueError("research_budget must be non-empty")
        return normalized

    @field_validator("evidence_policy")
    @classmethod
    def _evidence_policy_non_empty(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if not normalized:
            raise ValueError("evidence_policy must be non-empty")
        return normalized

    @model_validator(mode="after")
    def _variant_sources_for_variant_mode(self) -> "ResearchRunRequest":
        if self.mode == ResearchRunMode.VARIANTS and not any(
            (self.from_fix, self.from_sarif, self.from_report)
        ):
            raise ValueError(
                "variant research requests require one of from_fix, "
                "from_sarif, or from_report"
            )
        return self

    def to_options(self):
        from .options import ResearchOptions

        return ResearchOptions(
            hunters=self.hunters,
            persist=self.persist,
            rebuild=self.rebuild,
            research_budget=self.research_budget,
            emit_killed=self.emit_killed,
            emit_unresolved=self.emit_unresolved,
            proof_artifacts=self.proof_artifacts,
            evidence_policy=self.evidence_policy,
            hypotheses_path=self.hypotheses_path,
            evidence_ledger_path=self.evidence_ledger_path,
            sarif_path=self.sarif_path,
            research_report_path=self.research_report_path,
        )


class ResearchRunStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: str = Field(default_factory=lambda: f"research-{uuid4().hex[:16]}")
    state: ResearchRunState = ResearchRunState.QUEUED
    request: ResearchRunRequest | None = None
    created_at: str = Field(default_factory=utc_now)
    started_at: str | None = None
    completed_at: str | None = None
    generated_count: int = 0
    proven_count: int = 0
    killed_count: int = 0
    unresolved_count: int = 0
    hypotheses_path: str | None = None
    evidence_ledger_path: str | None = None
    sarif_path: str | None = None
    research_report_path: str | None = None
    proof_artifact_paths: tuple[str, ...] = Field(default_factory=tuple)
    metric_summary: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None

    @classmethod
    def from_result(
        cls,
        result: ResearchRunResult,
        *,
        job_id: str | None = None,
        request: ResearchRunRequest | None = None,
        created_at: str | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
    ) -> "ResearchRunStatus":
        return cls(
            job_id=job_id or f"research-{uuid4().hex[:16]}",
            state=ResearchRunState.SUCCEEDED,
            request=request,
            created_at=created_at or started_at or utc_now(),
            started_at=started_at,
            completed_at=completed_at or utc_now(),
            generated_count=len(result.generated),
            proven_count=len(result.proven),
            killed_count=len(result.killed),
            unresolved_count=len(result.unresolved),
            hypotheses_path=result.hypotheses_path,
            evidence_ledger_path=result.evidence_ledger_path,
            sarif_path=result.sarif_path,
            research_report_path=result.research_report_path,
            proof_artifact_paths=tuple(result.proof_artifact_paths),
            metric_summary=dict(result.metric_summary),
        )

    @classmethod
    def failed(
        cls,
        *,
        error: str,
        job_id: str | None = None,
        request: ResearchRunRequest | None = None,
        created_at: str | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
    ) -> "ResearchRunStatus":
        return cls(
            job_id=job_id or f"research-{uuid4().hex[:16]}",
            state=ResearchRunState.FAILED,
            request=request,
            created_at=created_at or started_at or utc_now(),
            started_at=started_at,
            completed_at=completed_at or utc_now(),
            error=error,
        )


class HypothesisQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: str | None = None
    statuses: tuple[HypothesisStatus, ...] = Field(default_factory=tuple)
    hunters: tuple[str, ...] = Field(default_factory=tuple)
    vulnerability_classes: tuple[str, ...] = Field(default_factory=tuple)
    priorities: tuple[ResearchPriority, ...] = Field(default_factory=tuple)
    file: str | None = None
    symbol: str | None = None
    offset: int = 0
    limit: int | None = None

    @field_validator("statuses", "hunters", "vulnerability_classes", mode="before")
    @classmethod
    def _coerce_string_tuple(cls, value: Any) -> tuple[Any, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return tuple(value)

    @field_validator("priorities", mode="before")
    @classmethod
    def _coerce_priority_tuple(cls, value: Any) -> tuple[Any, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return tuple(value)

    @field_validator("offset")
    @classmethod
    def _offset_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("offset must be non-negative")
        return value

    @field_validator("limit")
    @classmethod
    def _limit_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("limit must be positive")
        return value

    def filter(self, hypotheses: list[Hypothesis]) -> list[Hypothesis]:
        matched = [item for item in hypotheses if self.matches(item)]
        if self.offset:
            matched = matched[self.offset :]
        if self.limit is not None:
            matched = matched[: self.limit]
        return matched

    def matches(self, hypothesis: Hypothesis) -> bool:
        if self.hypothesis_id and hypothesis.id != self.hypothesis_id:
            return False
        if self.statuses and hypothesis.status not in self.statuses:
            return False
        if self.hunters and hypothesis.hunter not in self.hunters:
            return False
        if (
            self.vulnerability_classes
            and hypothesis.vulnerability_class not in self.vulnerability_classes
        ):
            return False
        if self.priorities and hypothesis.priority not in self.priorities:
            return False
        if self.file and not any(
            step.file == self.file for step in [*hypothesis.locations, *hypothesis.path]
        ):
            return False
        if self.symbol and not any(
            step.symbol == self.symbol
            for step in [*hypothesis.locations, *hypothesis.path]
        ):
            return False
        return True


class EvidenceQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: str | None = None
    statuses: tuple[EvidenceStatus, ...] = Field(default_factory=tuple)
    kinds: tuple[EvidenceKind, ...] = Field(default_factory=tuple)
    obligation: str | None = None
    file: str | None = None
    symbol: str | None = None
    offset: int = 0
    limit: int | None = None

    @field_validator("statuses", "kinds", mode="before")
    @classmethod
    def _coerce_enum_tuple(cls, value: Any) -> tuple[Any, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return tuple(value)

    @field_validator("offset")
    @classmethod
    def _offset_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("offset must be non-negative")
        return value

    @field_validator("limit")
    @classmethod
    def _limit_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("limit must be positive")
        return value

    def filter(self, evidence: list[EvidenceLedgerEntry]) -> list[EvidenceLedgerEntry]:
        matched = [item for item in evidence if self.matches(item)]
        if self.offset:
            matched = matched[self.offset :]
        if self.limit is not None:
            matched = matched[: self.limit]
        return matched

    def matches(self, entry: EvidenceLedgerEntry) -> bool:
        if self.hypothesis_id and entry.hypothesis_id != self.hypothesis_id:
            return False
        if self.statuses and entry.status not in self.statuses:
            return False
        if self.kinds and entry.kind not in self.kinds:
            return False
        if self.obligation and entry.obligation != self.obligation:
            return False
        if self.file and entry.file != self.file:
            return False
        if self.symbol and entry.symbol != self.symbol:
            return False
        return True


class SecurityTag(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    value: str
    detail: str | None = None
    file: str | None = None
    line: int | None = None
    symbol: str | None = None
    confidence: float = 1.0

    @field_validator("line")
    @classmethod
    def _line_must_be_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("line must be positive")
        return value

    @field_validator("confidence")
    @classmethod
    def _confidence_range(cls, value: float) -> float:
        if value < 0.0 or value > 1.0:
            raise ValueError("confidence must be between 0 and 1")
        return value


class SecurityGraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    language: str | None = None
    signature: str | None = None
    parameters: list[str] = Field(default_factory=list)
    returns: list[str] = Field(default_factory=list)
    tags: list[SecurityTag] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("line", "end_line")
    @classmethod
    def _line_must_be_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("line must be positive")
        return value


class SecurityGraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    kind: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SECURITY_GRAPH_SCHEMA_VERSION
    generated_at: str = Field(default_factory=utc_now)
    analysis_root: str = ""
    project_root_hash: str
    file_hashes: dict[str, str] = Field(default_factory=dict)
    nodes: list[SecurityGraphNode] = Field(default_factory=list)
    edges: list[SecurityGraphEdge] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityModelEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    name: str
    file: str | None = None
    line: int | None = None
    symbol: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("line")
    @classmethod
    def _line_must_be_positive(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("line must be positive")
        return value


class ProjectSecurityModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PROJECT_SECURITY_MODEL_SCHEMA_VERSION
    generated_at: str = Field(default_factory=utc_now)
    analysis_root: str = ""
    project_root_hash: str
    file_hashes: dict[str, str] = Field(default_factory=dict)
    entrypoints: list[SecurityModelEntry] = Field(default_factory=list)
    trust_boundaries: list[SecurityModelEntry] = Field(default_factory=list)
    assets: list[SecurityModelEntry] = Field(default_factory=list)
    guards: list[SecurityModelEntry] = Field(default_factory=list)
    sources: list[SecurityModelEntry] = Field(default_factory=list)
    sinks: list[SecurityModelEntry] = Field(default_factory=list)
    sanitizers: list[SecurityModelEntry] = Field(default_factory=list)
    frameworks: list[SecurityModelEntry] = Field(default_factory=list)
    lessons: list[SecurityModelEntry] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
