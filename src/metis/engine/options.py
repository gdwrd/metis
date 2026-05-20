# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReviewAgenticOptions:
    max_iterations: int = 2
    max_tool_calls: int = 4
    tool_timeout_seconds: int = 5
    max_extra_tokens: int = 8000
    wallclock_seconds: float = 60.0


@dataclass(frozen=True, slots=True)
class ReviewOptions:
    use_retrieval_context: bool = True
    review_mode: str = "standard"
    review_profile: str = "normal"
    agentic: ReviewAgenticOptions = ReviewAgenticOptions()
    skip_test_files: bool = False
    extra_test_path_patterns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        normalized = _normalize_review_mode(self.review_mode)
        if normalized != self.review_mode:
            object.__setattr__(self, "review_mode", normalized)
        normalized_profile = _normalize_review_profile(self.review_profile)
        if normalized_profile != self.review_profile:
            object.__setattr__(self, "review_profile", normalized_profile)
        if isinstance(self.extra_test_path_patterns, str):
            object.__setattr__(
                self,
                "extra_test_path_patterns",
                (self.extra_test_path_patterns,),
            )
        elif not isinstance(self.extra_test_path_patterns, tuple):
            object.__setattr__(
                self,
                "extra_test_path_patterns",
                tuple(str(item) for item in self.extra_test_path_patterns),
            )


@dataclass(frozen=True, slots=True)
class TriageOptions:
    use_retrieval_context: bool = True
    include_triaged: bool = False
    triage_evidence_budget: str = "standard"
    triage_evidence_retry_timeout_seconds: float = 20.0
    skip_test_files: bool = False
    extra_test_path_patterns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.extra_test_path_patterns, str):
            object.__setattr__(
                self,
                "extra_test_path_patterns",
                (self.extra_test_path_patterns,),
            )
        elif not isinstance(self.extra_test_path_patterns, tuple):
            object.__setattr__(
                self,
                "extra_test_path_patterns",
                tuple(str(item) for item in self.extra_test_path_patterns),
            )


def coerce_review_options(
    options: ReviewOptions | None = None,
    *,
    use_retrieval_context: bool | None = None,
    review_mode: str | None = None,
    review_profile: str | None = None,
    agentic: ReviewAgenticOptions | None = None,
    skip_test_files: bool | None = None,
    extra_test_path_patterns: tuple[str, ...] | list[str] | None = None,
) -> ReviewOptions:
    if options is None:
        return ReviewOptions(
            use_retrieval_context=(
                True if use_retrieval_context is None else use_retrieval_context
            ),
            review_mode=_normalize_review_mode(review_mode),
            review_profile=_normalize_review_profile(review_profile),
            agentic=agentic or ReviewAgenticOptions(),
            skip_test_files=False if skip_test_files is None else skip_test_files,
            extra_test_path_patterns=_coerce_path_patterns(extra_test_path_patterns),
        )
    if (
        use_retrieval_context is None
        and review_mode is None
        and review_profile is None
        and agentic is None
        and skip_test_files is None
        and extra_test_path_patterns is None
    ):
        _normalize_review_mode(options.review_mode)
        _normalize_review_profile(options.review_profile)
        return options
    return ReviewOptions(
        use_retrieval_context=(
            options.use_retrieval_context
            if use_retrieval_context is None
            else use_retrieval_context
        ),
        review_mode=(
            options.review_mode
            if review_mode is None
            else _normalize_review_mode(review_mode)
        ),
        review_profile=(
            options.review_profile
            if review_profile is None
            else _normalize_review_profile(review_profile)
        ),
        agentic=agentic or options.agentic,
        skip_test_files=(
            options.skip_test_files if skip_test_files is None else skip_test_files
        ),
        extra_test_path_patterns=(
            options.extra_test_path_patterns
            if extra_test_path_patterns is None
            else _coerce_path_patterns(extra_test_path_patterns)
        ),
    )


def _normalize_review_mode(value: str | None) -> str:
    mode = (value or "standard").strip().lower()
    if mode not in {"standard", "agentic"}:
        raise ValueError(f"Unsupported review mode: {value}")
    return mode


def _normalize_review_profile(value: str | None) -> str:
    profile = (value or "normal").strip().lower()
    if profile not in {"normal", "research"}:
        raise ValueError(f"Unsupported review profile: {value}")
    return profile


def _coerce_path_patterns(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        items = [value]
    else:
        items = value
    return tuple(str(item) for item in items)


def coerce_triage_options(
    options: TriageOptions | None = None,
    *,
    use_retrieval_context: bool | None = None,
    include_triaged: bool | None = None,
    triage_evidence_budget: str | None = None,
    triage_evidence_retry_timeout_seconds: float | None = None,
    skip_test_files: bool | None = None,
    extra_test_path_patterns: tuple[str, ...] | list[str] | None = None,
) -> TriageOptions:
    if options is None:
        return TriageOptions(
            use_retrieval_context=(
                True if use_retrieval_context is None else use_retrieval_context
            ),
            include_triaged=(False if include_triaged is None else include_triaged),
            triage_evidence_budget=triage_evidence_budget or "standard",
            triage_evidence_retry_timeout_seconds=(
                20.0
                if triage_evidence_retry_timeout_seconds is None
                else triage_evidence_retry_timeout_seconds
            ),
            skip_test_files=False if skip_test_files is None else skip_test_files,
            extra_test_path_patterns=_coerce_path_patterns(extra_test_path_patterns),
        )
    return TriageOptions(
        use_retrieval_context=(
            options.use_retrieval_context
            if use_retrieval_context is None
            else use_retrieval_context
        ),
        include_triaged=(
            options.include_triaged if include_triaged is None else include_triaged
        ),
        triage_evidence_budget=(
            options.triage_evidence_budget
            if triage_evidence_budget is None
            else triage_evidence_budget
        ),
        triage_evidence_retry_timeout_seconds=(
            options.triage_evidence_retry_timeout_seconds
            if triage_evidence_retry_timeout_seconds is None
            else triage_evidence_retry_timeout_seconds
        ),
        skip_test_files=(
            options.skip_test_files if skip_test_files is None else skip_test_files
        ),
        extra_test_path_patterns=(
            options.extra_test_path_patterns
            if extra_test_path_patterns is None
            else _coerce_path_patterns(extra_test_path_patterns)
        ),
    )
