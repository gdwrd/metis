# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from metis.engine.research.models import (
    FlowStep,
    Hypothesis,
    HypothesisStatus,
    ResearchLesson,
    ResearchLessonSource,
    ResearchLessonStatus,
    ResearchLessonType,
    utc_now,
)


@dataclass(frozen=True)
class LessonRefreshResult:
    active: list[ResearchLesson]
    invalidated: list[ResearchLesson]


class ResearchLearningStore:
    def __init__(self, repository_or_path) -> None:
        self._repository_or_path = repository_or_path

    @property
    def path(self) -> Path:
        get_path = getattr(self._repository_or_path, "get_research_lessons_path", None)
        if callable(get_path):
            return Path(get_path())
        return Path(self._repository_or_path)

    def read_all(self) -> list[ResearchLesson]:
        return _read_lessons(self.path)

    def read_latest(self) -> list[ResearchLesson]:
        latest: dict[str, ResearchLesson] = {}
        for lesson in self.read_all():
            latest[lesson.id] = lesson
        return [latest[key] for key in sorted(latest)]

    def refresh(
        self,
        current_file_hashes: dict[str, str],
        *,
        persist: bool = True,
    ) -> LessonRefreshResult:
        active: list[ResearchLesson] = []
        invalidated: list[ResearchLesson] = []
        for lesson in self.read_latest():
            if lesson.status != ResearchLessonStatus.ACTIVE:
                continue
            if _lesson_hashes_match(lesson, current_file_hashes):
                active.append(lesson)
                continue
            now = utc_now()
            updated = lesson.model_copy(
                update={
                    "status": ResearchLessonStatus.INVALIDATED,
                    "invalidated_at": now,
                    "invalidation_reason": "source file hash changed",
                    "updated_at": now,
                }
            )
            invalidated.append(updated)
            if persist:
                _append_lesson(self.path, updated)
        return LessonRefreshResult(active=active, invalidated=invalidated)

    def learn_from_hypotheses(
        self,
        hypotheses: Iterable[Hypothesis],
        current_file_hashes: dict[str, str],
        *,
        source: ResearchLessonSource | None = None,
        persist: bool = True,
    ) -> list[ResearchLesson]:
        latest = {lesson.id: lesson for lesson in self.read_latest()}
        learned: list[ResearchLesson] = []
        for hypothesis in hypotheses:
            for lesson in _lessons_for_hypothesis(
                hypothesis,
                current_file_hashes,
                source=source,
            ):
                existing = latest.get(lesson.id)
                if existing is not None and _blocks_relearning(
                    existing,
                    current_file_hashes,
                ):
                    continue
                latest[lesson.id] = lesson
                learned.append(lesson)
                if persist:
                    _append_lesson(self.path, lesson)
        return learned

    def learn_from_user_feedback(
        self,
        hypothesis: Hypothesis,
        current_file_hashes: dict[str, str],
        *,
        confirmed_true_positive: bool,
        persist: bool = True,
    ) -> list[ResearchLesson]:
        source = (
            ResearchLessonSource.USER_CONFIRMED_TRUE_POSITIVE
            if confirmed_true_positive
            else ResearchLessonSource.USER_CONFIRMED_FALSE_POSITIVE
        )
        feedback_hypothesis = hypothesis.model_copy(
            update={
                "status": (
                    HypothesisStatus.PROVEN
                    if confirmed_true_positive
                    else HypothesisStatus.KILLED
                ),
                "kill_reason": (
                    None
                    if confirmed_true_positive
                    else hypothesis.kill_reason or "User confirmed false positive"
                ),
                "unresolved_reason": None,
            }
        )
        return self.learn_from_hypotheses(
            [feedback_hypothesis],
            current_file_hashes,
            source=source,
            persist=persist,
        )

    def record_reuse(
        self,
        lesson_ids: Iterable[str],
        *,
        persist: bool = True,
    ) -> list[ResearchLesson]:
        requested = {str(lesson_id) for lesson_id in lesson_ids if lesson_id}
        if not requested:
            return []
        latest = {lesson.id: lesson for lesson in self.read_latest()}
        reused: list[ResearchLesson] = []
        now = utc_now()
        for lesson_id in sorted(requested):
            lesson = latest.get(lesson_id)
            if lesson is None or lesson.status != ResearchLessonStatus.ACTIVE:
                continue
            updated = lesson.model_copy(
                update={
                    "times_reused": lesson.times_reused + 1,
                    "last_seen_at": now,
                    "updated_at": now,
                }
            )
            reused.append(updated)
            if persist:
                _append_lesson(self.path, updated)
        return reused


class AuthzLessonIndex:
    def __init__(self, lessons: Iterable[ResearchLesson], *, hunter: str) -> None:
        self._hunter = hunter
        self._lessons = tuple(
            lesson
            for lesson in lessons
            if lesson.status == ResearchLessonStatus.ACTIVE and lesson.hunter == hunter
        )

    def expected_guard_for(self, asset: str) -> str | None:
        for lesson in self._lessons:
            if lesson.type != ResearchLessonType.GUARD_PATTERN:
                continue
            if _lesson_metadata_str(lesson, "asset") != asset:
                continue
            guard = _lesson_metadata_str(lesson, "expected_guard")
            if guard:
                return guard
        return None

    def suppression_for(
        self,
        *,
        source: str,
        file: str | None,
        symbol: str | None,
        observed_guards: Iterable[str],
    ) -> ResearchLesson | None:
        for lesson in self._lessons:
            if false_positive_suppression_matches(
                lesson,
                hunter=self._hunter,
                source=source,
                file=file,
                symbol=symbol,
                observed_guards=observed_guards,
            ):
                return lesson
        return None

    def refs_for(
        self,
        *,
        source: str,
        asset: str,
        expected_guard: str | None,
    ) -> list[str]:
        refs: set[str] = set()
        for lesson in self._lessons:
            if (
                lesson.type == ResearchLessonType.SOURCE_PATTERN
                and _lesson_metadata_str(lesson, "source") == source
            ):
                refs.add(lesson.id)
            if (
                lesson.type == ResearchLessonType.PROJECT_SPECIFIC_ASSET_RULE
                and _lesson_metadata_str(lesson, "asset") == asset
            ):
                refs.add(lesson.id)
            if (
                expected_guard
                and lesson.type == ResearchLessonType.GUARD_PATTERN
                and _lesson_metadata_str(lesson, "asset") == asset
                and _lesson_metadata_str(lesson, "expected_guard") == expected_guard
            ):
                refs.add(lesson.id)
        return sorted(refs)


def false_positive_suppression_matches(
    lesson: ResearchLesson,
    *,
    hunter: str,
    source: str,
    file: str | None,
    symbol: str | None,
    observed_guards: Iterable[str] = (),
) -> bool:
    if lesson.type != ResearchLessonType.FALSE_POSITIVE_SUPPRESSION:
        return False
    if not _has_scoped_false_positive_suppression(lesson):
        return False
    if lesson.hunter and lesson.hunter != hunter:
        return False
    if lesson.file != file:
        return False
    if lesson.symbol != symbol:
        return False
    if str(lesson.metadata.get("source") or "") != source:
        return False
    expected_guards = observed_guards_for_lesson(lesson)
    current_guards = {str(guard).strip() for guard in observed_guards if str(guard).strip()}
    if expected_guards and not expected_guards.issubset(current_guards):
        return False
    return True


def _lesson_metadata_str(lesson: ResearchLesson, key: str) -> str:
    return str(lesson.metadata.get(key) or "")


def observed_guards_for_lesson(lesson: ResearchLesson) -> set[str]:
    raw_guards = lesson.metadata.get("observed_guards")
    if isinstance(raw_guards, list | tuple | set):
        guards = {str(guard).strip() for guard in raw_guards if str(guard).strip()}
        if guards:
            return guards
    observed_guard = str(lesson.metadata.get("observed_guard") or "")
    return {
        guard.strip()
        for guard in observed_guard.split(",")
        if guard.strip()
    }


def observed_guards_for_hypothesis(hypothesis: Hypothesis) -> list[str]:
    return _observed_guards(hypothesis)


def _lessons_for_hypothesis(
    hypothesis: Hypothesis,
    current_file_hashes: dict[str, str],
    *,
    source: ResearchLessonSource | None,
) -> list[ResearchLesson]:
    if hypothesis.status == HypothesisStatus.KILLED:
        if not _can_learn_false_positive_suppression(
            hypothesis,
            current_file_hashes,
        ):
            return []
        return [
            _lesson_from_hypothesis(
                hypothesis,
                current_file_hashes,
                lesson_type=ResearchLessonType.FALSE_POSITIVE_SUPPRESSION,
                source=source or ResearchLessonSource.KILLED_HYPOTHESIS,
                pattern="|".join(
                    (
                        hypothesis.hunter,
                        hypothesis.source,
                        _primary_symbol(hypothesis) or "",
                        hypothesis.observed_guard or "",
                        hypothesis.expected_guard or "",
                    )
                ),
                summary=f"Suppress repeat candidate killed for {hypothesis.title}.",
            )
        ]
    if hypothesis.status != HypothesisStatus.PROVEN:
        return []

    lesson_source = source or ResearchLessonSource.PROVEN_HYPOTHESIS
    lessons: list[ResearchLesson] = []
    if hypothesis.expected_guard:
        lessons.append(
            _lesson_from_hypothesis(
                hypothesis,
                current_file_hashes,
                lesson_type=ResearchLessonType.GUARD_PATTERN,
                source=lesson_source,
                pattern="|".join(
                    (
                        hypothesis.hunter,
                        hypothesis.asset or "",
                        hypothesis.expected_guard,
                    )
                ),
                summary=(
                    f"{hypothesis.asset or hypothesis.source} paths expect "
                    f"guard {hypothesis.expected_guard}."
                ),
            )
        )
    if hypothesis.source:
        lessons.append(
            _lesson_from_hypothesis(
                hypothesis,
                current_file_hashes,
                lesson_type=ResearchLessonType.SOURCE_PATTERN,
                source=lesson_source,
                pattern=f"{hypothesis.hunter}|{hypothesis.source}",
                summary=f"{hypothesis.source} is a relevant research source.",
            )
        )
    if hypothesis.sink:
        lessons.append(
            _lesson_from_hypothesis(
                hypothesis,
                current_file_hashes,
                lesson_type=ResearchLessonType.SINK_PATTERN,
                source=lesson_source,
                pattern=f"{hypothesis.hunter}|{hypothesis.sink}",
                summary=f"{hypothesis.sink} is a relevant research sink.",
            )
        )
    if hypothesis.asset:
        lessons.append(
            _lesson_from_hypothesis(
                hypothesis,
                current_file_hashes,
                lesson_type=ResearchLessonType.PROJECT_SPECIFIC_ASSET_RULE,
                source=lesson_source,
                pattern=f"{hypothesis.hunter}|{hypothesis.asset}",
                summary=f"{hypothesis.asset} is a project-specific protected asset.",
            )
        )
    return lessons


def _lesson_from_hypothesis(
    hypothesis: Hypothesis,
    current_file_hashes: dict[str, str],
    *,
    lesson_type: ResearchLessonType,
    source: ResearchLessonSource,
    pattern: str,
    summary: str,
) -> ResearchLesson:
    location = _primary_location(hypothesis)
    file = location.file if location is not None else None
    metadata = {
        "asset": hypothesis.asset,
        "expected_guard": hypothesis.expected_guard,
        "observed_guard": hypothesis.observed_guard,
        "observed_guards": _observed_guards(hypothesis),
        "missing_guard": hypothesis.missing_guard,
        "source": hypothesis.source,
        "status": hypothesis.status.value,
    }
    if hypothesis.kill_reason:
        metadata["kill_reason"] = hypothesis.kill_reason
    return ResearchLesson(
        id=_lesson_id(
            lesson_type.value,
            hypothesis.hunter,
            hypothesis.vulnerability_class,
            file or "",
            _primary_symbol(hypothesis) or "",
            pattern,
        ),
        type=lesson_type,
        source=source,
        summary=summary,
        pattern=pattern,
        hunter=hypothesis.hunter,
        vulnerability_class=hypothesis.vulnerability_class,
        hypothesis_id=hypothesis.id,
        file=file,
        line=location.line if location is not None else None,
        symbol=location.symbol if location is not None else None,
        source_file_hashes=_source_hashes_for(hypothesis, current_file_hashes),
        metadata={key: value for key, value in metadata.items() if value is not None},
    )


def _primary_location(hypothesis: Hypothesis) -> FlowStep | None:
    if hypothesis.locations:
        return hypothesis.locations[0]
    if hypothesis.path:
        return hypothesis.path[0]
    return None


def _primary_symbol(hypothesis: Hypothesis) -> str | None:
    location = _primary_location(hypothesis)
    return location.symbol if location is not None else None


def _source_hashes_for(
    hypothesis: Hypothesis,
    current_file_hashes: dict[str, str],
) -> dict[str, str]:
    files = {
        step.file
        for step in (*hypothesis.locations, *hypothesis.path)
        if step.file in current_file_hashes
    }
    for entry in hypothesis.evidence:
        if entry.file in current_file_hashes:
            files.add(str(entry.file))
    return {file: current_file_hashes[file] for file in sorted(files)}


def _can_learn_false_positive_suppression(
    hypothesis: Hypothesis,
    current_file_hashes: dict[str, str],
) -> bool:
    location = _primary_location(hypothesis)
    return (
        location is not None
        and bool(location.symbol)
        and location.file in current_file_hashes
    )


def _has_scoped_false_positive_suppression(lesson: ResearchLesson) -> bool:
    return (
        lesson.type == ResearchLessonType.FALSE_POSITIVE_SUPPRESSION
        and bool(lesson.file)
        and bool(lesson.symbol)
        and bool(lesson.source_file_hashes.get(str(lesson.file)))
    )


def _lesson_hashes_match(
    lesson: ResearchLesson,
    current_file_hashes: dict[str, str],
) -> bool:
    if lesson.type == ResearchLessonType.FALSE_POSITIVE_SUPPRESSION:
        return (
            _has_scoped_false_positive_suppression(lesson)
            and current_file_hashes.get(str(lesson.file))
            == lesson.source_file_hashes[str(lesson.file)]
        )
    if not lesson.source_file_hashes:
        return True
    for file, expected_hash in lesson.source_file_hashes.items():
        if current_file_hashes.get(file) != expected_hash:
            return False
    return True


def _blocks_relearning(
    lesson: ResearchLesson,
    current_file_hashes: dict[str, str],
) -> bool:
    return (
        lesson.status == ResearchLessonStatus.ACTIVE
        and _lesson_hashes_match(lesson, current_file_hashes)
    )


def _observed_guards(hypothesis: Hypothesis) -> list[str]:
    if not hypothesis.observed_guard:
        return []
    return [
        guard.strip()
        for guard in hypothesis.observed_guard.split(",")
        if guard.strip()
    ]


def _lesson_id(*parts: str) -> str:
    normalized = "|".join(str(part or "").strip() for part in parts)
    digest = sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"lesson-{digest}"


def _append_lesson(path: Path, lesson: ResearchLesson) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = lesson.model_dump(mode="json")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def _read_lessons(path: Path) -> list[ResearchLesson]:
    if not path.exists():
        return []
    lessons: list[ResearchLesson] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}") from exc
            lessons.append(ResearchLesson.model_validate(payload))
    return lessons
