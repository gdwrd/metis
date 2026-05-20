# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import shutil

from metis.engine.research import (
    EvidenceStatus,
    HypothesisStatus,
    ProjectSecurityModel,
    ResearchLearningStore,
    ResearchLesson,
    ResearchLessonSource,
    ResearchLessonStatus,
    ResearchLessonType,
    ResearchOptions,
    SecurityModelEntry,
)
from metis.engine.research.verification import HypothesisVerifier
from metis.engine.research.hunters.authz_outlier import AuthzOutlierHunter


FIXTURE = "tests/fixtures/research/authz_outlier_app"


def test_learning_store_learns_and_invalidates_source_hashes(tmp_path):
    store = ResearchLearningStore(tmp_path / "lessons.jsonl")
    result = AuthzOutlierHunter().hunt(FIXTURE)

    learned = store.learn_from_hypotheses(result.generated, {"app.py": "old-hash"})

    learned_types = {lesson.type for lesson in learned}
    assert ResearchLessonType.FALSE_POSITIVE_SUPPRESSION in learned_types
    assert ResearchLessonType.GUARD_PATTERN in learned_types
    assert ResearchLessonType.SOURCE_PATTERN in learned_types
    assert ResearchLessonType.PROJECT_SPECIFIC_ASSET_RULE in learned_types
    assert store.refresh({"app.py": "old-hash"}).active

    refresh = store.refresh({"app.py": "new-hash"})

    assert refresh.active == []
    assert refresh.invalidated
    assert {lesson.status for lesson in refresh.invalidated} == {
        ResearchLessonStatus.INVALIDATED
    }
    assert all(lesson.invalidation_reason for lesson in refresh.invalidated)


def test_learning_store_relearns_after_hash_invalidation(tmp_path):
    store = ResearchLearningStore(tmp_path / "lessons.jsonl")
    result = AuthzOutlierHunter().hunt(FIXTURE)

    first = store.learn_from_hypotheses(result.generated, {"app.py": "old-hash"})
    store.refresh({"app.py": "new-hash"})
    second = store.learn_from_hypotheses(result.generated, {"app.py": "new-hash"})

    assert first
    assert second
    assert {lesson.id for lesson in second} == {lesson.id for lesson in first}
    latest = store.read_latest()
    assert {lesson.status for lesson in latest} == {ResearchLessonStatus.ACTIVE}
    assert all(
        lesson.source_file_hashes.get("app.py") == "new-hash" for lesson in latest
    )


def test_learning_store_turns_user_false_positive_feedback_into_suppression(tmp_path):
    store = ResearchLearningStore(tmp_path / "lessons.jsonl")
    proven = AuthzOutlierHunter().hunt(FIXTURE).proven[0]

    learned = store.learn_from_user_feedback(
        proven,
        {"app.py": "hash"},
        confirmed_true_positive=False,
    )

    assert [lesson.type for lesson in learned] == [
        ResearchLessonType.FALSE_POSITIVE_SUPPRESSION
    ]
    assert learned[0].metadata["kill_reason"] == "User confirmed false positive"


def test_learning_store_requires_scoped_hash_for_false_positive_suppression(tmp_path):
    store = ResearchLearningStore(tmp_path / "lessons.jsonl")
    killed = AuthzOutlierHunter().hunt(FIXTURE).killed[0]
    locationless = killed.model_copy(update={"locations": [], "path": []})

    assert store.learn_from_hypotheses([locationless], {"app.py": "hash"}) == []
    assert store.learn_from_hypotheses([killed], {"other.py": "hash"}) == []

    learned = store.learn_from_hypotheses([killed], {"app.py": "hash"})

    assert [lesson.type for lesson in learned] == [
        ResearchLessonType.FALSE_POSITIVE_SUPPRESSION
    ]
    assert learned[0].file == "app.py"
    assert learned[0].symbol == "get_project"
    assert learned[0].source_file_hashes["app.py"] == "hash"


def test_learning_store_invalidates_legacy_or_stale_suppression_lessons(tmp_path):
    lessons_path = tmp_path / "lessons.jsonl"
    lessons = [
        _suppression_lesson(
            "lesson-unscoped",
            file=None,
            symbol=None,
            source_file_hashes={},
        ),
        _suppression_lesson(
            "lesson-hashless",
            file="app.py",
            symbol="get_project",
            source_file_hashes={},
        ),
        _suppression_lesson(
            "lesson-stale",
            file="app.py",
            symbol="get_project",
            source_file_hashes={"app.py": "old-hash"},
        ),
        _suppression_lesson(
            "lesson-valid",
            file="app.py",
            symbol="get_project",
            source_file_hashes={"app.py": "current-hash"},
        ),
    ]
    lessons_path.write_text(
        "\n".join(json.dumps(lesson.model_dump(mode="json")) for lesson in lessons)
        + "\n",
        encoding="utf-8",
    )
    store = ResearchLearningStore(lessons_path)

    refresh = store.refresh({"app.py": "current-hash"}, persist=False)

    assert {lesson.id for lesson in refresh.active} == {"lesson-valid"}
    assert {lesson.id for lesson in refresh.invalidated} == {
        "lesson-unscoped",
        "lesson-hashless",
        "lesson-stale",
    }


def test_authz_ignores_legacy_unscoped_suppression_lessons():
    store = ResearchLearningStore("unused.jsonl")
    killed = AuthzOutlierHunter().hunt(FIXTURE).killed[0]
    suppression = store.learn_from_hypotheses(
        [killed],
        {"app.py": "hash"},
        persist=False,
    )[0]
    legacy_unscoped = suppression.model_copy(
        update={"file": None, "symbol": None, "source_file_hashes": {}}
    )

    repeat = AuthzOutlierHunter().hunt(FIXTURE, lessons=(legacy_unscoped,))
    verified = HypothesisVerifier().verify_all(
        repeat.generated,
        lessons=(legacy_unscoped,),
    )

    assert repeat.metric_summary["suppressed_by_lesson"] == 0
    assert any(item.locations[0].symbol == "get_project" for item in repeat.generated)
    get_project = next(
        item for item in verified if item.locations[0].symbol == "get_project"
    )
    assert get_project.kill_reason != (
        f"Candidate suppressed by lesson {legacy_unscoped.id}"
    )
    assert all(entry.obligation != "lesson_suppression" for entry in get_project.evidence)


def test_authz_lesson_suppression_matches_structured_multi_guard_metadata():
    store = ResearchLearningStore("unused.jsonl")
    result = AuthzOutlierHunter().hunt(FIXTURE)
    killed = result.killed[0].model_copy(
        update={"observed_guard": "require_project_member, check_owner"}
    )
    learned = store.learn_from_hypotheses(
        [killed],
        {"app.py": "hash"},
        persist=False,
    )
    suppression = learned[0]
    model = ProjectSecurityModel(
        project_root_hash="hash",
        entrypoints=[
            SecurityModelEntry(
                id="route:get_project",
                type="route",
                name="/projects/<project_id>",
                file="app.py",
                line=18,
                symbol="get_project",
                metadata={
                    "route_path": "/projects/<project_id>",
                    "route_group": "projects",
                    "guards": ["require_project_member", "check_owner"],
                },
            ),
            SecurityModelEntry(
                id="route:update_project_settings",
                type="route",
                name="/projects/<project_id>/settings",
                file="app.py",
                line=23,
                symbol="update_project_settings",
                metadata={
                    "route_path": "/projects/<project_id>/settings",
                    "route_group": "projects",
                    "guards": [],
                },
            ),
        ],
    )

    repeat = AuthzOutlierHunter(
        guard_keywords=("require_", "check_"),
    ).hunt(
        FIXTURE,
        security_model=model,
        lessons=(suppression,),
    )
    missing_check = suppression.model_copy(
        update={
            "metadata": {
                **suppression.metadata,
                "observed_guards": ["require_project_member", "missing_guard"],
            }
        }
    )
    unsuppressed = AuthzOutlierHunter(
        guard_keywords=("require_", "check_"),
    ).hunt(
        FIXTURE,
        security_model=model,
        lessons=(missing_check,),
    )

    assert repeat.metric_summary["suppressed_by_lesson"] == 1
    assert all(item.locations[0].symbol != "get_project" for item in repeat.generated)
    assert any(
        item.locations[0].symbol == "get_project" for item in unsuppressed.generated
    )
    verified = HypothesisVerifier().verify_all(
        unsuppressed.generated,
        lessons=(missing_check,),
    )
    get_project = next(
        item for item in verified if item.locations[0].symbol == "get_project"
    )
    assert get_project.kill_reason != (
        f"Candidate suppressed by lesson {missing_check.id}"
    )
    assert all(
        entry.obligation != "lesson_suppression"
        or entry.status != EvidenceStatus.FAILED
        for entry in get_project.evidence
    )


def test_research_service_reuses_authz_lessons_and_reports_metrics(engine, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    engine.codebase_path = str(tmp_path)
    engine._config.codebase_path = str(tmp_path)

    first = engine.research.run(
        repo,
        options=ResearchOptions(persist=True, rebuild=True),
    )
    second = engine.research.run(
        repo,
        options=ResearchOptions(persist=True),
    )

    assert [item.status for item in first.generated].count(HypothesisStatus.KILLED) == 1
    assert first.metric_summary["lessons"]["learned"] >= 4
    assert first.metric_summary["lessons"]["reused"] == 0
    assert second.metric_summary["lessons"]["active"] >= 4
    assert second.metric_summary["lessons"]["reused"] >= 2
    assert second.metric_summary["authz_outlier"]["details"][
        "suppressed_by_lesson"
    ] == 1
    assert all(
        item.locations[0].symbol != "get_project" for item in second.generated
    )

    proven = second.proven[0]
    assert proven.locations[0].symbol == "update_project_settings"
    assert proven.lesson_refs

    security_model = json.loads((tmp_path / ".metis/security_model.json").read_text())
    assert security_model["lessons"]

    latest_lessons = engine.research.learning.read_latest()
    assert any(lesson.times_reused > 0 for lesson in latest_lessons)


def _suppression_lesson(
    lesson_id: str,
    *,
    file: str | None,
    symbol: str | None,
    source_file_hashes: dict[str, str],
) -> ResearchLesson:
    return ResearchLesson(
        id=lesson_id,
        type=ResearchLessonType.FALSE_POSITIVE_SUPPRESSION,
        source=ResearchLessonSource.KILLED_HYPOTHESIS,
        summary="Suppress repeat candidate.",
        pattern="authz_outlier|/projects/<project_id>|get_project",
        hunter="authz_outlier",
        vulnerability_class="CWE-862",
        file=file,
        line=18 if file else None,
        symbol=symbol,
        source_file_hashes=source_file_hashes,
        metadata={
            "source": "/projects/<project_id>",
            "observed_guards": ["require_project_member"],
        },
    )
