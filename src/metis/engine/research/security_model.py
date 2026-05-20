# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from pathlib import Path

from metis.engine.research.models import (
    PROJECT_SECURITY_MODEL_SCHEMA_VERSION,
    ProjectSecurityModel,
    ResearchLesson,
    SecurityGraph,
    SecurityGraphNode,
    SecurityModelEntry,
    SecurityTag,
)
from metis.engine.research.security_graph import SecurityGraphBuilder


class ProjectSecurityModelService:
    def __init__(
        self,
        repository,
        graph_builder: SecurityGraphBuilder | None = None,
    ) -> None:
        self._repository = repository
        self._graph_builder = graph_builder or SecurityGraphBuilder(repository)

    def load_or_build(
        self,
        root: str | Path | None = None,
        *,
        rebuild: bool = False,
        graph: SecurityGraph | None = None,
        lessons: tuple[ResearchLesson, ...] = (),
    ) -> ProjectSecurityModel:
        graph = graph or self._graph_builder.load_or_build(root, rebuild=rebuild)
        self._validate_graph_root(graph, root)
        model_path = Path(self._repository.get_security_model_path())
        if not rebuild and model_path.exists():
            try:
                model = ProjectSecurityModel.model_validate_json(
                    model_path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                model = None
            if (
                model is not None
                and model.schema_version == PROJECT_SECURITY_MODEL_SCHEMA_VERSION
                and model.analysis_root == graph.analysis_root
                and model.file_hashes == graph.file_hashes
            ):
                return self._with_lessons(model, lessons)
        return self.build(graph, lessons=lessons)

    def build(
        self,
        graph: SecurityGraph,
        *,
        lessons: tuple[ResearchLesson, ...] = (),
    ) -> ProjectSecurityModel:
        self._validate_graph_root(graph, None)
        entrypoints: list[SecurityModelEntry] = []
        trust_boundaries: list[SecurityModelEntry] = []
        assets: list[SecurityModelEntry] = []
        guards: list[SecurityModelEntry] = []
        sources: list[SecurityModelEntry] = []
        sinks: list[SecurityModelEntry] = []
        sanitizers: list[SecurityModelEntry] = []
        frameworks: list[SecurityModelEntry] = []

        for node in graph.nodes:
            node_tags = _tags_by_kind(node)
            entrypoint_tags = node_tags.get("entrypoint", [])
            guard_values = sorted({tag.value for tag in node_tags.get("guard", [])})
            if entrypoint_tags and node.type == "function":
                for tag in entrypoint_tags:
                    entrypoints.append(
                        _entry_from_tag(
                            node,
                            tag,
                            entry_type="route",
                            metadata={
                                "node_id": node.id,
                                "route_path": tag.value,
                                "route_group": node.metadata.get("route_group"),
                                "guards": guard_values,
                            },
                        )
                    )
                route_group = str(node.metadata.get("route_group") or "")
                if route_group:
                    assets.append(
                        SecurityModelEntry(
                            id=f"asset:{route_group}",
                            type="route_group",
                            name=route_group,
                            file=node.file,
                            line=node.line,
                            symbol=node.symbol,
                            tags=["route_group"],
                            metadata={"node_id": node.id},
                        )
                    )
            for tag in node_tags.get("source", []):
                entry = _entry_from_tag(node, tag, entry_type="source")
                sources.append(entry)
                trust_boundaries.append(
                    _entry_from_tag(
                        node,
                        tag,
                        entry_type="trust_boundary",
                        metadata={"node_id": node.id, "source": tag.value},
                    )
                )
            for tag in node_tags.get("sink", []):
                sinks.append(_entry_from_tag(node, tag, entry_type="sink"))
            for tag in node_tags.get("guard", []):
                guards.append(_entry_from_tag(node, tag, entry_type="guard"))
            for tag in node_tags.get("sanitizer", []):
                sanitizers.append(_entry_from_tag(node, tag, entry_type="sanitizer"))
            for tag in node_tags.get("framework", []):
                frameworks.append(_entry_from_tag(node, tag, entry_type="framework"))

        model = ProjectSecurityModel(
            analysis_root=graph.analysis_root,
            project_root_hash=graph.project_root_hash,
            file_hashes=dict(sorted(graph.file_hashes.items())),
            entrypoints=_dedupe_entries(entrypoints),
            trust_boundaries=_dedupe_entries(trust_boundaries),
            assets=_dedupe_entries(assets),
            guards=_dedupe_entries(guards),
            sources=_dedupe_entries(sources),
            sinks=_dedupe_entries(sinks),
            sanitizers=_dedupe_entries(sanitizers),
            frameworks=_dedupe_entries(frameworks),
            lessons=_lesson_entries(lessons),
        )
        self.write(model)
        return model

    def write(self, model: ProjectSecurityModel) -> None:
        model_path = Path(self._repository.get_security_model_path())
        model_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = model_path.with_suffix(model_path.suffix + ".tmp")
        tmp_path.write_text(
            json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp_path, model_path)

    def _validate_graph_root(
        self,
        graph: SecurityGraph,
        root: str | Path | None,
    ) -> None:
        candidate = graph.analysis_root or root or self._repository._config.codebase_path
        self._repository.resolve_inside_codebase(
            candidate,
            purpose="Security model graph root",
        )

    def _with_lessons(
        self,
        model: ProjectSecurityModel,
        lessons: tuple[ResearchLesson, ...],
    ) -> ProjectSecurityModel:
        lesson_entries = _lesson_entries(lessons)
        if model.lessons == lesson_entries:
            return model
        updated = model.model_copy(update={"lessons": lesson_entries})
        self.write(updated)
        return updated


def _tags_by_kind(node: SecurityGraphNode) -> dict[str, list[SecurityTag]]:
    tags: dict[str, list[SecurityTag]] = {}
    for tag in node.tags:
        tags.setdefault(tag.kind, []).append(tag)
    return tags


def _entry_from_tag(
    node: SecurityGraphNode,
    tag: SecurityTag,
    *,
    entry_type: str,
    metadata: dict | None = None,
) -> SecurityModelEntry:
    entry_metadata = {"node_id": node.id}
    entry_metadata.update(metadata or {})
    return SecurityModelEntry(
        id=f"{entry_type}:{node.id}:{tag.value}",
        type=entry_type,
        name=tag.value,
        file=tag.file or node.file,
        line=tag.line or node.line,
        symbol=tag.symbol or node.symbol,
        tags=[tag.kind],
        metadata=entry_metadata,
    )


def _dedupe_entries(entries: list[SecurityModelEntry]) -> list[SecurityModelEntry]:
    deduped: dict[str, SecurityModelEntry] = {}
    for entry in entries:
        deduped.setdefault(entry.id, entry)
    return [deduped[key] for key in sorted(deduped)]


def _lesson_entries(lessons: tuple[ResearchLesson, ...]) -> list[SecurityModelEntry]:
    entries: list[SecurityModelEntry] = []
    for lesson in lessons:
        entries.append(
            SecurityModelEntry(
                id=f"lesson:{lesson.id}",
                type=lesson.type.value,
                name=lesson.pattern,
                file=lesson.file,
                line=lesson.line,
                symbol=lesson.symbol,
                tags=["lesson", lesson.type.value],
                metadata={
                    "lesson_id": lesson.id,
                    "source": lesson.source.value,
                    "summary": lesson.summary,
                    "times_reused": lesson.times_reused,
                    **lesson.metadata,
                },
            )
        )
    return _dedupe_entries(entries)
