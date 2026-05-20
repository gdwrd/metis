# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import json
import os
from pathlib import Path
import threading
import time
from typing import Any

from .hunters.registry import HunterRegistry
from .learning import ResearchLearningStore
from .models import (
    EvidenceLedgerEntry,
    EvidenceQuery,
    Hypothesis,
    HypothesisQuery,
    HypothesisStatus,
    ResearchLessonSource,
    ResearchRunRequest,
    ResearchRunResult,
    ResearchRunState,
    ResearchRunStatus,
    ResearchRunMode,
    utc_now,
)
from .options import ResearchOptions
from .proof import LocalProofGenerator
from .reporting import write_research_sarif
from .security_graph import SecurityGraphBuilder
from .security_model import ProjectSecurityModelService
from .store import ResearchJsonlStore
from .variants import PatchVariantMiner
from .verification import HypothesisVerifier


class ResearchService:
    def __init__(self, repository) -> None:
        self._repository = repository
        self.security_graph = SecurityGraphBuilder(repository)
        self.security_model = ProjectSecurityModelService(
            repository,
            self.security_graph,
        )
        self.hunters = HunterRegistry.default()
        self.variants = PatchVariantMiner()
        self.verifier = HypothesisVerifier()
        self.proofs = LocalProofGenerator(repository)
        self.learning = ResearchLearningStore(repository)
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._job_lock = threading.Lock()
        self._job_statuses: dict[str, ResearchRunStatus] = {}
        self._job_results: dict[str, ResearchRunResult] = {}
        self._job_futures: dict[str, Future] = {}

    def run_request(self, request: ResearchRunRequest) -> ResearchRunResult:
        request = request.model_copy(deep=True)
        options = request.to_options()
        root = request.root
        if request.mode == ResearchRunMode.VARIANTS:
            return self.run_variants(
                root,
                from_fix=request.from_fix,
                from_sarif=request.from_sarif,
                from_report=request.from_report,
                options=options,
            )
        return self.run(root, options=options)

    def start_request(self, request: ResearchRunRequest) -> ResearchRunStatus:
        request = request.model_copy(deep=True)
        status = ResearchRunStatus(request=request)
        with self._job_lock:
            self._job_statuses[status.job_id] = status.model_copy(deep=True)
        future = self._executor.submit(self._run_tracked_request, status.job_id, request)
        with self._job_lock:
            self._job_futures[status.job_id] = future
        return status.model_copy(deep=True)

    def get_run_status(self, job_id: str) -> ResearchRunStatus:
        with self._job_lock:
            try:
                return self._job_statuses[job_id].model_copy(deep=True)
            except KeyError as exc:
                raise KeyError(f"Unknown research job_id: {job_id}") from exc

    def get_run_result(self, job_id: str) -> ResearchRunResult | None:
        with self._job_lock:
            result = self._job_results.get(job_id)
            return result.model_copy(deep=True) if result is not None else None

    def query_hypotheses(
        self,
        result: ResearchRunResult,
        query: HypothesisQuery | None = None,
    ) -> list[Hypothesis]:
        hypothesis_query = query or HypothesisQuery()
        return hypothesis_query.filter(result.generated)

    def query_evidence(
        self,
        result: ResearchRunResult,
        query: EvidenceQuery | None = None,
    ) -> list[EvidenceLedgerEntry]:
        evidence_query = query or EvidenceQuery()
        return evidence_query.filter(result.evidence)

    def query_run_hypotheses(
        self,
        job_id: str,
        query: HypothesisQuery | None = None,
    ) -> list[Hypothesis] | None:
        self.get_run_status(job_id)
        result = self.get_run_result(job_id)
        if result is None:
            return None
        return self.query_hypotheses(result, query)

    def query_run_evidence(
        self,
        job_id: str,
        query: EvidenceQuery | None = None,
    ) -> list[EvidenceLedgerEntry] | None:
        self.get_run_status(job_id)
        result = self.get_run_result(job_id)
        if result is None:
            return None
        return self.query_evidence(result, query)

    def forget_request(self, job_id: str) -> bool:
        with self._job_lock:
            if job_id not in self._job_statuses:
                return False
            future = self._job_futures.get(job_id)
            if future is not None and not future.done():
                return False
            self._job_statuses.pop(job_id, None)
            self._job_results.pop(job_id, None)
            self._job_futures.pop(job_id, None)
            return True

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)

    def _run_tracked_request(
        self,
        job_id: str,
        request: ResearchRunRequest,
    ) -> ResearchRunResult:
        created_at = self.get_run_status(job_id).created_at
        started_at = utc_now()
        with self._job_lock:
            self._job_statuses[job_id] = ResearchRunStatus(
                job_id=job_id,
                state=ResearchRunState.RUNNING,
                request=request,
                created_at=created_at,
                started_at=started_at,
            )
        try:
            result = self.run_request(request)
        except Exception as exc:
            completed_at = utc_now()
            with self._job_lock:
                self._job_statuses[job_id] = ResearchRunStatus.failed(
                    job_id=job_id,
                    request=request,
                    created_at=created_at,
                    started_at=started_at,
                    completed_at=completed_at,
                    error=str(exc),
                )
            raise
        completed_at = utc_now()
        with self._job_lock:
            self._job_results[job_id] = result.model_copy(deep=True)
            self._job_statuses[job_id] = ResearchRunStatus.from_result(
                result,
                job_id=job_id,
                request=request,
                created_at=created_at,
                started_at=started_at,
                completed_at=completed_at,
            )
        return result

    def run(
        self,
        root: str | Path | None = None,
        *,
        options: ResearchOptions | None = None,
    ) -> ResearchRunResult:
        started = time.monotonic()
        research_options = options or ResearchOptions()
        root_path = self._repository.resolve_inside_codebase(
            root or self._repository._config.codebase_path,
            purpose="Research root",
        )
        graph = self.security_graph.load_or_build(
            root_path,
            rebuild=research_options.rebuild,
        )
        lesson_refresh = self.learning.refresh(
            graph.file_hashes,
            persist=research_options.persist,
        )
        active_lessons = tuple(lesson_refresh.active)
        model = self.security_model.load_or_build(
            root_path,
            rebuild=research_options.rebuild,
            graph=graph,
            lessons=active_lessons,
        )
        hypotheses: list[Hypothesis] = []
        proof_artifact_paths: list[str] = []
        lesson_refs: set[str] = set()
        selected_hunters = tuple(research_options.hunters)
        metric_summary: dict[str, Any] = {
            "available_hunters": self.hunters.available_names(),
            "selected_hunters": selected_hunters,
        }
        for hunter in self.hunters.select(selected_hunters):
            hunter_result = hunter.hunt(
                root_path,
                security_model=model,
                security_graph=graph,
                lessons=active_lessons,
            )
            hypotheses.extend(hunter_result.generated)
            proof_artifact_paths.extend(hunter_result.proof_artifact_paths)
            lesson_refs.update(_lesson_refs_from_result(hunter_result))
            metric_summary[hunter.name] = {
                "details": hunter_result.metric_summary,
                "generated": len(hunter_result.generated),
                "proven": len(hunter_result.proven),
                "killed": len(hunter_result.killed),
                "unresolved": len(hunter_result.unresolved),
            }
        hypotheses = self.verifier.verify_all(
            hypotheses,
            lessons=active_lessons,
            evidence_policy=research_options.evidence_policy,
            codebase_path=str(root_path),
        )

        hypotheses_path = (
            research_options.hypotheses_path
            or self._repository.get_research_hypotheses_path()
        )
        evidence_path = (
            research_options.evidence_ledger_path
            or self._repository.get_research_evidence_path()
        )
        sarif_path = (
            research_options.sarif_path or self._repository.get_research_sarif_path()
        )
        report_path = (
            research_options.research_report_path
            or self._repository.get_research_report_path()
        )
        metric_summary["verified"] = {
            "generated": len(hypotheses),
            "proven": sum(
                1 for item in hypotheses if item.status == HypothesisStatus.PROVEN
            ),
            "killed": sum(
                1 for item in hypotheses if item.status == HypothesisStatus.KILLED
            ),
            "unresolved": sum(
                1 for item in hypotheses if item.status == HypothesisStatus.UNRESOLVED
            ),
        }
        metric_summary["research_budget"] = research_options.research_budget
        metric_summary["evidence_policy"] = research_options.evidence_policy
        lesson_refs.update(_lesson_refs_from_hypotheses(hypotheses))
        reused_lessons = self.learning.record_reuse(
            lesson_refs,
            persist=research_options.persist,
        )
        learned_lessons = self.learning.learn_from_hypotheses(
            hypotheses,
            graph.file_hashes,
            persist=research_options.persist,
        )
        metric_summary["lessons"] = {
            "active": len(active_lessons),
            "invalidated": len(lesson_refresh.invalidated),
            "learned": len(learned_lessons),
            "reused": len(reused_lessons),
            "lesson_refs": sorted(lesson_refs),
        }
        if research_options.proof_artifacts:
            proof_result = self._generate_local_proofs(
                hypotheses,
                root_path=root_path,
                enabled=True,
            )
            hypotheses = proof_result.hypotheses
            proof_artifact_paths.extend(proof_result.artifact_paths)
            metric_summary["proof_artifacts"] = proof_result.metric_summary
        metric_summary["analysis_budget"] = {
            "research_budget": research_options.research_budget,
            "wallclock_seconds": time.monotonic() - started,
            "persist": research_options.persist,
            "proof_artifacts_requested": research_options.proof_artifacts,
        }
        result = ResearchRunResult.from_hypotheses(
            hypotheses,
            hypotheses_path=hypotheses_path if research_options.persist else None,
            evidence_ledger_path=evidence_path if research_options.persist else None,
            metric_summary=metric_summary,
        ).model_copy(
            update={
                "sarif_path": sarif_path if research_options.persist else None,
                "research_report_path": (
                    report_path if research_options.persist else None
                ),
                "proof_artifact_paths": proof_artifact_paths,
            }
        )
        if research_options.persist:
            store = ResearchJsonlStore(
                hypotheses_path=hypotheses_path,
                evidence_path=evidence_path,
            )
            store.append_hypotheses(result.generated)
            store.append_evidence_entries(result.evidence)
            write_research_sarif(
                result.generated,
                sarif_path,
                evidence_ledger_path=evidence_path,
                include_statuses=research_options.sarif_statuses(),
            )
            _write_research_report(result, report_path)
        return result

    def run_variants(
        self,
        root: str | Path | None = None,
        *,
        from_fix: str | Path | None = None,
        from_sarif: str | Path | None = None,
        from_report: str | Path | None = None,
        options: ResearchOptions | None = None,
    ) -> ResearchRunResult:
        started = time.monotonic()
        research_options = options or ResearchOptions()
        root_path = self._repository.resolve_inside_codebase(
            root or self._repository._config.codebase_path,
            purpose="Variant mining root",
        )
        graph = self.security_graph.load_or_build(
            root_path,
            rebuild=research_options.rebuild,
        )
        lesson_refresh = self.learning.refresh(
            graph.file_hashes,
            persist=research_options.persist,
        )
        mined = self.variants.mine(
            root_path,
            security_graph=graph,
            from_fix=from_fix,
            from_sarif=from_sarif,
            from_report=from_report,
        )
        active_lessons = tuple(lesson_refresh.active)
        hypotheses = self.verifier.verify_all(
            mined.hypotheses,
            lessons=active_lessons,
            evidence_policy=research_options.evidence_policy,
            codebase_path=str(root_path),
        )
        hypotheses_path = (
            research_options.hypotheses_path
            or self._repository.get_research_hypotheses_path()
        )
        evidence_path = (
            research_options.evidence_ledger_path
            or self._repository.get_research_evidence_path()
        )
        sarif_path = (
            research_options.sarif_path or self._repository.get_research_sarif_path()
        )
        report_path = (
            research_options.research_report_path
            or self._repository.get_research_report_path()
        )
        metric_summary = {
            "variant_patterns": [
                pattern.model_dump(mode="json") for pattern in mined.patterns
            ],
            "variant_sources": {
                "from_fix": str(from_fix) if from_fix is not None else None,
                "from_sarif": str(from_sarif) if from_sarif is not None else None,
                "from_report": str(from_report) if from_report is not None else None,
            },
            "verified": {
                "generated": len(hypotheses),
                "proven": sum(
                    1
                    for item in hypotheses
                    if item.status == HypothesisStatus.PROVEN
                ),
                "killed": sum(
                    1
                    for item in hypotheses
                    if item.status == HypothesisStatus.KILLED
                ),
                "unresolved": sum(
                    1
                    for item in hypotheses
                    if item.status == HypothesisStatus.UNRESOLVED
                ),
            },
            "research_budget": research_options.research_budget,
            "evidence_policy": research_options.evidence_policy,
        }
        lesson_refs = _lesson_refs_from_hypotheses(hypotheses)
        reused_lessons = self.learning.record_reuse(
            lesson_refs,
            persist=research_options.persist,
        )
        learned_lessons = self.learning.learn_from_hypotheses(
            hypotheses,
            graph.file_hashes,
            source=ResearchLessonSource.FIXED_VARIANT,
            persist=research_options.persist,
        )
        metric_summary["lessons"] = {
            "active": len(lesson_refresh.active),
            "invalidated": len(lesson_refresh.invalidated),
            "learned": len(learned_lessons),
            "reused": len(reused_lessons),
            "lesson_refs": sorted(lesson_refs),
        }
        proof_artifact_paths: list[str] = []
        if research_options.proof_artifacts:
            proof_result = self._generate_local_proofs(
                hypotheses,
                root_path=root_path,
                enabled=True,
            )
            hypotheses = proof_result.hypotheses
            proof_artifact_paths = proof_result.artifact_paths
            metric_summary["proof_artifacts"] = proof_result.metric_summary
        metric_summary["analysis_budget"] = {
            "research_budget": research_options.research_budget,
            "wallclock_seconds": time.monotonic() - started,
            "persist": research_options.persist,
            "proof_artifacts_requested": research_options.proof_artifacts,
        }
        result = ResearchRunResult.from_hypotheses(
            hypotheses,
            hypotheses_path=hypotheses_path if research_options.persist else None,
            evidence_ledger_path=evidence_path if research_options.persist else None,
            metric_summary=metric_summary,
        ).model_copy(
            update={
                "sarif_path": sarif_path if research_options.persist else None,
                "research_report_path": (
                    report_path if research_options.persist else None
                ),
                "proof_artifact_paths": proof_artifact_paths,
            }
        )
        if research_options.persist:
            store = ResearchJsonlStore(
                hypotheses_path=hypotheses_path,
                evidence_path=evidence_path,
            )
            store.append_hypotheses(result.generated)
            store.append_evidence_entries(result.evidence)
            write_research_sarif(
                result.generated,
                sarif_path,
                evidence_ledger_path=evidence_path,
                include_statuses=research_options.sarif_statuses(),
            )
            _write_research_report(result, report_path)
        return result

    def _generate_local_proofs(
        self,
        hypotheses: list[Hypothesis],
        *,
        root_path: Path,
        enabled: bool,
    ):
        if enabled:
            return self.proofs.generate_for_hypotheses(
                hypotheses,
                root=root_path,
                proofs_dir=self._repository.get_research_proofs_dir(),
            )
        return _disabled_proof_result(hypotheses)


def _write_research_report(
    result: ResearchRunResult,
    path: str | os.PathLike[str],
) -> str:
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = report_path.with_suffix(report_path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_path, report_path)
    return str(report_path)


def _lesson_refs_from_result(result: ResearchRunResult) -> set[str]:
    refs = _lesson_refs_from_hypotheses(result.generated)
    metric_refs = result.metric_summary.get("lesson_refs")
    if isinstance(metric_refs, list | tuple | set):
        refs.update(str(ref) for ref in metric_refs if ref)
    return refs


def _lesson_refs_from_hypotheses(hypotheses: list[Hypothesis]) -> set[str]:
    return {
        str(ref)
        for hypothesis in hypotheses
        for ref in hypothesis.lesson_refs
        if ref
    }


def _disabled_proof_result(hypotheses: list[Hypothesis]):
    from .proof import LocalProofRunResult, ProofDecision

    return LocalProofRunResult(
        hypotheses=hypotheses,
        decisions=[
            ProofDecision(
                hypothesis_id=hypothesis.id,
                status="skipped",
                reason="proof artifact persistence is disabled",
            )
            for hypothesis in hypotheses
        ],
    )
