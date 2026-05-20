# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from metis.cli.exporters import export_sarif
from metis.engine.options import ReviewOptions, TriageOptions
from metis.engine.research import DEFAULT_RESEARCH_HUNTERS, ResearchOptions

from .artifacts import (
    TuiArtifactStore,
    find_latest_review_sarif,
    find_latest_triage_sarif,
)
from .chat_model import TuiChatModelAdapter
from .commands import TuiCommandRequest, parse_research_command_options
from .context import write_context_document
from .events import EventLevel, TuiEvent, utc_now_iso
from .sanitize import sanitize_text, sanitize_value
from .security_report import (
    AffectedFileSnippet,
    AttackChainCandidate,
    SecurityFinding,
    affected_file_snippet_to_dict,
    attack_chain_candidate_to_dict,
    build_attack_chain_candidates,
    build_cross_batch_attack_chain_candidates,
    extract_security_findings,
    format_affected_file_snippets,
    format_attack_chain_candidate,
    security_finding_to_dict,
)

EventCallback = Callable[[TuiEvent], None]


class TriageInputRequiredError(FileNotFoundError):
    """Raised when /triage needs an explicit SARIF path from the TUI."""


def _parse_runtime_hunters(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return DEFAULT_RESEARCH_HUNTERS
    if isinstance(raw, str):
        hunters = tuple(item.strip() for item in raw.split(",") if item.strip())
    else:
        hunters = tuple(str(item).strip() for item in raw if str(item).strip())
    return hunters or DEFAULT_RESEARCH_HUNTERS


def _bool_default(
    value: bool | None,
    runtime: dict[str, Any],
    key: str,
    *,
    default: bool,
) -> bool:
    if value is not None:
        return bool(value)
    return bool(runtime.get(key, default))


def _text_default(
    value: str | None,
    runtime: dict[str, Any],
    key: str,
    *,
    default: str,
) -> str:
    if value is not None:
        return str(value or default)
    return str(runtime.get(key, default) or default)


def _path_patterns_default(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,) if raw else ()
    return tuple(str(item) for item in raw if str(item))


class TuiDomainRunner:
    def __init__(
        self,
        engine,
        *,
        codebase_path: str | Path,
        run_id: str | None = None,
        artifacts_base_dir: str | Path = "results/tui",
        runtime_config: dict[str, Any] | None = None,
        event_callback: EventCallback | None = None,
    ):
        self.engine = engine
        self.runtime_config = dict(runtime_config or {})
        self.run_id = run_id or utc_now_iso().replace(":", "").replace(".", "-")
        self.artifacts = TuiArtifactStore(
            run_id=self.run_id,
            codebase_path=codebase_path,
            base_dir=artifacts_base_dir,
        )
        self._event_callback = event_callback
        self._sequence = 0
        self._command_number = 0
        self._current_log_path: Path | None = None
        self._emit("run.created", "run", "Run created")

    def execute(self, request: TuiCommandRequest) -> None:
        self._command_number += 1
        command_id = f"{self._command_number:03d}-{request.name}-{uuid4().hex[:8]}"
        log_path = self.artifacts.command_log_path(self._command_number, request.name)
        self._current_log_path = log_path
        self.artifacts.record_command(
            command_id=command_id,
            command_name=request.name,
            raw=request.raw or f"/{request.name}",
            log_path=log_path,
        )
        self._emit(
            "command.accepted",
            command_id,
            f"Accepted /{request.name}",
            payload={"args": list(request.args)},
        )
        usage_command = None
        try:
            with self._usage_command_context(request) as usage_command:
                self._emit("command.started", command_id, f"Started /{request.name}")
                if request.name == "index":
                    self._run_index(command_id)
                elif request.name == "review_code":
                    self._run_review_code(command_id, request)
                elif request.name == "review_file":
                    self._run_review_file(command_id, request)
                elif request.name == "review_patch":
                    self._run_review_patch(command_id, request)
                elif request.name == "research":
                    self._run_research(command_id, request)
                elif request.name == "triage":
                    self._run_triage(command_id, request)
                elif request.name == "security_report":
                    self._run_security_report(command_id, request)
                elif request.name == "init":
                    self._run_init(command_id)
                else:
                    raise ValueError(f"Unsupported domain command: {request.name}")
        except TriageInputRequiredError as exc:
            self.artifacts.finish_command(command_id, "failed")
            self._emit_usage_updated(command_id, usage_command)
            self._emit(
                "command.failed",
                command_id,
                str(exc),
                level="warning",
                payload={"error": str(exc), "input_required": True},
            )
            self._current_log_path = None
            raise
        except Exception as exc:
            self.artifacts.finish_command(command_id, "failed")
            self.artifacts.set_status("failed")
            self._emit_usage_updated(command_id, usage_command)
            self._emit(
                "command.failed",
                command_id,
                f"/{request.name} failed: {exc}",
                level="error",
                payload={"error": str(exc)},
            )
            self._emit(
                "run.failed",
                "run",
                f"Run failed during /{request.name}",
                level="error",
                payload={"error": str(exc), "command_id": command_id},
            )
            self._current_log_path = None
            raise
        self.artifacts.finish_command(command_id, "succeeded")
        self.artifacts.set_status("succeeded")
        self._emit_usage_updated(command_id, usage_command)
        self._emit("command.finished", command_id, f"Finished /{request.name}")
        self._current_log_path = None

    def _run_index(self, command_id: str) -> None:
        total = self.engine.indexing.count_index_items()
        self._emit(
            "index.scan.started",
            command_id,
            "Scanning indexable files",
            payload={"total_items": total},
        )

        prepared = 0

        def _progress(payload: dict[str, Any]) -> None:
            event_type = str(payload.get("event") or "index.item.discovered")
            message = str(payload.get("message") or "Index progress")
            self._emit(event_type, command_id, message, payload=payload)

        iterator = self.engine.indexing.index_prepare_nodes_iter(
            progress_callback=_progress
        )
        for _item in iterator:
            prepared += 1
            self._emit(
                "command.progress",
                command_id,
                "Preparing index nodes",
                payload={"completed": prepared, "total": total},
            )
        self._emit(
            "index.prepare.summary",
            command_id,
            "Index nodes prepared",
            payload={"completed": prepared, "total": total},
        )
        self._emit("index.embeddings.started", command_id, "Embedding indexes")
        self.engine.indexing.index_finalize_embeddings()
        self._emit("index.embeddings.finished", command_id, "Embedding complete")

    def _run_review_code(self, command_id: str, request: TuiCommandRequest) -> None:
        options = self._review_options(request)
        if options is not None and options.review_profile == "research":
            self._run_research(
                command_id,
                TuiCommandRequest("research", raw=request.raw or "/review_code"),
            )
            return
        files = list(self.engine.review.get_code_files(options=options))
        total = len(files)
        findings = 0

        def _progress(payload: dict[str, Any]) -> None:
            self._emit(
                str(payload.get("event") or "command.progress"),
                command_id,
                str(payload.get("message") or "Review progress"),
                payload=payload,
            )

        results = []
        reviews = self.engine.review.review_code(
            get_code_files_func=lambda: files,
            options=options,
            progress_callback=_progress,
        )
        for result in reviews:
            if result:
                results.append(result)
                finding_count = self._finding_count(result)
                findings += finding_count
                self._emit(
                    "review.result.recorded",
                    command_id,
                    f"Reviewed {result.get('file') or result.get('file_path') or 'file'}",
                    payload={"finding_count": finding_count},
                )
                for issue in result.get("reviews", []) or []:
                    self._emit(
                        "review.finding.emitted",
                        command_id,
                        str(issue.get("issue") or "Finding emitted"),
                        payload={"issue": issue},
                    )
            else:
                self._emit("review.result.skipped", command_id, "Review skipped a file")
        report = {"reviews": results}
        sarif_path, _payload = export_sarif(report, self.artifacts.paths.review_sarif)
        self.artifacts.set_latest_review_sarif_source("current-run")
        self._emit(
            "sarif.review.written",
            command_id,
            f"Review SARIF written to {sarif_path}",
            payload={"path": str(sarif_path), "files": total, "findings": findings},
        )

    def _run_review_file(self, command_id: str, request: TuiCommandRequest) -> None:
        path = self._required_path(request)
        options = self._review_options(request)
        self._emit(
            "review.file.started",
            command_id,
            f"Reviewing {path}",
            payload={"path": str(path)},
        )
        result = self.engine.review.review_file(str(path), options=options)
        report = {"reviews": [result] if result else []}
        sarif_path, _payload = export_sarif(report, self.artifacts.paths.review_sarif)
        self.artifacts.set_latest_review_sarif_source("current-run")
        self._emit(
            "sarif.review.written",
            command_id,
            f"Review SARIF written to {sarif_path}",
            payload={"path": str(sarif_path), "findings": self._finding_count(result)},
        )

    def _run_review_patch(self, command_id: str, request: TuiCommandRequest) -> None:
        path = self._required_path(request)
        options = self._review_options(request)
        result = self.engine.review.review_patch(str(path), options=options)
        sarif_path, _payload = export_sarif(result, self.artifacts.paths.review_sarif)
        self.artifacts.set_latest_review_sarif_source("current-run")
        self._emit(
            "sarif.review.written",
            command_id,
            f"Patch review SARIF written to {sarif_path}",
            payload={"path": str(sarif_path)},
        )

    def _run_research(self, command_id: str, request: TuiCommandRequest) -> None:
        options = self._research_options(request)
        self._emit(
            "research.started",
            command_id,
            "Running vulnerability research",
            payload={
                "hunters": list(options.hunters),
                "research_budget": options.research_budget,
                "emit_killed": options.emit_killed,
                "emit_unresolved": options.emit_unresolved,
                "proof_artifacts": options.proof_artifacts,
                "evidence_policy": options.evidence_policy,
            },
        )
        result = self.engine.research.run(
            self.artifacts.codebase_path,
            options=options,
        )
        self._emit(
            "research.hypotheses.verified",
            command_id,
            "Research hypotheses verified",
            payload={
                "generated": len(result.generated),
                "proven": len(result.proven),
                "killed": len(result.killed),
                "unresolved": len(result.unresolved),
            },
        )
        self._emit(
            "research.artifacts.written",
            command_id,
            f"Research report written to {self.artifacts.paths.research_report}",
            payload={
                "report": str(self.artifacts.paths.research_report),
                "sarif": str(self.artifacts.paths.research_sarif),
                "hypotheses": str(self.artifacts.paths.research_hypotheses),
                "evidence": str(self.artifacts.paths.research_evidence),
                "generated": len(result.generated),
                "proven": len(result.proven),
                "killed": len(result.killed),
                "unresolved": len(result.unresolved),
            },
        )
        self._run_security_report_from_sarif(
            command_id,
            self.artifacts.paths.research_sarif,
            source="research",
        )

    def _review_options(self, request: TuiCommandRequest) -> ReviewOptions | None:
        review_mode = _text_default(
            None,
            self.runtime_config,
            "review_mode",
            default="standard",
        )
        review_profile = _text_default(
            None,
            self.runtime_config,
            "review_profile",
            default="normal",
        )
        skip_test_files = _bool_default(
            None,
            self.runtime_config,
            "skip_test_files",
            default=False,
        )
        extra_patterns = _path_patterns_default(
            self.runtime_config.get("extra_test_path_patterns")
        )
        if (
            request.use_retrieval_context
            and review_mode == "standard"
            and review_profile == "normal"
            and not skip_test_files
            and not extra_patterns
        ):
            return None
        return ReviewOptions(
            use_retrieval_context=request.use_retrieval_context,
            review_mode=review_mode,
            review_profile=review_profile,
            skip_test_files=skip_test_files,
            extra_test_path_patterns=extra_patterns,
        )

    def _research_options(self, request: TuiCommandRequest) -> ResearchOptions:
        parsed = parse_research_command_options(request.args)
        return ResearchOptions(
            hunters=parsed.hunters
            or _parse_runtime_hunters(self.runtime_config.get("research_hunters")),
            persist=True,
            rebuild=_bool_default(
                parsed.rebuild,
                self.runtime_config,
                "research_rebuild",
                default=False,
            ),
            research_budget=_text_default(
                parsed.research_budget,
                self.runtime_config,
                "research_budget",
                default="standard",
            ),
            emit_killed=_bool_default(
                parsed.emit_killed,
                self.runtime_config,
                "research_emit_killed",
                default=False,
            ),
            emit_unresolved=_bool_default(
                parsed.emit_unresolved,
                self.runtime_config,
                "research_emit_unresolved",
                default=False,
            ),
            proof_artifacts=_bool_default(
                parsed.proof_artifacts,
                self.runtime_config,
                "research_proof_artifacts",
                default=False,
            ),
            evidence_policy=_text_default(
                parsed.evidence_policy,
                self.runtime_config,
                "research_evidence_policy",
                default="triage_evidence",
            ),
            hypotheses_path=str(self.artifacts.paths.research_hypotheses),
            evidence_ledger_path=str(self.artifacts.paths.research_evidence),
            sarif_path=str(self.artifacts.paths.research_sarif),
            research_report_path=str(self.artifacts.paths.research_report),
        )

    def _run_triage(self, command_id: str, request: TuiCommandRequest) -> None:
        sarif_path, source = self._resolve_triage_input(request)
        options = TriageOptions(use_retrieval_context=request.use_retrieval_context)

        def _progress(payload: dict[str, Any]) -> None:
            event = str(payload.get("event") or "progress")
            event_type = {
                "start": "triage.finding.started",
                "done": "triage.finding.finished",
                "error": "triage.finding.failed",
            }.get(event, "command.progress")
            self._emit(
                event_type,
                command_id,
                "Triage finding progress",
                payload=payload,
            )

        def _debug(message: str) -> None:
            self._emit(
                "log.message",
                command_id,
                str(message),
                payload={"source": "triage"},
            )

        def _checkpoint(payload: dict, processed: int, total: int) -> None:
            self._emit(
                "sarif.triage.checkpoint",
                command_id,
                "Triage checkpoint",
                payload={"processed": processed, "total": total},
            )

        output_path = self.engine.triage_sarif_file(
            str(sarif_path),
            str(self.artifacts.paths.triage_sarif),
            progress_callback=_progress,
            debug_callback=_debug,
            checkpoint_callback=_checkpoint,
            checkpoint_every=1,
            options=options,
        )
        self._emit(
            "sarif.triage.written",
            command_id,
            f"Triage SARIF written to {output_path}",
            payload={
                "input": str(sarif_path),
                "output": str(output_path),
                "source": source,
            },
        )

    def _run_init(self, command_id: str) -> None:
        self._emit("context.scan.started", command_id, "Scanning project context")
        path = write_context_document(self.artifacts.codebase_path)
        self._emit(
            "context.written",
            command_id,
            f"CONTEXT.md written to {path}",
            payload={"path": str(path)},
        )

    def _run_security_report(self, command_id: str, request: TuiCommandRequest) -> None:
        sarif_path, source = self._resolve_security_report_input(request)
        self._run_security_report_from_sarif(command_id, sarif_path, source=source)

    def _run_security_report_from_sarif(
        self, command_id: str, sarif_path: Path, *, source: str
    ) -> None:
        self._emit(
            "security_report.started",
            command_id,
            f"Reading SARIF from {sarif_path}",
            payload={"input": str(sarif_path), "source": source},
        )
        payload = self._read_sarif_payload(sarif_path)
        findings = extract_security_findings(payload)
        self.artifacts.paths.security_report_findings.write_text(
            json.dumps(
                [security_finding_to_dict(finding) for finding in findings],
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self._emit(
            "security_report.findings.extracted",
            command_id,
            f"Extracted {len(findings)} typed finding(s)",
            payload={
                "findings": len(findings),
                "path": str(self.artifacts.paths.security_report_findings),
            },
        )
        candidates = build_attack_chain_candidates(findings)
        cross_batch_candidates = build_cross_batch_attack_chain_candidates(candidates)
        self.artifacts.paths.security_report_candidates.write_text(
            json.dumps(
                [attack_chain_candidate_to_dict(candidate) for candidate in candidates],
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self.artifacts.paths.security_report_cross_batch_candidates.write_text(
            json.dumps(
                [
                    attack_chain_candidate_to_dict(candidate)
                    for candidate in cross_batch_candidates
                ],
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self._emit(
            "security_report.candidates.built",
            command_id,
            f"Built {len(candidates)} attack-chain candidate(s)",
            payload={
                "findings": len(findings),
                "candidates": len(candidates),
                "path": str(self.artifacts.paths.security_report_candidates),
            },
        )
        self._emit(
            "security_report.cross_batch.built",
            command_id,
            f"Built {len(cross_batch_candidates)} cross-batch chain candidate(s)",
            payload={
                "cross_batch_candidates": len(cross_batch_candidates),
                "path": str(
                    self.artifacts.paths.security_report_cross_batch_candidates
                ),
            },
        )
        batches = self._security_report_batches(candidates)
        self._emit(
            "security_report.batches.prepared",
            command_id,
            f"Prepared {len(batches)} model batch(es)",
            payload={
                "findings": len(findings),
                "candidates": len(candidates),
                "batches": len(batches),
            },
        )
        self._emit(
            "security_report.llm.started",
            command_id,
            "Extracting attack chains from SARIF findings",
            payload={
                "input": str(sarif_path),
                "findings": len(findings),
                "candidates": len(candidates),
                "batches": len(batches),
            },
        )
        chain_notes = self._extract_security_report_chains(
            command_id, findings, candidates, batches
        )
        cross_batch_notes = self._extract_cross_batch_security_report_chains(
            command_id, cross_batch_candidates
        )
        all_chain_notes = [*chain_notes, *cross_batch_notes]
        self.artifacts.paths.security_report_batch_notes.write_text(
            self._security_report_notes_context(all_chain_notes, limit=1_000_000)
            + "\n",
            encoding="utf-8",
        )
        report = self._invoke_security_report_final(
            all_chain_notes,
            len(findings),
            len(candidates) + len(cross_batch_candidates),
        ).strip()
        if not report:
            self._emit(
                "log.message",
                command_id,
                "Security report model returned an empty final response; writing fallback report from extracted chain notes.",
                level="warning",
                payload={"source": "security_report"},
            )
            report = self._fallback_security_report(
                sarif_path,
                findings,
                [*candidates, *cross_batch_candidates],
                all_chain_notes,
            )
        self._write_security_report_context(
            sarif_path=sarif_path,
            source=source,
            findings=findings,
            candidates=candidates,
            cross_batch_candidates=cross_batch_candidates,
            batches=batches,
            chain_notes=all_chain_notes,
        )
        self._emit(
            "security_report.artifacts.written",
            command_id,
            "Saved security report processing artifacts",
            payload={
                "findings_path": str(self.artifacts.paths.security_report_findings),
                "candidates_path": str(self.artifacts.paths.security_report_candidates),
                "cross_batch_candidates_path": str(
                    self.artifacts.paths.security_report_cross_batch_candidates
                ),
                "batch_notes_path": str(
                    self.artifacts.paths.security_report_batch_notes
                ),
                "context_path": str(self.artifacts.paths.security_report_context),
            },
        )
        self.artifacts.paths.security_report.write_text(report + "\n", encoding="utf-8")
        self._emit(
            "security_report.written",
            command_id,
            f"Security report written to {self.artifacts.paths.security_report}",
            payload={
                "input": str(sarif_path),
                "output": str(self.artifacts.paths.security_report),
                "source": source,
            },
        )

    def _resolve_security_report_input(
        self, request: TuiCommandRequest
    ) -> tuple[Path, str]:
        if request.args:
            path = Path(request.args[0])
            if not path.is_file():
                raise FileNotFoundError(path)
            return path, "explicit"
        current = self.artifacts.paths.triage_sarif
        if current.is_file():
            return current, "current-run"
        latest = find_latest_triage_sarif(self.artifacts.paths.run_dir.parent)
        if latest:
            return latest
        raise FileNotFoundError("No triage SARIF found for /security_report.")

    def _extract_security_report_chains(
        self,
        command_id: str,
        findings: list[SecurityFinding],
        candidates: list[AttackChainCandidate],
        batches: list[list[AttackChainCandidate]],
    ) -> list[str]:
        if not findings:
            return ["No SARIF results were present. No attack chains can be confirmed."]
        if not candidates:
            return [
                "No attack-chain candidates were generated from the SARIF findings. "
                "The final report should explain that no chains can be confirmed."
            ]
        chain_notes: list[str] = []
        total = len(batches)
        for index, batch in enumerate(batches, start=1):
            self._emit(
                "security_report.batch.started",
                command_id,
                f"Analyzing security report batch {index}/{total}",
                payload={
                    "batch": index,
                    "batches": total,
                    "candidates": len(batch),
                    "findings": sum(len(candidate.findings) for candidate in batch),
                },
            )
            snippets = self._affected_file_snippets_for_batch(batch)
            if snippets:
                self._emit(
                    "security_report.snippets.attached",
                    command_id,
                    f"Attached {len(snippets)} affected-file snippet(s)",
                    payload={
                        "batch": index,
                        "batches": total,
                        "snippets": len(snippets),
                    },
                )
            context = self._security_report_context(
                batch,
                snippets=snippets,
                limit=60_000,
            )
            note = self._invoke_security_report_batch(
                context,
                batch_index=index,
                batch_total=total,
            ).strip()
            if not note:
                self._emit(
                    "log.message",
                    command_id,
                    f"Security report batch {index}/{total} returned an empty response; using deterministic batch notes.",
                    level="warning",
                    payload={"source": "security_report", "batch": index},
                )
                note = self._fallback_security_chain_notes(batch, index, total)
            chain_notes.append(note)
            self._emit(
                "security_report.batch.finished",
                command_id,
                f"Finished security report batch {index}/{total}",
                payload={
                    "batch": index,
                    "batches": total,
                    "candidates": len(batch),
                    "findings": sum(len(candidate.findings) for candidate in batch),
                    "candidate_chars": len(note),
                },
            )
        self._emit(
            "security_report.synthesis.started",
            command_id,
            "Synthesizing final security report",
            payload={
                "chain_note_batches": len(chain_notes),
                "findings": len(findings),
                "candidates": len(candidates),
            },
        )
        return chain_notes

    def _extract_cross_batch_security_report_chains(
        self,
        command_id: str,
        cross_batch_candidates: list[AttackChainCandidate],
    ) -> list[str]:
        if not cross_batch_candidates:
            self._emit(
                "security_report.cross_batch.skipped",
                command_id,
                "No cross-batch chain candidates generated",
                payload={"cross_batch_candidates": 0},
            )
            return []
        self._emit(
            "security_report.cross_batch.started",
            command_id,
            "Analyzing cross-batch chain candidates",
            payload={"cross_batch_candidates": len(cross_batch_candidates)},
        )
        snippets = self._affected_file_snippets_for_batch(
            cross_batch_candidates,
            max_snippets=12,
        )
        context = self._security_report_context(
            cross_batch_candidates,
            snippets=snippets,
            limit=80_000,
        )
        note = self._invoke_security_report_cross_batch(
            context,
            candidate_count=len(cross_batch_candidates),
        ).strip()
        if not note:
            self._emit(
                "log.message",
                command_id,
                "Cross-batch security report analysis returned an empty response; using deterministic cross-batch notes.",
                level="warning",
                payload={"source": "security_report"},
            )
            note = self._fallback_cross_batch_chain_notes(cross_batch_candidates)
        self._emit(
            "security_report.cross_batch.finished",
            command_id,
            "Finished cross-batch chain analysis",
            payload={
                "cross_batch_candidates": len(cross_batch_candidates),
                "candidate_chars": len(note),
            },
        )
        return [note]

    def _invoke_security_report_batch(
        self, prompt_context: str, *, batch_index: int, batch_total: int
    ) -> str:
        return TuiChatModelAdapter(
            self.engine,
            timeout=3600,
            max_retries=1,
            max_tokens=65536,
        ).invoke(
            [
                (
                    "system",
                    "\n".join(
                        (
                            "You are Arm Metis, a senior application security reviewer.",
                            "This is a map step for a large security report.",
                            "Analyze only this batch of prebuilt attack-chain candidates.",
                            "The candidates were built from all SARIF findings using deterministic primitive, source, sink, trust-boundary, component, and score tags.",
                            "Validate, merge, downgrade, or reject candidate chains based only on the provided evidence.",
                            "For each retained chain, include a score from 0.0 to 10.0, severity, affected finding IDs or locations, impact, prerequisites, evidence, and evidence gaps.",
                            "Include only non-destructive PoC ideas for authorized local validation.",
                            "If a finding is standalone, keep it as a single-finding candidate unless the evidence clearly shows it is not attack-relevant.",
                            "Do not write the final report. Return concise Markdown chain notes for this batch.",
                            "Always return Markdown text. Do not return an empty response.",
                        )
                    ),
                ),
                (
                    "human",
                    f"Analyze attack-chain candidate batch {batch_index}/{batch_total}.\n\n"
                    + prompt_context,
                ),
            ]
        )

    def _invoke_security_report_cross_batch(
        self, prompt_context: str, *, candidate_count: int
    ) -> str:
        return TuiChatModelAdapter(
            self.engine,
            timeout=3600,
            max_retries=1,
            max_tokens=65536,
        ).invoke(
            [
                (
                    "system",
                    "\n".join(
                        (
                            "You are Arm Metis, a senior application security reviewer.",
                            "This is the cross-batch join step for a large security report.",
                            "Batching is not the discovery boundary. These XCHAIN candidates were generated globally by matching candidate postconditions to other candidate preconditions.",
                            "Analyze whether each cross-batch chain is a practical attack path, especially chains where one issue enables RCE through another issue from a different batch.",
                            "Keep retained chains concise but include score, severity, source candidate IDs, affected finding IDs, impact, prerequisites, evidence, and evidence gaps.",
                            "Include only non-destructive PoC ideas for authorized local validation.",
                            "Return Markdown cross-batch chain notes. Do not write the final report.",
                            "Always return Markdown text. Do not return an empty response.",
                        )
                    ),
                ),
                (
                    "human",
                    f"Analyze {candidate_count} cross-batch attack-chain candidate(s).\n\n"
                    + prompt_context,
                ),
            ]
        )

    def _invoke_security_report_final(
        self, chain_notes: list[str], finding_count: int, candidate_count: int
    ) -> str:
        notes_context = self._security_report_notes_context(chain_notes, limit=180_000)
        return TuiChatModelAdapter(
            self.engine,
            timeout=3600,
            max_retries=1,
            max_tokens=65536,
        ).invoke(
            [
                (
                    "system",
                    "\n".join(
                        (
                            "You are Arm Metis, a senior application security reviewer.",
                            "This is the reduce step for a large security report.",
                            "Write a public-release quality Markdown security report from batch-level and cross-batch attack-chain notes.",
                            "Merge duplicate or overlapping candidates across batches, but do not discard unique attack chains.",
                            "Treat XCHAIN notes as global bridge candidates that can combine findings from different LLM batches.",
                            "Write the report attack chain by attack chain.",
                            "Every attack chain must include a score from 0.0 to 10.0, severity, affected findings, impact, prerequisites, evidence, non-destructive PoC steps or pseudocode, evidence gaps, and remediation.",
                            "Rank chains by practical exploitability and impact.",
                            "Call out assumptions and evidence gaps instead of inventing facts.",
                            "End with prioritized remediation guidance.",
                            "Always return Markdown text. Do not return an empty response.",
                        )
                    ),
                ),
                (
                    "human",
                    f"Synthesize the final report from {finding_count} SARIF finding(s) and {candidate_count} prebuilt attack-chain candidate(s) using these batch notes.\n\n"
                    + notes_context,
                ),
            ]
        )

    def _read_sarif_payload(self, path: Path) -> dict[str, Any]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid SARIF JSON: {path}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"Invalid SARIF payload: {path}")
        return payload

    def _security_report_batches(
        self,
        candidates: list[AttackChainCandidate],
        *,
        max_candidates: int = 25,
        max_chars: int = 60_000,
    ) -> list[list[AttackChainCandidate]]:
        if not candidates:
            return []
        batches: list[list[AttackChainCandidate]] = []
        current: list[AttackChainCandidate] = []
        current_chars = 0
        for candidate in candidates:
            candidate_chars = len(format_attack_chain_candidate(candidate))
            would_exceed_candidates = len(current) >= max_candidates
            would_exceed_chars = current_chars + candidate_chars > max_chars
            if current and (would_exceed_candidates or would_exceed_chars):
                batches.append(current)
                current = []
                current_chars = 0
            current.append(candidate)
            current_chars += candidate_chars
        if current:
            batches.append(current)
        return batches

    def _security_report_context(
        self,
        candidates: list[AttackChainCandidate],
        *,
        snippets: list[AffectedFileSnippet] | None = None,
        limit: int,
    ) -> str:
        if not candidates:
            return "No attack-chain candidates were generated."
        joined = "\n\n".join(format_attack_chain_candidate(item) for item in candidates)
        snippet_text = format_affected_file_snippets(snippets or [])
        if snippet_text:
            joined = f"{joined}\n\n{snippet_text}"
        return joined[:limit]

    def _security_report_notes_context(
        self, chain_notes: list[str], *, limit: int
    ) -> str:
        if not chain_notes:
            return "No attack-chain notes were generated."
        joined = "\n\n---\n\n".join(
            f"## Batch Notes {index}\n\n{note}"
            for index, note in enumerate(chain_notes, start=1)
        )
        if len(joined) <= limit:
            return joined
        return joined[:limit] + "\n\n... batch notes truncated for final synthesis ..."

    def _fallback_security_chain_notes(
        self,
        candidates: list[AttackChainCandidate],
        batch_index: int,
        batch_total: int,
    ) -> str:
        lines = [
            f"## Batch {batch_index}/{batch_total} Deterministic Chain Notes",
            "",
            "The model returned no batch analysis, so these notes preserve the prebuilt attack-chain candidates for final synthesis.",
            "",
        ]
        for candidate in candidates:
            lines.extend(
                [
                    f"### {candidate.chain_id}: {candidate.title}",
                    "",
                    f"Score: {candidate.score_hint:.1f}/10.0",
                    "",
                    f"Relationship: {candidate.relation_reason}",
                    "",
                    "Affected findings: "
                    + ", ".join(finding.finding_id for finding in candidate.findings),
                    "",
                    "Evidence:",
                    "",
                    "```text",
                    format_attack_chain_candidate(candidate)[:4000],
                    "```",
                    "",
                ]
            )
        return "\n".join(lines)

    def _fallback_cross_batch_chain_notes(
        self, candidates: list[AttackChainCandidate]
    ) -> str:
        lines = [
            "## Deterministic Cross-Batch Chain Notes",
            "",
            "The model returned no cross-batch analysis, so these notes preserve deterministic global join candidates for final synthesis.",
            "",
        ]
        for candidate in candidates:
            lines.extend(
                [
                    f"### {candidate.chain_id}: {candidate.title}",
                    "",
                    f"Score: {candidate.score_hint:.1f}/10.0",
                    "",
                    "Source candidates: "
                    + ", ".join(candidate.source_candidate_ids or ("direct",)),
                    "",
                    f"Relationship: {candidate.relation_reason}",
                    "",
                    "Bridge hooks: " + (", ".join(candidate.bridge_hooks) or "none"),
                    "",
                    "Affected findings: "
                    + ", ".join(finding.finding_id for finding in candidate.findings),
                    "",
                    "Evidence:",
                    "",
                    "```text",
                    format_attack_chain_candidate(candidate)[:4000],
                    "```",
                    "",
                ]
            )
        return "\n".join(lines)

    def _fallback_security_report(
        self,
        sarif_path: Path,
        findings: list[SecurityFinding],
        candidates: list[AttackChainCandidate],
        chain_notes: list[str],
    ) -> str:
        lines = [
            "# Security Report",
            "",
            "## Generation Note",
            "",
            "The configured AI model returned an empty final response, so Metis wrote a deterministic fallback report from the extracted attack-chain notes and SARIF. Re-run `/security_report` after checking provider limits for a richer AI-generated narrative.",
            "",
            "## Executive Summary",
            "",
        ]
        if not findings:
            lines.extend(
                [
                    "No SARIF results were present, so no attack chains can be confirmed.",
                    "",
                    "## Attack Chains",
                    "",
                    "No confirmed attack chains.",
                ]
            )
            return "\n".join(lines)

        lines.extend(
            [
                f"Metis found {len(findings)} triaged SARIF finding(s) in `{sarif_path}`.",
                f"Metis built {len(candidates)} candidate attack chain(s) before final synthesis.",
                f"The fallback report preserves {len(chain_notes)} batch attack-chain note set(s) and assigns conservative chain scores for follow-up review.",
                "",
                "## Attack Chains",
                "",
            ]
        )
        for candidate in candidates[:25]:
            lines.extend(
                [
                    f"### {candidate.chain_id}: {candidate.title}",
                    "",
                    f"Score: {candidate.score_hint:.1f}/10.0",
                    "",
                    f"Attack families: {', '.join(candidate.attack_families)}",
                    "",
                    f"Relationship: {candidate.relation_reason}",
                    "",
                    "Evidence:",
                    "",
                    "```text",
                    format_attack_chain_candidate(candidate)[:4000],
                    "```",
                    "",
                    "Non-destructive PoC:",
                    "",
                    "1. Reproduce only in an authorized local test environment.",
                    "2. Navigate to the referenced file and line.",
                    "3. Trace whether attacker-controlled input can reach the vulnerable operation.",
                    "4. Confirm the expected impact without executing destructive payloads.",
                    "",
                    "Remediation priority: Review and fix based on reachability, exploitability, and exposed attack surface.",
                    "",
                ]
            )
        if len(candidates) > 25:
            lines.append(f"{len(candidates) - 25} additional candidate(s) omitted.")
        return "\n".join(lines)

    def _affected_file_snippets_for_batch(
        self,
        candidates: list[AttackChainCandidate],
        *,
        max_snippets: int = 8,
        window: int = 8,
    ) -> list[AffectedFileSnippet]:
        snippets: list[AffectedFileSnippet] = []
        seen: set[tuple[str, int, str]] = set()
        for candidate in candidates:
            for finding in candidate.findings:
                for location in finding.locations:
                    parsed = self._parse_location(location)
                    if parsed is None:
                        continue
                    relative_path, line_number = parsed
                    key = (relative_path, line_number, finding.finding_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    snippet = self._read_affected_file_snippet(
                        finding.finding_id,
                        relative_path,
                        line_number,
                        window=window,
                    )
                    if snippet is not None:
                        snippets.append(snippet)
                    if len(snippets) >= max_snippets:
                        return snippets
        return snippets

    def _parse_location(self, location: str) -> tuple[str, int] | None:
        raw = sanitize_text(location)
        if ":" not in raw:
            return None
        path_text, line_text = raw.rsplit(":", 1)
        try:
            line_number = int(line_text)
        except ValueError:
            return None
        if line_number <= 0 or not path_text:
            return None
        return path_text, line_number

    def _read_affected_file_snippet(
        self,
        finding_id: str,
        relative_path: str,
        line_number: int,
        *,
        window: int,
    ) -> AffectedFileSnippet | None:
        root = Path(self.artifacts.codebase_path).resolve()
        target = (root / relative_path).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            return None
        if not target.is_file():
            return None
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        start_line = max(1, line_number - window)
        end_line = min(len(lines), line_number + window)
        if start_line > end_line:
            return None
        numbered = [
            f"{number:>5}  {lines[number - 1]}"
            for number in range(start_line, end_line + 1)
        ]
        return AffectedFileSnippet(
            finding_id=finding_id,
            path=relative_path,
            start_line=start_line,
            end_line=end_line,
            text="\n".join(numbered)[:4000],
        )

    def _write_security_report_context(
        self,
        *,
        sarif_path: Path,
        source: str,
        findings: list[SecurityFinding],
        candidates: list[AttackChainCandidate],
        cross_batch_candidates: list[AttackChainCandidate],
        batches: list[list[AttackChainCandidate]],
        chain_notes: list[str],
    ) -> None:
        snippet_payload: list[dict[str, Any]] = []
        for batch in batches:
            snippet_payload.extend(
                affected_file_snippet_to_dict(snippet)
                for snippet in self._affected_file_snippets_for_batch(batch)
            )
        payload = {
            "schema_version": 1,
            "input": str(sarif_path),
            "source": source,
            "findings": len(findings),
            "candidates": len(candidates),
            "cross_batch_candidates": len(cross_batch_candidates),
            "batches": len(batches),
            "batch_note_count": len(chain_notes),
            "model_context_policy": (
                "compact candidate summaries plus bounded affected-file snippets; "
                "cross-batch candidates are generated globally from bridge metadata "
                "before final synthesis; full typed findings and candidates are stored as artifacts"
            ),
            "artifacts": {
                "findings": str(self.artifacts.paths.security_report_findings),
                "candidates": str(self.artifacts.paths.security_report_candidates),
                "cross_batch_candidates": str(
                    self.artifacts.paths.security_report_cross_batch_candidates
                ),
                "batch_notes": str(self.artifacts.paths.security_report_batch_notes),
                "context": str(self.artifacts.paths.security_report_context),
                "report": str(self.artifacts.paths.security_report),
            },
            "affected_file_snippets": snippet_payload,
        }
        self.artifacts.paths.security_report_context.write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )

    def _resolve_triage_input(self, request: TuiCommandRequest) -> tuple[Path, str]:
        if request.args:
            path = Path(request.args[0])
            if not path.is_file():
                raise FileNotFoundError(path)
            return path, "explicit"
        current = self.artifacts.paths.review_sarif
        if current.is_file():
            return current, "current-run"
        latest = find_latest_review_sarif(self.artifacts.paths.run_dir.parent)
        if latest:
            return latest
        raise TriageInputRequiredError("No review SARIF found for /triage.")

    def _required_path(self, request: TuiCommandRequest) -> Path:
        path = request.target_path
        if path is None:
            raise ValueError(f"/{request.name} requires a path.")
        if not path.exists():
            raise FileNotFoundError(path)
        return path

    def _finding_count(self, result: Any) -> int:
        if not isinstance(result, dict):
            return 0
        reviews = result.get("reviews")
        return len(reviews) if isinstance(reviews, list) else 0

    def _usage_command_context(self, request: TuiCommandRequest):
        usage_command = getattr(self.engine, "usage_command", None)
        if not callable(usage_command):
            return nullcontext(None)
        target = str(request.args[0]) if request.args else None
        return usage_command(
            request.name,
            target=target,
            display_name=f"/{request.name}",
        )

    def _emit_usage_updated(self, command_id: str, usage_command: Any) -> None:
        if usage_command is None:
            return
        finalize = getattr(self.engine, "finalize_usage_command", None)
        if not callable(finalize):
            return
        record = finalize(usage_command)
        self._emit(
            "usage.updated",
            command_id,
            "Token usage updated",
            payload={
                "summary": record.get("summary", {}),
                "cumulative": record.get("cumulative", {}),
            },
        )

    def _emit(
        self,
        event_type: str,
        command_id: str,
        message: str,
        *,
        level: EventLevel = "info",
        payload: dict[str, Any] | None = None,
    ) -> TuiEvent:
        self._sequence += 1
        event = TuiEvent(
            run_id=self.run_id,
            command_id=command_id,
            sequence=self._sequence,
            type=event_type,
            timestamp=utc_now_iso(),
            level=level,
            message=sanitize_text(message),
            payload=sanitize_value(payload or {}),
        )
        if self._current_log_path is not None:
            self.artifacts.append_event(self._current_log_path, event)
        if self._event_callback is not None:
            self._event_callback(event)
        return event
