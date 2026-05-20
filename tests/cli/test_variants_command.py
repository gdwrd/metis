# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

from metis.cli import commands
from metis.cli.command_runtime import CommandRuntime
from metis.engine.research import ResearchRunResult


def test_run_variants_invokes_research_service_with_fix_source(monkeypatch, tmp_path):
    captured = []
    patch_file = tmp_path / "patch.diff"
    patch_file.write_text("", encoding="utf-8")

    class _ResearchService:
        def run_variants(self, root, *, from_fix, from_sarif, from_report, options):
            captured.append(
                (
                    root,
                    from_fix,
                    from_sarif,
                    from_report,
                    options.persist,
                    options.emit_killed,
                    options.proof_artifacts,
                    options.evidence_policy,
                    options.sarif_path,
                )
            )
            return ResearchRunResult()

    engine = SimpleNamespace(
        codebase_path=str(tmp_path),
        research=_ResearchService(),
    )
    args = SimpleNamespace(quiet=True, output_file=None)
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)

    commands.run_variants(
        engine,
        [
            "--from-fix",
            str(patch_file),
            "--emit-killed",
            "--proof-artifacts",
            "--evidence-policy",
            "triage_evidence",
            "--sarif",
            str(tmp_path / "variants.sarif"),
        ],
        args,
        CommandRuntime(
            command="variants",
            command_args=[],
            use_retrieval_context=False,
        ),
    )

    assert captured == [
        (
            str(tmp_path),
            str(patch_file),
            None,
            None,
            True,
            True,
            True,
            "triage_evidence",
            str(tmp_path / "variants.sarif"),
        )
    ]


def test_run_variants_help_is_visible(monkeypatch):
    captured = []
    args = SimpleNamespace(quiet=False, output_file=None)
    monkeypatch.setattr(
        commands,
        "print_console",
        lambda message, *_args, **_kwargs: captured.append(str(message)),
    )

    commands.run_variants(
        SimpleNamespace(),
        ["--help"],
        args,
        CommandRuntime(
            command="variants",
            command_args=[],
            use_retrieval_context=False,
        ),
    )

    assert any("Metis variants" in message for message in captured)


def test_run_variants_rejects_missing_input(monkeypatch):
    captured = []

    class _ResearchService:
        def run_variants(self, *_args, **_kwargs):  # pragma: no cover - must not run
            raise AssertionError("missing input should stop before mining")

    engine = SimpleNamespace(
        codebase_path=".",
        research=_ResearchService(),
    )
    args = SimpleNamespace(quiet=True, output_file=None)
    monkeypatch.setattr(
        commands,
        "check_file_exists",
        lambda path, quiet=False: captured.append(f"File not found: {path}") or False,
    )

    commands.run_variants(
        engine,
        ["--from-fix", "missing.patch"],
        args,
        CommandRuntime(
            command="variants",
            command_args=[],
            use_retrieval_context=False,
        ),
    )

    assert any("File not found" in message for message in captured)
