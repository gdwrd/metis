# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import asyncio

from textual.widgets import Input, OptionList, Static

from metis.tui.chat import ChatUpdate, TuiChatSession
from metis.tui.chat_model import TuiChatModelAdapter
from metis.tui.bootstrap import TuiStartupState
from metis.tui.events import TuiEvent
from metis.tui.app import ChatEvent, MetisActivity, MetisTuiApp, RunnerEvent
from metis.tui.theme import metis_logo


class _Runner:
    def __init__(self):
        self.commands = []
        self._event_callback = None
        self.run_id = "app-test"
        self.sequence = 0

    def execute(self, command):
        self.commands.append(command.name)

    def _emit(self, event_type, command_id, message, *, level="info", payload=None):
        self.sequence += 1
        event = TuiEvent(
            run_id=self.run_id,
            command_id=command_id,
            sequence=self.sequence,
            type=event_type,
            timestamp="2026-05-12T00:00:00Z",
            level=level,
            message=message,
            payload=payload or {},
        )
        if self._event_callback is not None:
            self._event_callback(event)
        return event


class _FakeModel:
    def invoke(self, messages):
        self.messages = messages
        return type("Message", (), {"content": "ready"})()

    def stream(self, messages):
        self.messages = messages
        yield type("Chunk", (), {"content": "hello "})()
        yield type("Chunk", (), {"content": "from model"})()


class _FakeAdapter(TuiChatModelAdapter):
    def __init__(self, model):
        self.model = model

    def build_model(self):
        return self.model


class _Engine:
    def __init__(self):
        self.llm_provider = _Provider()


class _Provider:
    query_model = "gpt-test"

    def __init__(self):
        self.model = _FakeModel()

    def get_chat_model(self, **_kwargs):
        return self.model

    def get_embed_model_code(self, **_kwargs):
        return object()

    def get_embed_model_docs(self, **_kwargs):
        return object()


def test_tui_app_smoke_accepts_help_command():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=40)
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("/", "h", "e", "l", "p", "enter")
            assert any("/review_code" in line for line in app.chat_transcript)

    asyncio.run(_run())


def test_tui_app_input_accepts_normal_typing_before_submit():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=80)
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("h", "e", "l", "l", "o")
            await pilot.pause()

            input_widget = app.query_one("#input", Input)
            assert input_widget.has_focus
            assert input_widget.value == "hello"

    asyncio.run(_run())


def test_tui_app_shows_slash_command_completion_popup():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=80)
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("/", "r", "e", "v", "i", "e", "w", "_", "f")
            await pilot.pause()

            completions = app.query_one("#command-completions", OptionList)
            assert completions.display is True
            assert completions.option_count == 1
            assert "review_file" in str(completions.get_option_at_index(0).prompt)

    asyncio.run(_run())


def test_tui_app_accepts_slash_command_completion_without_submitting():
    async def _run():
        runner = _Runner()
        app = MetisTuiApp(runner, width_hint=80)
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("/", "r", "e", "v", "i", "e", "w", "_", "f", "tab")
            await pilot.pause()

            input_widget = app.query_one("#input", Input)
            completions = app.query_one("#command-completions", OptionList)
            assert input_widget.value == "/review_file "
            assert completions.display is False
            assert runner.commands == []

    asyncio.run(_run())


def test_tui_app_accepts_clicked_slash_command_completion():
    async def _run():
        runner = _Runner()
        app = MetisTuiApp(runner, width_hint=80)
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("/", "r", "e", "v", "i", "e", "w", "_", "f")
            await pilot.pause()

            completions = app.query_one("#command-completions", OptionList)
            assert completions.display is True

            completions.action_select()
            await pilot.pause()

            assert app.query_one("#input", Input).value == "/review_file "
            assert completions.display is False
            assert runner.commands == []

    asyncio.run(_run())


def test_tui_app_enter_accepts_completion_before_command_submit():
    async def _run():
        runner = _Runner()
        app = MetisTuiApp(runner, width_hint=80)
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("/", "h", "enter")
            await pilot.pause()

            assert app.query_one("#input", Input).value == "/help"
            assert runner.commands == []

            await pilot.press("enter")
            await pilot.pause()
            assert any("/review_code" in line for line in app.chat_transcript)

    asyncio.run(_run())


def test_metis_logo_uses_large_arm_ascii_at_normal_width():
    logo = metis_logo(120)

    assert "____" in logo
    assert "METIS" in logo
    assert len(logo.splitlines()) >= 5
    assert "[bold" not in logo
    assert "[/bold" not in logo


def test_tui_app_updates_logo_from_runtime_width():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=120)
        async with app.run_test(size=(60, 24)) as pilot:
            await pilot.pause()
            logo_text = str(app.query_one("#top", Static).render())
            assert "METIS" in logo_text
            assert "ARM METIS" in logo_text

    asyncio.run(_run())


def test_tui_app_uses_modern_textual_layout():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=100)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.query_one("#hero") is not None
            assert app.query_one("#activity", MetisActivity) is not None
            assert app.query_one("#workspace") is not None
            assert app.query_one("#bottom-panel") is not None
            assert app.query_one("#connection-status") is not None
            assert app.query_one("#shortcuts") is not None
            assert app.query_one("#activity", MetisActivity).parent.id == "bottom-panel"
            assert app.query_one("#status").parent.id == "bottom-panel"
            assert app.query_one("#input").parent.id == "bottom-panel"

    asyncio.run(_run())


def test_tui_theme_uses_transparent_backgrounds():
    from metis.tui.theme import METIS_CSS

    assert "background: ansi_default;" in METIS_CSS
    assert "background: transparent;" in METIS_CSS
    assert "background: #000000;" not in METIS_CSS
    assert "background: #050505;" not in METIS_CSS
    assert "background: #030303;" not in METIS_CSS


def test_tui_app_uses_native_terminal_background_colors():
    app = MetisTuiApp(_Runner(), width_hint=80)

    assert app.native_ansi_color is True


def test_tui_app_hides_endpoint_until_status_command():
    async def _run():
        endpoint = "https://openai-api-proxy.geo.arm.com/api/providers/openai/v1"
        app = MetisTuiApp(
            _Runner(),
            width_hint=100,
            startup_state=TuiStartupState(
                stage="ready",
                chat_enabled=True,
                message="ready",
                provider_name="openai",
                model="gpt-5.5",
                base_url=endpoint,
                provider_ready=True,
                provider_status="ready",
            ),
        )
        async with app.run_test() as pilot:
            await pilot.pause()
            assert endpoint not in str(app.query_one("#startup", Static).render())
            assert endpoint not in str(
                app.query_one("#connection-status", Static).render()
            )

            await pilot.click("#input")
            await pilot.press("/", "s", "t", "a", "t", "u", "s", "enter")
            await pilot.pause()

            transcript = "\n".join(app.chat_transcript)
            assert "Endpoint: " + endpoint in transcript
            assert "Tools: project_tree" in transcript

    asyncio.run(_run())


def test_tui_app_normal_input_uses_chat_model_not_planner():
    async def _run():
        runner = _Runner()
        model = _FakeModel()
        chat = TuiChatSession(
            object(),
            codebase_path=".",
            adapter=_FakeAdapter(model),
        )
        app = MetisTuiApp(
            runner,
            width_hint=80,
            chat_session=chat,
            startup_state=TuiStartupState(
                stage="ready",
                chat_enabled=True,
                message="ready",
                provider_ready=True,
            ),
        )
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press(
                "a",
                "n",
                "a",
                "l",
                "y",
                "z",
                "e",
                " ",
                "v",
                "u",
                "l",
                "n",
                "s",
                "enter",
            )
            await pilot.pause(0.2)
            assert runner.commands == []
            assert any(
                "Metis\nhello from model" in line for line in app.chat_transcript
            )
            assert app.chat_transcript.count("Metis\nhello from model") == 1
            assert app.query_one("#activity", MetisActivity).active is False

    asyncio.run(_run())


def test_tui_app_keeps_compact_header_after_input_resize():
    async def _run():
        chat = TuiChatSession(
            object(),
            codebase_path=".",
            adapter=_FakeAdapter(_FakeModel()),
        )
        app = MetisTuiApp(
            _Runner(),
            width_hint=120,
            chat_session=chat,
            startup_state=TuiStartupState(
                stage="ready",
                chat_enabled=True,
                message="ready",
                provider_ready=True,
            ),
        )
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.click("#input")
            await pilot.press("h", "i", "enter")
            await pilot.pause(0.2)
            await pilot.resize_terminal(60, 24)
            await pilot.pause()
            header = str(app.query_one("#top", Static).render())
            assert header.startswith("ARM METIS")
            assert "chat | chat" not in header.lower()
            assert "metis" in header.lower()

    asyncio.run(_run())


def test_tui_app_resolves_dot_project_label_and_hides_idle_activity():
    async def _run():
        app = MetisTuiApp(
            _Runner(),
            width_hint=80,
            startup_state=TuiStartupState(
                stage="ready",
                chat_enabled=True,
                message="ready",
                provider_name="openai",
                model="gpt-5.5",
                provider_ready=True,
                provider_status="ready",
            ),
        )
        async with app.run_test() as pilot:
            await pilot.pause()
            status = str(app.query_one("#status").render())
            assert "cwd: ." not in status
            assert "openai gpt-5.5" in status
            assert app.query_one("#activity", MetisActivity).display is False

    asyncio.run(_run())


def test_tui_app_shows_live_session_token_totals():
    class _UsageEngine:
        llm_provider = None

        def usage_totals(self):
            return {
                "input_tokens": 120_000,
                "output_tokens": 2_800_000,
                "total_tokens": 2_920_000,
            }

    class _UsageRunner(_Runner):
        def __init__(self):
            super().__init__()
            self.engine = _UsageEngine()

    async def _run():
        app = MetisTuiApp(_UsageRunner(), width_hint=80)
        async with app.run_test() as pilot:
            app._set_compact_header(True)
            await pilot.pause()
            status = str(app.query_one("#status").render())
            header = str(app.query_one("#top", Static).render())
            assert "tokens:" not in status
            assert "120K in" in header
            assert "2.8M out" in header

    asyncio.run(_run())


def test_tui_app_uses_rendered_turn_blocks_for_markdown_reply():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=80)
        async with app.run_test() as pilot:
            app._write_assistant("This is **important** and `code`.")
            await pilot.pause()

            assert app.chat_transcript[-1] == "Metis\nThis is **important** and `code`."

    asyncio.run(_run())


def test_tui_app_shows_activity_while_chat_worker_is_running():
    async def _run():
        runner = _Runner()
        chat = TuiChatSession(
            object(),
            codebase_path=".",
            adapter=_FakeAdapter(_FakeModel()),
        )
        app = MetisTuiApp(
            runner,
            width_hint=80,
            chat_session=chat,
            startup_state=TuiStartupState(
                stage="ready",
                chat_enabled=True,
                message="ready",
                provider_ready=True,
            ),
        )
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("h", "i", "enter")
            await pilot.pause()
            activity = app.query_one("#activity", MetisActivity)
            assert activity.detail in {
                "Waiting for LLM reply",
                "Streaming LLM reply",
                "Ready",
            }
            assert "METIS ACTIVITY" not in str(activity.render())

    asyncio.run(_run())


def test_tui_app_keeps_chat_available_while_provider_check_is_pending():
    class _RealRunner(_Runner):
        def __init__(self):
            super().__init__()
            self.engine = _Engine()
            self.artifacts = type("Artifacts", (), {"codebase_path": "."})()

    async def _run():
        runner = _RealRunner()
        app = MetisTuiApp(runner, width_hint=80)
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("h", "i", "enter")
            await pilot.pause(0.1)
            assert not any("Chat is disabled" in line for line in app.chat_transcript)

    asyncio.run(_run())


def test_tui_app_bootstrap_ready_verifies_then_enables_chat(tmp_path):
    class _RealRunner(_Runner):
        def __init__(self):
            super().__init__()
            self.engine = _Engine()
            self.artifacts = type("Artifacts", (), {"codebase_path": str(tmp_path)})()

    async def _run():
        runner = _RealRunner()
        app = MetisTuiApp(
            runner,
            width_hint=80,
            startup_state=TuiStartupState.ready(runner.engine, {"model": "gpt-test"}),
        )
        async with app.run_test() as pilot:
            await pilot.pause(0.4)
            assert app.startup_state.chat_enabled is True
            assert app.chat_session is not None
            await pilot.click("#input")
            await pilot.press("h", "i", "enter")
            await pilot.pause(0.2)
            assert any(
                "Metis\nhello from model" in line for line in app.chat_transcript
            )

    asyncio.run(_run())


def test_tui_app_provider_failure_is_advisory_when_chat_session_exists(tmp_path):
    class _FailingProvider(_Provider):
        def get_chat_model(self, **_kwargs):
            raise RuntimeError("Connection error.")

    class _FailingEngine:
        def __init__(self):
            self.llm_provider = _FailingProvider()

    class _RealRunner(_Runner):
        def __init__(self):
            super().__init__()
            self.engine = _FailingEngine()
            self.artifacts = type("Artifacts", (), {"codebase_path": str(tmp_path)})()

    async def _run():
        runner = _RealRunner()
        app = MetisTuiApp(
            runner,
            width_hint=80,
            startup_state=TuiStartupState.ready(runner.engine, {"model": "gpt-test"}),
        )
        async with app.run_test() as pilot:
            await pilot.pause(0.4)
            assert app.chat_session is not None
            assert app.startup_state.chat_enabled is True
            startup_text = str(app.query_one("#startup", Static).render())
            assert "Context" in startup_text
            status_text = str(app.query_one("#status").render())
            assert "failed" in status_text or "Chat ready" in status_text
            assert any("Connection error." in line for line in app.chat_transcript)
            assert any("chat will still try" in line for line in app.chat_transcript)

    asyncio.run(_run())


def test_tui_app_renders_public_review_progress_without_raw_event_names(tmp_path):
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=100)
        async with app.run_test() as pilot:
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="001-review",
                        sequence=1,
                        type="command.started",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message="Started /review_code",
                        payload={},
                    )
                )
            )
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="001-review",
                        sequence=2,
                        type="review.file.finished",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message=f"Reviewed {tmp_path / 'include' / 'ap_mpm.h'}",
                        payload={
                            "current_file": str(tmp_path / "include" / "ap_mpm.h"),
                            "completed_count": 7,
                            "total_files": 42,
                            "finding_count": 3,
                        },
                    )
                )
            )
            await pilot.pause()

            transcript = "\n".join(app.chat_transcript)
            assert "review.file.finished" not in transcript
            assert "Reviewed .../include/ap_mpm.h" in transcript
            assert "/private/" not in transcript
            summary = str(app.query_one("#status").render())
            assert "/review_code" in summary
            assert "7/42" in summary
            assert "findings 3" in summary

    asyncio.run(_run())


def test_tui_app_renders_sarif_artifact_in_run_summary():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=100)
        async with app.run_test() as pilot:
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="001-review",
                        sequence=1,
                        type="command.started",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message="Started /review_code",
                        payload={},
                    )
                )
            )
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="001-review",
                        sequence=2,
                        type="sarif.review.written",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message="Review SARIF written",
                        payload={
                            "path": "results/tui/run/review.sarif",
                            "files": 42,
                            "findings": 3,
                        },
                    )
                )
            )
            await pilot.pause()

            transcript = "\n".join(app.chat_transcript)
            assert "sarif.review.written" not in transcript
            assert "Review SARIF ready: results/tui/run/review.sarif" in transcript
            summary = str(app.query_one("#status").render())
            assert "SARIF results/tui/run/review.sarif" in summary

    asyncio.run(_run())


def test_tui_app_renders_security_report_artifact_in_run_summary():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=100)
        async with app.run_test() as pilot:
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="001-report",
                        sequence=1,
                        type="command.started",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message="Started /security_report",
                        payload={},
                    )
                )
            )
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="001-report",
                        sequence=2,
                        type="security_report.written",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message="Security report written",
                        payload={"output": "results/tui/run/security-report.md"},
                    )
                )
            )
            await pilot.pause()

            transcript = "\n".join(app.chat_transcript)
            assert "security_report.written" not in transcript
            assert (
                "Security report ready: results/tui/run/security-report.md"
                in transcript
            )
            summary = str(app.query_one("#status").render())
            assert "report results/tui/run/security-report.md" in summary

    asyncio.run(_run())


def test_tui_app_does_not_double_count_review_result_events(tmp_path):
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=100)
        async with app.run_test() as pilot:
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="001-review",
                        sequence=1,
                        type="command.started",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message="Started /review_code",
                        payload={},
                    )
                )
            )
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="001-review",
                        sequence=2,
                        type="review.file.finished",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message="Reviewed include/ap_mpm.h",
                        payload={
                            "current_file": "include/ap_mpm.h",
                            "completed_count": 1,
                            "total_files": 2,
                            "finding_count": 3,
                        },
                    )
                )
            )
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="001-review",
                        sequence=3,
                        type="review.result.recorded",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message="Reviewed include/ap_mpm.h",
                        payload={"finding_count": 1},
                    )
                )
            )
            await pilot.pause()

            summary = str(app.query_one("#status").render())
            assert "findings 3" in summary
            assert "findings 4" not in summary

    asyncio.run(_run())


def test_tui_app_hard_bootstrap_failure_disables_chat():
    async def _run():
        runner = _Runner()
        app = MetisTuiApp(
            runner,
            width_hint=80,
            startup_state=TuiStartupState.failed(
                stage="config", error=RuntimeError("missing key")
            ),
        )
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("h", "i", "enter")
            await pilot.pause(0.1)
            assert not any("Metis chat ready" in line for line in app.chat_transcript)
            assert any("Chat is disabled" in line for line in app.chat_transcript)

    asyncio.run(_run())


def test_tui_app_tool_updates_do_not_persist_rich_markup():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=80)
        async with app.run_test() as pilot:
            app.post_message(ChatEvent(ChatUpdate("tool", "using tool")))
            await pilot.pause()
            assert not any("Tool\nusing tool" in line for line in app.chat_transcript)
            assert not any("[dim]" in line for line in app.chat_transcript)
            assert app.query_one("#activity", MetisActivity).active is True
            assert "using tool" in app._tool_log_lines[-1]

    asyncio.run(_run())


def test_tui_app_renders_ai_tool_call_output_in_live_log():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=80)
        async with app.run_test() as pilot:
            app.post_message(ChatEvent(ChatUpdate("tool", "tool started: review_code")))
            app.post_message(
                ChatEvent(
                    ChatUpdate(
                        "tool_result",
                        "review_code\n/review_code finished\ndefault_sarif=results/tui/run/review.sarif",
                    )
                )
            )
            app.post_message(
                ChatEvent(ChatUpdate("tool", "tool finished: review_code"))
            )
            await pilot.pause()

            assert any(
                "Tool\n/review_code started" in line for line in app.chat_transcript
            )
            assert any(
                "Tool\n/review_code finished" in line for line in app.chat_transcript
            )
            assert app.query_one("#tool-log").display is True
            assert any("/review_code finished" in line for line in app._tool_log_lines)
            assert any(
                "results/tui/run/review.sarif" in line for line in app._tool_log_lines
            )

    asyncio.run(_run())


def test_tui_app_suppresses_read_only_tool_transcript_spam():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=80)
        async with app.run_test() as pilot:
            app.post_message(ChatEvent(ChatUpdate("tool", "tool started: read_file")))
            app.post_message(
                ChatEvent(ChatUpdate("tool_result", "read_file\ncontents"))
            )
            app.post_message(ChatEvent(ChatUpdate("tool", "tool finished: read_file")))
            await pilot.pause()

            transcript = "\n".join(app.chat_transcript)
            assert "read_file started" not in transcript
            assert "read_file finished" not in transcript
            assert "read_file" in "\n".join(app._tool_log_lines)
            assert "contents" in "\n".join(app._tool_log_lines)

    asyncio.run(_run())


def test_metis_activity_words_change_slower_than_frames():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=80)
        async with app.run_test() as pilot:
            activity = app.query_one("#activity", MetisActivity)
            activity.set_busy("testing")
            first_word = activity.WORDS[activity._word]

            for _ in range(7):
                activity._tick()

            assert activity.WORDS[activity._word] == first_word
            activity._tick()
            assert activity.WORDS[activity._word] != first_word
            await pilot.pause()

    asyncio.run(_run())


def test_tui_app_slash_review_code_streams_runner_events_to_live_log():
    class _ProgressRunner(_Runner):
        def execute(self, command):
            self.commands.append(command.name)
            self._emit("command.accepted", "001-review", "Accepted /review_code")
            self._emit("command.started", "001-review", "Started /review_code")
            self._emit(
                "command.progress",
                "001-review",
                "Preparing review inputs",
                payload={"completed": 1, "total": 3},
            )
            self._emit(
                "review.file.finished",
                "001-review",
                "Reviewed src/app.py",
                payload={
                    "current_file": "src/app.py",
                    "completed_count": 2,
                    "total_files": 3,
                    "finding_count": 1,
                },
            )
            self._emit(
                "sarif.review.written",
                "001-review",
                "Review SARIF written to results/tui/run/review.sarif",
                payload={
                    "path": "results/tui/run/review.sarif",
                    "files": 3,
                    "findings": 1,
                },
            )
            self._emit("command.finished", "001-review", "Finished /review_code")

    async def _run():
        runner = _ProgressRunner()
        app = MetisTuiApp(runner, width_hint=80)
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press(
                "/",
                "r",
                "e",
                "v",
                "i",
                "e",
                "w",
                "_",
                "c",
                "o",
                "d",
                "e",
                "enter",
            )
            await pilot.pause(0.2)

            assert runner.commands == ["review_code"]
            assert app.query_one("#tool-log").display is True
            assert any(
                "Preparing review inputs" in line for line in app._tool_log_lines
            )
            assert any("src/app.py" in line for line in app._tool_log_lines)
            assert any("Review SARIF written" in line for line in app._tool_log_lines)

    asyncio.run(_run())


def test_tui_app_bounds_live_tool_log_lines():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=80)
        async with app.run_test() as pilot:
            app._start_tool_log("noisy_tool")
            for index in range(app.TOOL_LOG_LIMIT + 20):
                app._append_tool_log(f"line {index}")
            await pilot.pause()

            assert len(app._tool_log_lines) == app.TOOL_LOG_LIMIT
            assert app._tool_log_lines[0] == "line 20"
            assert app._tool_log_lines[-1] == f"line {app.TOOL_LOG_LIMIT + 19}"

    asyncio.run(_run())


def test_tui_app_init_uses_ai_chat_when_available(tmp_path):
    class _InitModel:
        def stream(self, messages):
            self.messages = messages
            yield type(
                "Chunk", (), {"content": "# Project Context\n\nAI generated.\n"}
            )()

    async def _run():
        runner = _Runner()
        chat = TuiChatSession(
            object(),
            codebase_path=tmp_path,
            adapter=_FakeAdapter(_InitModel()),
        )
        app = MetisTuiApp(
            runner,
            width_hint=80,
            chat_session=chat,
            startup_state=TuiStartupState(
                stage="ready",
                chat_enabled=True,
                message="ready",
                provider_ready=True,
            ),
        )
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("/", "i", "n", "i", "t", "enter")
            await pilot.pause(0.3)

            assert runner.commands == []
            assert (
                (tmp_path / "CONTEXT.md")
                .read_text(encoding="utf-8")
                .startswith("# Project Context")
            )
            assert any("CONTEXT.md written" in line for line in app.chat_transcript)

    asyncio.run(_run())


def test_tui_app_provider_event_does_not_clear_chat_activity():
    async def _run():
        app = MetisTuiApp(_Runner(), width_hint=80)
        async with app.run_test() as pilot:
            app._active = True
            app._set_busy("Waiting for LLM reply", owner="chat")
            app.post_message(
                RunnerEvent(
                    TuiEvent(
                        run_id="app-test",
                        command_id="provider",
                        sequence=1,
                        type="provider.ready",
                        timestamp="2026-05-12T00:00:00Z",
                        level="info",
                        message="provider ready",
                        payload={},
                    )
                )
            )
            await pilot.pause()
            activity = app.query_one("#activity", MetisActivity)
            assert activity.active is True
            assert activity.detail == "Waiting for LLM reply"

    asyncio.run(_run())


def test_tui_app_prompts_for_explicit_triage_path_when_no_review_sarif():
    class _PromptRunner(_Runner):
        def execute(self, command):
            self.commands.append(command.name)
            if command.name == "triage" and not command.args:
                from metis.tui.runner import TriageInputRequiredError

                raise TriageInputRequiredError("missing")

    async def _run():
        runner = _PromptRunner()
        app = MetisTuiApp(runner, width_hint=80)
        async with app.run_test() as pilot:
            await pilot.click("#input")
            await pilot.press("/", "t", "r", "i", "a", "g", "e", "enter")
            await pilot.pause(0.2)
            assert app._pending_triage_path is True
            assert any("Enter a SARIF path" in line for line in app.chat_transcript)

    asyncio.run(_run())
