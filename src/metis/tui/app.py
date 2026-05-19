# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
from queue import SimpleQueue
import shutil
import sys
from typing import Iterable

from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.padding import Padding
from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.containers import Container, Vertical
from textual.css.query import NoMatches
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Input, Label, OptionList, RichLog, Static

from .bootstrap import TuiStartupState
from .chat import ChatUpdate, TuiChatSession
from .chat_model import ProviderVerifier, TuiChatModelAdapter
from .commands import (
    DOMAIN_COMMANDS,
    TuiCommandName,
    command_completion_items,
    command_help,
    parse_slash_command,
)
from .events import TuiEvent
from .runner import TriageInputRequiredError, TuiDomainRunner
from .sanitize import sanitize_text
from .theme import METIS_CSS, metis_logo
from .tools import DOMAIN_TOOLS, TuiAgentToolRunner


class RunnerEvent(Message):
    def __init__(self, event: TuiEvent):
        super().__init__()
        self.event = event


class ChatEvent(Message):
    def __init__(self, update: ChatUpdate):
        super().__init__()
        self.update = update


@dataclass(slots=True)
class RunDisplayState:
    command: str = ""
    phase: str = "Idle"
    current_path: str = ""
    completed: int = 0
    total: int | None = None
    findings: int = 0
    artifact_path: str = ""


class MetisActivity(Static):
    active = reactive(False)
    detail = reactive("Ready")

    FRAMES = (
        "[=    ]",
        "[==   ]",
        "[===  ]",
        "[ === ]",
        "[  ===]",
        "[   ==]",
        "[    =]",
        "[     ]",
    )
    WORDS = (
        "working",
        "reading",
        "analyzing",
        "reviewing",
        "waiting",
        "summarizing",
    )

    def __init__(self, *children, **kwargs):
        super().__init__(*children, **kwargs)
        self._frame = 0
        self._word = 0
        self._ticks = 0

    def on_mount(self) -> None:
        self.set_interval(0.35, self._tick)
        self.display = False
        self._render_activity()

    def set_busy(self, detail: str) -> None:
        self.active = True
        self.detail = sanitize_text(detail)
        self._render_activity()

    def set_ready(self, detail: str = "Ready") -> None:
        self.active = False
        self.detail = sanitize_text(detail)
        self.display = False
        self._render_activity()

    def _tick(self) -> None:
        if not self.active:
            return
        self._frame = (self._frame + 1) % len(self.FRAMES)
        self._ticks += 1
        if self._ticks % 8 == 0:
            self._word = (self._word + 1) % len(self.WORDS)
        self._render_activity()

    def _render_activity(self) -> None:
        if self.active:
            self.display = True
            word = self.WORDS[self._word]
            frame = self.FRAMES[self._frame]
            text = Text()
            text.append("● ", style="#f4bf4f")
            text.append(f"{word:<18}", style="#d8d8d8")
            text.append(f" {frame}  ", style="#9b4dff")
            text.append(self.detail, style="#a5a5a5")
            self.update(text)
            return
        self.update(Text(""))


class MetisTuiApp(App[None]):
    CSS = METIS_CSS
    BINDINGS = [("ctrl+c", "quit", "Quit")]
    TOOL_LOG_LIMIT = 160

    def __init__(
        self,
        runner: TuiDomainRunner,
        *,
        width_hint: int = 80,
        startup_state: TuiStartupState | None = None,
        chat_session: TuiChatSession | None = None,
    ):
        super().__init__(ansi_color=True)
        self.runner = runner
        self._active = False
        self._event_queue: SimpleQueue[TuiEvent] = SimpleQueue()
        self.width_hint = width_hint
        self.chat_transcript: list[str] = []
        self.runner._event_callback = self._event_queue.put
        self._pending_triage_path = False
        self._activity_owner: str | None = None
        self.startup_state = startup_state or TuiStartupState.ready(
            getattr(runner, "engine", None), {}
        )
        self.chat_session = chat_session
        self._assistant_buffer = ""
        self._initializing_context = False
        self._run_display = RunDisplayState()
        self._compact_header = False
        self._tool_log_lines: list[str] = []
        self._tool_log_title = ""
        self._tool_log_finished = False
        self._status_override: str | None = None
        self._command_completion_items: tuple[tuple[TuiCommandName, str, str], ...] = ()

    def compose(self) -> ComposeResult:
        with Vertical(id="shell"):
            with Container(id="hero"):
                yield Static(Text(metis_logo(self.width_hint)), id="top")
                yield Static(Text(self._startup_text()), id="startup")
                yield Static(self._connection_text(), id="connection-status")
                yield Static(
                    Text(
                        "+ AI harness for ARM/Metis vulnerability analysis +\n"
                        "+ Powered by Metis. Driven by AI."
                    ),
                    id="tagline",
                )
            with Vertical(id="workspace"):
                yield RichLog(id="transcript", wrap=True, highlight=True)
                yield RichLog(id="tool-log", wrap=True, highlight=True)
            with Vertical(id="bottom-panel"):
                yield Label(self._status_strip_text(), id="status")
                yield MetisActivity(id="activity")
                yield OptionList(id="command-completions", compact=True)
                yield Input(placeholder="Ask Metis or type /help", id="input")
            yield Static(Text(self._shortcut_text()), id="shortcuts")

    def on_mount(self) -> None:
        self._refresh_logo(self.size.width)
        self._ensure_chat_session()
        self._refresh_startup_text()
        self.query_one("#tool-log", RichLog).display = False
        self.query_one("#command-completions", OptionList).display = False
        if not self.startup_state.chat_enabled:
            self._write_system("Metis chat unavailable. Type /help for slash commands.")
            self._write_system(f"Chat disabled: {self.startup_state.disabled_reason}")
        else:
            self._write_system(self._onboarding_text())
        if self._can_verify_provider():
            self._set_busy("Checking provider readiness", owner="provider-check")
            self._verify_provider()
        self.set_interval(0.1, self._drain_runner_events)
        self.set_interval(0.5, self._refresh_token_status)
        self.query_one("#input", Input).focus()

    def on_resize(self, event: events.Resize) -> None:
        if self._compact_header:
            self.query_one("#top", Static).update(Text(self._compact_header_text()))
            return
        self._refresh_logo(event.size.width)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        self._hide_command_completions()
        if not text:
            return
        self._set_compact_header(True)
        self._write_user(text)
        if self._pending_triage_path:
            self._pending_triage_path = False
            self._handle_slash(f"/triage {text}")
            return
        if text.startswith("/"):
            self._handle_slash(text)
            return
        if not self.startup_state.chat_enabled or self.chat_session is None:
            reason = self.startup_state.disabled_reason or self.startup_state.message
            self._write_system(f"Chat is disabled: {sanitize_text(reason)}")
            return
        self._run_chat(text)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "input":
            return
        self._refresh_command_completions(event.value)

    def on_key(self, event: events.Key) -> None:
        if not self._command_completions_visible():
            return
        if event.key in {"down", "ctrl+n"}:
            self.query_one("#command-completions", OptionList).action_cursor_down()
            event.prevent_default()
            event.stop()
            return
        if event.key in {"up", "ctrl+p"}:
            self.query_one("#command-completions", OptionList).action_cursor_up()
            event.prevent_default()
            event.stop()
            return
        if event.key == "tab" and self._accept_command_completion():
            event.prevent_default()
            event.stop()
            return
        if (
            event.key == "enter"
            and self._should_accept_command_completion_on_enter()
            and self._accept_command_completion()
        ):
            event.prevent_default()
            event.stop()
            return
        if event.key == "escape":
            self._hide_command_completions()
            event.prevent_default()
            event.stop()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "command-completions":
            return
        self._accept_command_completion(index=event.option_index)
        event.stop()

    def on_runner_event(self, message: RunnerEvent) -> None:
        event = message.event.sanitized()
        self._apply_run_event(event)
        self._append_runner_event_to_tool_log(event)
        display_message = self._display_runner_event(event)
        if display_message:
            self._write_system(display_message)
        status_override = None
        if not event.type.startswith(
            ("review.", "sarif.", "index.", "triage.", "security_report.", "command.")
        ):
            status_override = self._status_text(event)
        self.query_one("#status", Label).update(
            self._status_strip_text(status_override)
        )
        if event.type == "provider.ready":
            self._ensure_chat_session()
            self.startup_state = replace(
                self.startup_state,
                chat_enabled=True,
                provider_ready=True,
                provider_status="ready",
                disabled_reason="",
            )
            self._refresh_startup_text()
            self._set_ready("Provider ready", owner="provider-check")
        if event.type == "provider.failed":
            self.startup_state = replace(
                self.startup_state,
                chat_enabled=self.chat_session is not None,
                provider_ready=False,
                provider_status="failed",
                disabled_reason=sanitize_text(event.message),
            )
            self._refresh_startup_text()
            self._write_system(
                f"Provider check failed: {sanitize_text(event.message)}; chat will still try on submit."
            )
            self._set_ready("Provider check failed", owner="provider-check")
        if event.type == "run.finished":
            self._active = False
            self._finish_run()
            self._set_ready("Ready", owner="domain-command")
        if event.type == "command.finished":
            self._finish_run()
        if event.type == "triage.input.required":
            self._pending_triage_path = True
            self._write_system("Enter a SARIF path to continue triage.")

    def _handle_slash(self, text: str) -> None:
        try:
            request = parse_slash_command(text)
        except ValueError as exc:
            self._write_system(f"Error: {exc}")
            return
        if request.name == "help":
            self._write_system(command_help())
            return
        if request.name == "status":
            self._write_system(self._status_report())
            return
        if request.name == "exit":
            self.exit()
            return
        if request.name not in DOMAIN_COMMANDS:
            self._write_system(f"Unsupported command: /{request.name}")
            return
        if request.name == "init" and self._can_run_ai_init():
            self._run_project_init()
            return
        if (
            request.name != "init"
            and hasattr(self.runner, "engine")
            and getattr(self.runner, "engine") is None
        ):
            self._write_system("Command unavailable until Metis startup succeeds.")
            return
        self._run_commands([request])

    def _refresh_command_completions(self, value: str) -> None:
        if value != value.rstrip():
            self._hide_command_completions()
            return
        raw = value.strip()
        if not raw.startswith("/") or " " in raw:
            self._hide_command_completions()
            return
        items = command_completion_items(raw)
        if not items:
            self._hide_command_completions()
            return
        self._command_completion_items = items
        completions = self.query_one("#command-completions", OptionList)
        completions.clear_options()
        completions.add_options(item[2] for item in items)
        completions.highlighted = 0
        completions.display = True

    def _hide_command_completions(self) -> None:
        self._command_completion_items = ()
        try:
            completions = self.query_one("#command-completions", OptionList)
        except NoMatches:
            return
        completions.display = False
        completions.clear_options()

    def _command_completions_visible(self) -> bool:
        try:
            completions = self.query_one("#command-completions", OptionList)
        except NoMatches:
            return False
        return bool(completions.display and self._command_completion_items)

    def _accept_command_completion(self, *, index: int | None = None) -> bool:
        if not self._command_completion_items:
            return False
        completions = self.query_one("#command-completions", OptionList)
        selected_index = completions.highlighted if index is None else index
        if selected_index is None:
            selected_index = 0
        if selected_index < 0 or selected_index >= len(self._command_completion_items):
            return False
        _command, insert_text, _label = self._command_completion_items[selected_index]
        input_widget = self.query_one("#input", Input)
        if input_widget.value == insert_text:
            return False
        input_widget.value = insert_text
        input_widget.cursor_position = len(insert_text)
        self._hide_command_completions()
        input_widget.focus()
        return True

    def _should_accept_command_completion_on_enter(self) -> bool:
        input_value = self.query_one("#input", Input).value.strip()
        if not input_value.startswith("/"):
            return False
        selected = self._selected_command_completion()
        if selected is None:
            return False
        command, _insert_text, _label = selected
        return input_value != f"/{command}"

    def _selected_command_completion(
        self, *, index: int | None = None
    ) -> tuple[TuiCommandName, str, str] | None:
        if not self._command_completion_items:
            return None
        completions = self.query_one("#command-completions", OptionList)
        selected_index = completions.highlighted if index is None else index
        if selected_index is None:
            selected_index = 0
        if selected_index < 0 or selected_index >= len(self._command_completion_items):
            return None
        return self._command_completion_items[selected_index]

    def _run_commands(self, commands: Iterable) -> None:
        if self._active:
            self._write_system("A command is already running.")
            return
        command_tuple = tuple(commands)
        if command_tuple:
            self._begin_run(command_tuple[0].name)
            self._start_tool_log(f"/{command_tuple[0].name}")
        self._active = True
        self._set_busy("Running domain command", owner="domain-command")
        self.run_worker(
            lambda: self._execute_commands(command_tuple),
            thread=True,
            exclusive=True,
            name="metis-domain-command",
        )

    def _execute_commands(self, commands: tuple) -> None:
        self.runner._event_callback = self._event_queue.put
        try:
            for command in commands:
                try:
                    self.runner.execute(command)
                except TriageInputRequiredError:
                    self.runner._emit(
                        "triage.input.required",
                        "triage",
                        "No review SARIF found. Enter a SARIF path for /triage.",
                        level="warning",
                    )
                    self.runner._emit(
                        "log.message",
                        "triage",
                        "Enter a SARIF path to continue triage.",
                        level="warning",
                    )
                    break
        finally:
            self.runner._emit("run.finished", "run", "Command worker finished")

    def _run_chat(self, text: str) -> None:
        if self._active:
            self._write_system("A command or chat response is already running.")
            return
        self._active = True
        self._assistant_buffer = ""
        self._set_busy("Waiting for LLM reply", owner="chat")
        self.run_worker(
            lambda: self._execute_chat(text),
            thread=True,
            exclusive=True,
            name="metis-chat",
        )

    def _run_project_init(self) -> None:
        if self._active:
            self._write_system("A command or chat response is already running.")
            return
        self._active = True
        self._assistant_buffer = ""
        self._initializing_context = True
        self._set_busy("Inspecting project for /init", owner="chat")
        self.run_worker(
            self._execute_project_init,
            thread=True,
            exclusive=True,
            name="metis-project-init",
        )

    def _execute_chat(self, text: str) -> None:
        assert self.chat_session is not None
        try:
            for update in self.chat_session.submit(text):
                self.call_from_thread(self.post_message, ChatEvent(update))
        finally:
            self.call_from_thread(
                self.post_message, ChatEvent(ChatUpdate("done", "Chat worker finished"))
            )

    def _execute_project_init(self) -> None:
        assert self.chat_session is not None
        try:
            for update in self.chat_session.initialize_project_context():
                self.call_from_thread(self.post_message, ChatEvent(update))
        finally:
            self.call_from_thread(
                self.post_message, ChatEvent(ChatUpdate("done", "Init worker finished"))
            )

    def on_chat_event(self, message: ChatEvent) -> None:
        update = message.update
        if update.kind == "token":
            self._assistant_buffer += update.text
            preview = sanitize_text(self._assistant_buffer)[-80:]
            self.query_one("#status", Label).update(
                self._status_strip_text(f"Streaming: {preview}")
            )
            self._set_busy("Streaming LLM reply", owner="chat")
            return
        if update.kind == "final":
            if self._initializing_context and self.chat_session is not None:
                context_path = self.chat_session.context_loader.path
                context_path.write_text(sanitize_text(update.text), encoding="utf-8")
                self.chat_session.loaded_context = (
                    self.chat_session.context_loader.load()
                )
                self._write_system(f"CONTEXT.md written to {context_path}")
            else:
                self._write_assistant(update.text)
            self._status_override = None
            self.query_one("#status", Label).update(self._status_strip_text())
            self._set_ready("Ready", owner="chat")
            return
        if update.kind == "error":
            self._initializing_context = False
            self._write_system(f"Error: {sanitize_text(update.text)}")
            self.query_one("#status", Label).update(
                self._status_strip_text("Chat failed")
            )
            self._finish_tool_log("failed")
            self._set_ready("Chat failed", owner="chat")
            return
        if update.kind == "tool":
            self._handle_tool_update(update.text)
            self.query_one("#status", Label).update(
                self._status_strip_text(sanitize_text(update.text))
            )
            self._set_busy(update.text, owner="chat")
            return
        if update.kind == "tool_result":
            self._append_tool_result(update.text)
            self.query_one("#status", Label).update(
                self._status_strip_text("Tool output received")
            )
            self._set_busy("Reading tool output", owner="chat")
            return
        if update.kind == "status":
            self.query_one("#status", Label).update(
                self._status_strip_text(sanitize_text(update.text))
            )
            return
        if update.kind == "done":
            self._active = False
            self._initializing_context = False
            self._status_override = None
            if self._tool_log_title:
                self._finish_tool_log("complete")
            self._set_ready("Ready", owner="chat")

    def _drain_runner_events(self) -> None:
        while not self._event_queue.empty():
            event = self._event_queue.get()
            self.post_message(RunnerEvent(event))

    def _write_chat(
        self, message: str, renderable: RenderableType | None = None
    ) -> None:
        safe_message = sanitize_text(message)
        self.chat_transcript.append(safe_message)
        self.query_one("#transcript", RichLog).write(renderable or safe_message)

    def _write_user(self, message: str) -> None:
        safe_message = sanitize_text(message)
        self._write_chat(
            f"You\n{safe_message}",
            self._message_renderable("you", safe_message, "#66d9ef"),
        )

    def _write_assistant(self, message: str) -> None:
        safe_message = sanitize_text(message)
        self._write_chat(
            f"Metis\n{safe_message}",
            self._message_renderable("metis", safe_message, "#9b4dff", markdown=True),
        )

    def _write_system(self, message: str) -> None:
        safe_message = sanitize_text(message)
        self._write_chat(
            f"System\n{safe_message}",
            self._message_renderable("system", safe_message, "#7a7a7a"),
        )

    def _write_tool_event(self, message: str) -> None:
        safe_message = sanitize_text(message)
        self._write_chat(
            f"Tool\n{safe_message}",
            self._message_renderable("tool", safe_message, "#f4bf4f"),
        )

    def _message_renderable(
        self, role: str, message: str, role_style: str, *, markdown: bool = False
    ) -> Group:
        label = Text(f"{role:<7}", style=f"bold {role_style}")
        body: RenderableType
        if markdown:
            body = Markdown(
                message,
                style="#c8c8c8",
                code_theme="monokai",
                inline_code_theme="monokai",
            )
        else:
            body = Text(message, style="#b8b8b8")
        return Group(Padding(label, (1, 0, 0, 0)), Padding(body, (0, 0, 0, 2)))

    def _begin_run(self, command: str) -> None:
        self._run_display = RunDisplayState(
            command=f"/{command}",
            phase=self._phase_for_command(command),
        )
        self._set_compact_header(True)
        self._refresh_run_summary()

    def _finish_run(self) -> None:
        if not self._run_display.command:
            return
        self._status_override = None
        if self._run_display.artifact_path:
            self._run_display.phase = "Output ready"
        else:
            self._run_display.phase = "Complete"
        self._refresh_run_summary()

    def _apply_run_event(self, event: TuiEvent) -> None:
        if event.type == "command.started":
            command = self._command_from_message(event.message)
            if command:
                self._begin_run(command)
            return

        payload = event.payload or {}
        if event.type in {
            "review.file.started",
            "review.file.finished",
            "review.file.skipped",
        }:
            self._run_display.phase = "Reviewing files"
            self._apply_progress_payload(payload)
            current_file = payload.get("current_file")
            if current_file:
                self._run_display.current_path = self._display_path(str(current_file))
        elif event.type == "review.result.recorded":
            self._run_display.phase = "Recording findings"
            if self._run_display.total is None:
                self._run_display.findings += int(payload.get("finding_count") or 0)
                self._run_display.completed = max(self._run_display.completed, 1)
            self._run_display.current_path = self._display_path_from_message(
                event.message
            )
        elif event.type == "review.finding.emitted":
            self._run_display.phase = "Finding emitted"
        elif event.type == "sarif.review.written":
            self._run_display.phase = "Review SARIF ready"
            self._run_display.artifact_path = self._display_path(
                str(payload.get("path") or "")
            )
            self._run_display.total = (
                int(payload.get("files") or self._run_display.total or 0)
                or self._run_display.total
            )
            self._run_display.findings = int(
                payload.get("findings") or self._run_display.findings
            )
        elif event.type == "index.scan.started":
            self._run_display.phase = "Scanning files"
            self._run_display.total = int(payload.get("total_items") or 0) or None
        elif event.type == "command.progress":
            self._run_display.phase = sanitize_text(event.message)
            self._apply_progress_payload(payload)
        elif event.type == "index.embeddings.started":
            self._run_display.phase = "Embedding context"
        elif event.type == "index.embeddings.finished":
            self._run_display.phase = "Context ready"
        elif event.type in {
            "triage.finding.started",
            "triage.finding.finished",
            "sarif.triage.checkpoint",
        }:
            self._run_display.phase = "Triaging SARIF"
            self._run_display.completed = int(
                payload.get("processed")
                or payload.get("index")
                or self._run_display.completed
            )
            self._run_display.total = (
                int(payload.get("total") or self._run_display.total or 0)
                or self._run_display.total
            )
        elif event.type == "sarif.triage.written":
            self._run_display.phase = "Triage SARIF ready"
            self._run_display.artifact_path = self._display_path(
                str(payload.get("output") or "")
            )
        elif event.type == "security_report.started":
            self._run_display.phase = "Reading triage SARIF"
        elif event.type == "security_report.findings.extracted":
            self._run_display.phase = "Extracting typed findings"
            self._run_display.findings = int(
                payload.get("findings") or self._run_display.findings
            )
        elif event.type == "security_report.candidates.built":
            self._run_display.phase = "Building attack chains"
        elif event.type == "security_report.cross_batch.built":
            self._run_display.phase = "Joining cross-batch chains"
        elif event.type == "security_report.batches.prepared":
            self._run_display.phase = "Preparing model batches"
            self._run_display.total = int(payload.get("batches") or 0) or None
        elif event.type == "security_report.snippets.attached":
            self._run_display.phase = "Reading affected files"
        elif event.type == "security_report.llm.started":
            self._run_display.phase = "Extracting attack chains"
            self._run_display.completed = 0
            self._run_display.total = int(payload.get("batches") or 0) or None
            self._run_display.findings = int(
                payload.get("findings") or self._run_display.findings
            )
        elif event.type == "security_report.batch.started":
            self._run_display.phase = "Analyzing attack chains"
            self._run_display.completed = max(int(payload.get("batch") or 1) - 1, 0)
            self._run_display.total = int(payload.get("batches") or 0) or None
        elif event.type == "security_report.batch.finished":
            self._run_display.phase = "Analyzing attack chains"
            self._run_display.completed = int(
                payload.get("batch") or self._run_display.completed
            )
            self._run_display.total = int(payload.get("batches") or 0) or None
        elif event.type == "security_report.synthesis.started":
            self._run_display.phase = "Synthesizing report"
            if self._run_display.total:
                self._run_display.completed = self._run_display.total
        elif event.type in {
            "security_report.cross_batch.started",
            "security_report.cross_batch.finished",
        }:
            self._run_display.phase = "Checking cross-batch chains"
        elif event.type == "security_report.artifacts.written":
            self._run_display.phase = "Saving processing artifacts"
        elif event.type == "security_report.written":
            self._run_display.phase = "Security report ready"
            self._run_display.artifact_path = self._display_path(
                str(payload.get("output") or "")
            )
        elif event.type == "command.failed":
            self._run_display.phase = "Failed"
        self._refresh_run_summary()

    def _apply_progress_payload(self, payload: dict) -> None:
        if "completed_count" in payload:
            self._run_display.completed = int(payload.get("completed_count") or 0)
        elif "completed" in payload:
            self._run_display.completed = int(payload.get("completed") or 0)
        if "total_files" in payload:
            self._run_display.total = int(payload.get("total_files") or 0) or None
        elif "total" in payload:
            self._run_display.total = int(payload.get("total") or 0) or None
        if "finding_count" in payload:
            self._run_display.findings = int(payload.get("finding_count") or 0)

    def _display_runner_event(self, event: TuiEvent) -> str | None:
        payload = event.payload or {}
        if event.type == "command.started":
            return (
                f"Started {self._run_display.command or sanitize_text(event.message)}"
            )
        if event.type == "review.file.finished":
            path = self._display_path(str(payload.get("current_file") or "file"))
            return f"Reviewed {path}  {self._progress_text()}  findings {self._run_display.findings}"
        if event.type == "review.file.skipped":
            path = self._display_path(str(payload.get("current_file") or "file"))
            return f"Skipped {path}  {self._progress_text()}"
        if event.type == "sarif.review.written":
            return f"Review SARIF ready: {self._run_display.artifact_path}  findings {self._run_display.findings}"
        if event.type == "sarif.triage.written":
            return f"Triage SARIF ready: {self._run_display.artifact_path}"
        if event.type == "security_report.written":
            return f"Security report ready: {self._run_display.artifact_path}"
        if event.type == "index.scan.started":
            total = self._run_display.total or 0
            return f"Indexing project context: {total} files"
        if event.type == "index.embeddings.finished":
            return "Index ready"
        if event.type == "command.failed":
            return f"Command failed: {sanitize_text(event.message)}"
        if event.type == "triage.input.required":
            return f"{sanitize_text(event.message)}"
        return None

    def _status_text(self, event: TuiEvent) -> str:
        if self._run_display.command and event.type.startswith(
            ("review.", "sarif.", "index.", "triage.", "security_report.", "command.")
        ):
            return f"{self._run_display.phase} {self._progress_text()}".strip()
        return sanitize_text(event.message)

    def _refresh_run_summary(self) -> None:
        self.query_one("#status", Label).update(self._status_strip_text())
        if self._compact_header:
            self.query_one("#top", Static).update(Text(self._compact_header_text()))

    def _progress_text(self) -> str:
        if self._run_display.total:
            return f"{self._run_display.completed}/{self._run_display.total}"
        if self._run_display.completed:
            return str(self._run_display.completed)
        return ""

    def _display_path_from_message(self, message: str) -> str:
        prefix = "Reviewed "
        if message.startswith(prefix):
            return self._display_path(message[len(prefix) :])
        return sanitize_text(message)

    def _display_path(self, raw_path: str) -> str:
        safe_path = sanitize_text(raw_path)
        if not safe_path:
            return ""
        path = Path(safe_path)
        if not path.is_absolute():
            return path.as_posix()
        codebase = getattr(getattr(self.runner, "artifacts", None), "codebase_path", "")
        if codebase:
            try:
                return path.resolve().relative_to(Path(codebase).resolve()).as_posix()
            except ValueError:
                pass
        if len(path.parts) >= 3:
            return str(Path("...") / Path(*path.parts[-2:]))
        return path.name

    def _command_from_message(self, message: str) -> str:
        marker = "Started /"
        if marker not in message:
            return ""
        return message.split(marker, 1)[1].split()[0]

    def _phase_for_command(self, command: str) -> str:
        return {
            "index": "Indexing project context",
            "review_code": "Reviewing files",
            "review_file": "Reviewing file",
            "review_patch": "Reviewing patch",
            "triage": "Triaging SARIF",
            "security_report": "Writing security report",
            "init": "Inspecting project",
        }.get(command, "Running")

    def _set_compact_header(self, compact: bool) -> None:
        if self._compact_header == compact:
            return
        self._compact_header = compact
        if compact:
            self.query_one("#top", Static).update(Text(self._compact_header_text()))
        else:
            self._refresh_logo(self.size.width)
        for widget_id in ("#startup", "#connection-status", "#tagline"):
            self.query_one(widget_id, Static).display = not compact

    def _compact_header_text(self) -> str:
        state = self._run_display
        mode = state.command or "Chat"
        detail = state.phase if state.command else self._project_label()
        provider = self._provider_label()
        return (
            f"ARM METIS  |  {mode}  |  {detail}  |  {provider}"
            f"  |  {self._token_usage_text()}"
        )

    def _startup_text(self) -> str:
        state = self.startup_state
        rows = [
            ("Provider", state.provider_name or "unknown"),
            ("Model", state.model or "unknown"),
        ]
        rows.append(
            (
                "Context",
                state.context_status or "unknown",
            )
        )
        if state.hint:
            rows.append(("Hint", state.hint))
        return "\n".join(f"{label:<8} {value}" for label, value in rows)

    def _connection_text(self) -> Text:
        state = self.startup_state
        provider_ready = state.provider_ready and state.provider_status != "failed"
        chat_ready = state.chat_enabled and self.chat_session is not None
        text = Text()
        text.append("●", style="#62e884" if provider_ready else "#ff5c5c")
        text.append(f" {state.provider_name or 'provider'} {state.model or 'model'}   ")
        text.append("●", style="#62e884" if chat_ready else "#ff5c5c")
        text.append(" chat " + ("ready" if chat_ready else "disabled"))
        return text

    def _shortcut_text(self) -> str:
        return "/help   /init   /status   /index   /review_code   /triage   /security_report"

    def _status_strip_text(self, override: str | None = None) -> Text:
        if override is not None and self._active:
            self._status_override = override
        elif override is None and not self._active:
            self._status_override = None
        status_override = (
            override
            if override is not None
            else None if self._run_display.command else self._status_override
        )
        state = self.startup_state
        provider_ready = state.provider_ready and state.provider_status != "failed"
        chat_ready = state.chat_enabled and self.chat_session is not None
        ready = provider_ready and chat_ready
        text = Text()
        text.append("● ", style="#62e884" if ready else "#ff5c5c")
        text.append("Ready   " if ready else "Not ready   ", style="#d8d8d8")
        text.append(self._provider_label(), style="#9b4dff")
        if not provider_ready:
            text.append(f" provider {state.provider_status}", style="#ff8a8a")
        text.append("   ")
        text.append(self._project_label(), style="#d8d8d8")
        context = self.startup_state.context_status or "unknown"
        text.append("   context: ", style="#7a7a7a")
        text.append(context, style="#b8b8b8")
        if status_override:
            text.append("   ")
            text.append(status_override, style="#f4bf4f")
        elif self._run_display.command:
            text.append("   ")
            text.append(self._run_summary_plain(), style="#f4bf4f")
        return text

    def _refresh_token_status(self) -> None:
        try:
            self.query_one("#status", Label).update(self._status_strip_text())
            if self._compact_header:
                self.query_one("#top", Static).update(Text(self._compact_header_text()))
        except NoMatches:
            return

    def _token_usage_text(self) -> str:
        totals = self._usage_totals()
        input_tokens = int(totals.get("input_tokens") or 0)
        output_tokens = int(totals.get("output_tokens") or 0)
        return (
            f"{self._format_token_count(input_tokens)} in"
            f"  {self._format_token_count(output_tokens)} out"
        )

    def _format_token_count(self, value: int) -> str:
        count = max(0, int(value or 0))
        if count >= 1_000_000:
            return self._compact_number(count / 1_000_000) + "M"
        if count >= 1_000:
            return self._compact_number(count / 1_000) + "K"
        return str(count)

    def _compact_number(self, value: float) -> str:
        if value >= 100:
            return str(int(round(value)))
        text = f"{value:.1f}"
        return text[:-2] if text.endswith(".0") else text

    def _usage_totals(self) -> dict:
        engine = getattr(self.runner, "engine", None)
        usage_totals = getattr(engine, "usage_totals", None)
        if callable(usage_totals):
            return usage_totals()
        runtime = getattr(engine, "usage_runtime", None)
        snapshot_total = getattr(runtime, "snapshot_total", None)
        if callable(snapshot_total):
            return snapshot_total()
        return {}

    def _run_summary_plain(self) -> str:
        state = self._run_display
        parts = [state.command or "Ready", state.phase]
        progress = self._progress_text()
        if progress:
            parts.append(progress)
        if state.current_path:
            parts.append(state.current_path)
        if state.findings:
            parts.append(f"findings {state.findings}")
        if state.artifact_path:
            label = "report" if state.command == "/security_report" else "SARIF"
            parts.append(f"{label} {state.artifact_path}")
        return "  ".join(parts)

    def _handle_tool_update(self, message: str) -> None:
        safe = sanitize_text(message)
        prefix = ""
        tool_name = ""
        detail = ""
        if ": " in safe:
            prefix, detail = safe.split(": ", 1)
            tool_name = detail.split(":", 1)[0].strip()
        if prefix in {"tool started", "tool planned"} and tool_name:
            self._start_tool_log(tool_name)
            if self._is_domain_tool(tool_name):
                self._write_tool_event(f"/{tool_name} started")
            self._append_tool_log(f"> {tool_name} started")
            return
        if prefix in {"tool finished", "tool done"} and tool_name:
            if self._is_domain_tool(tool_name):
                self._write_tool_event(f"/{tool_name} finished")
            self._append_tool_log(f"> {tool_name} finished")
            self._finish_tool_log("complete")
            return
        if prefix == "tool error" and tool_name:
            self._write_tool_event(f"/{detail}")
            self._append_tool_log(f"! {detail}")
            self._finish_tool_log("failed")
            return
        self._append_tool_log(f"> {safe}")

    def _start_tool_log(self, title: str) -> None:
        safe_title = sanitize_text(title or "tool")
        if (
            self._tool_log_title.lstrip("/") == safe_title.lstrip("/")
            and self._tool_log_lines
        ):
            self._tool_log_title = safe_title
            self.query_one("#tool-log", RichLog).display = True
            return
        self._tool_log_title = safe_title
        self._tool_log_finished = False
        self._tool_log_lines = []
        log = self.query_one("#tool-log", RichLog)
        log.display = True
        log.clear()
        self._append_tool_log(f"== {safe_title} live output ==")

    def _finish_tool_log(self, state: str) -> None:
        if not self._tool_log_title or self._tool_log_finished:
            return
        self._append_tool_log(f"== {self._tool_log_title} {sanitize_text(state)} ==")
        self._tool_log_finished = True

    def _append_tool_result(self, result: str) -> None:
        safe = sanitize_text(result)
        first_line = safe.splitlines()[0] if safe.splitlines() else "tool result"
        if not self._tool_log_title:
            self._start_tool_log(first_line)
        for line in safe.splitlines() or [safe]:
            self._append_tool_log(line)

    def _is_domain_tool(self, tool_name: str) -> bool:
        return tool_name.lstrip("/") in DOMAIN_TOOLS

    def _append_tool_log(self, line: str) -> None:
        safe_line = sanitize_text(line)
        self._tool_log_lines.append(safe_line)
        truncated = False
        if len(self._tool_log_lines) > self.TOOL_LOG_LIMIT:
            self._tool_log_lines = self._tool_log_lines[-self.TOOL_LOG_LIMIT :]
            truncated = True
        log = self.query_one("#tool-log", RichLog)
        log.display = True
        if truncated:
            self._redraw_tool_log()
        else:
            log.write(self._tool_log_line_renderable(safe_line))

    def _redraw_tool_log(self) -> None:
        log = self.query_one("#tool-log", RichLog)
        log.clear()
        log.write(Text("... older tool output trimmed ...", style="#7a7a7a"))
        for line in self._tool_log_lines:
            log.write(self._tool_log_line_renderable(line))

    def _tool_log_line_renderable(self, line: str) -> Text:
        style = "#9f9f9f"
        if line.startswith("=="):
            style = "bold #f4bf4f"
        elif line.startswith("!"):
            style = "#ff8a8a"
        elif (
            line.startswith("+") or "ready" in line.lower() or "written" in line.lower()
        ):
            style = "#62e884"
        elif line.startswith(">"):
            style = "#b8b8b8"
        return Text(line, style=style)

    def _append_runner_event_to_tool_log(self, event: TuiEvent) -> None:
        if not event.type.startswith(
            (
                "command.",
                "review.",
                "sarif.",
                "index.",
                "triage.",
                "security_report.",
                "context.",
                "log.",
            )
        ):
            return
        if event.type == "command.started":
            command = self._command_from_message(event.message) or event.message
            self._start_tool_log(f"/{command}")
        line = self._tool_log_line_for_event(event)
        if line:
            self._append_tool_log(line)

    def _tool_log_line_for_event(self, event: TuiEvent) -> str:
        payload = event.payload or {}
        if event.type == "command.accepted":
            return f"> {sanitize_text(event.message)}"
        if event.type == "command.started":
            return f"> {sanitize_text(event.message)}"
        if event.type == "command.finished":
            return f"+ {sanitize_text(event.message)}"
        if event.type == "command.failed":
            return f"! {sanitize_text(event.message)}"
        if event.type == "command.progress":
            progress = self._progress_text()
            suffix = f" {progress}" if progress else ""
            return f"> {sanitize_text(event.message)}{suffix}"
        if event.type in {
            "review.file.started",
            "review.file.finished",
            "review.file.skipped",
        }:
            raw_path = str(
                payload.get("current_file") or payload.get("path") or event.message
            )
            path = self._display_path(raw_path)
            progress = self._progress_text()
            suffix = f" {progress}" if progress else ""
            action = {
                "review.file.started": "reviewing",
                "review.file.finished": "reviewed",
                "review.file.skipped": "skipped",
            }[event.type]
            return f"> {action} {path}{suffix}".strip()
        if event.type == "review.result.recorded":
            count = int(payload.get("finding_count") or 0)
            path = self._display_path_from_message(event.message)
            return f"> recorded {path} findings {count}"
        if event.type == "review.finding.emitted":
            return f"! finding: {sanitize_text(event.message)}"
        if event.type.startswith("sarif."):
            return f"+ {sanitize_text(event.message)}"
        if event.type.startswith("index."):
            return f"> {sanitize_text(event.message)}"
        if event.type.startswith("triage."):
            progress = self._progress_text()
            suffix = f" {progress}" if progress else ""
            return f"> {sanitize_text(event.message)}{suffix}"
        if event.type.startswith("security_report."):
            return f"> {sanitize_text(event.message)}"
        if event.type.startswith("context."):
            return f"> {sanitize_text(event.message)}"
        if event.type == "log.message":
            return sanitize_text(event.message)
        return ""

    def _project_label(self) -> str:
        artifacts = getattr(self.runner, "artifacts", None)
        raw_path = getattr(artifacts, "codebase_path", "") or os.getcwd()
        try:
            path = Path(str(raw_path)).expanduser().resolve()
        except OSError:
            path = Path(str(raw_path)).expanduser()
        return path.name or path.as_posix()

    def _provider_label(self) -> str:
        name = self.startup_state.provider_name or "provider"
        model = self.startup_state.model or "model"
        return f"{name} {model}"

    def _onboarding_text(self) -> str:
        context = self.startup_state.context_status
        if context in {"missing", "unknown", ""}:
            return "Run /init to let Metis inspect this project, or ask a question to start."
        return "Ask Metis or type /help for slash commands."

    def _status_report(self) -> str:
        state = self.startup_state
        artifacts = getattr(self.runner, "artifacts", None)
        project_root = getattr(artifacts, "codebase_path", "") or os.getcwd()
        endpoint = state.base_url or "default provider endpoint"
        api_key_present = any(
            os.environ.get(name)
            for name in (
                "OPENAI_API_KEY",
                "AZURE_OPENAI_API_KEY",
                "METIS_OPENAI_API_KEY",
            )
        )
        tool_names = "project_tree, list_dir, read_file, file_slice, search_text, find_file, index, review_code, review_file, review_patch, triage, security_report"
        return "\n".join(
            (
                "Status",
                f"Provider: {state.provider_name or 'unknown'} ({state.provider_status})",
                f"Model: {state.model or 'unknown'}",
                f"Endpoint: {endpoint}",
                f"API key present: {'yes' if api_key_present else 'no'}",
                f"Chat: {'ready' if state.chat_enabled and self.chat_session is not None else 'disabled'}",
                f"Context: {state.context_status or 'unknown'}",
                f"Project root: {project_root}",
                f"Executable: {shutil.which('metis') or 'not found on PATH'}",
                f"Python: {sys.executable}",
                f"Tools: {tool_names}",
            )
        )

    def _refresh_startup_text(self) -> None:
        self.query_one("#startup", Static).update(Text(self._startup_text()))
        self.query_one("#connection-status", Static).update(self._connection_text())
        self.query_one("#status", Label).update(self._status_strip_text())

    def _refresh_logo(self, width: int | None = None) -> None:
        logo_width = width or self.width_hint
        self.query_one("#top", Static).update(Text(metis_logo(logo_width)))

    def _set_busy(self, detail: str, *, owner: str) -> None:
        self._activity_owner = owner
        self.query_one("#activity", MetisActivity).set_busy(detail)

    def _set_ready(self, detail: str = "Ready", *, owner: str | None = None) -> None:
        if owner is not None and self._activity_owner != owner:
            return
        self._activity_owner = None
        self.query_one("#activity", MetisActivity).set_ready(detail)

    def _verify_provider(self) -> None:
        def _run() -> None:
            try:
                adapter = TuiChatModelAdapter(self.runner.engine)
                check = ProviderVerifier(adapter).verify()
                message = check.message
                event_type = "provider.ready" if check.ready else "provider.failed"
                level = "info" if check.ready else "warning"
            except Exception as exc:
                message = sanitize_text(exc)
                event_type = "provider.failed"
                level = "warning"
            if level == "info":
                self.runner._emit(event_type, "provider", message, level="info")
            else:
                self.runner._emit(event_type, "provider", message, level="warning")

        self.run_worker(_run, thread=True, exclusive=False, name="metis-provider-check")

    def _can_verify_provider(self) -> bool:
        return (
            self.startup_state.stage == "ready"
            and not self.startup_state.provider_ready
            and getattr(getattr(self.runner, "engine", None), "llm_provider", None)
            is not None
        )

    def _ensure_chat_session(self) -> None:
        if self.chat_session is not None:
            return
        engine = getattr(self.runner, "engine", None)
        artifacts = getattr(self.runner, "artifacts", None)
        if engine is None or artifacts is None:
            return
        try:
            self.chat_session = TuiChatSession(
                engine,
                codebase_path=artifacts.codebase_path,
                tool_runner=TuiAgentToolRunner(
                    artifacts.codebase_path,
                    domain_runner=self.runner,
                ),
            )
            self.startup_state = replace(
                self.startup_state,
                context_status=self.chat_session.loaded_context.status,
            )
        except Exception as exc:
            self.startup_state = TuiStartupState.failed(
                stage="chat", error=Exception(sanitize_text(exc))
            )

    def _can_run_ai_init(self) -> bool:
        return self.startup_state.chat_enabled and self.chat_session is not None


def run_tui(engine, args, *, startup_state: TuiStartupState | None = None) -> None:
    runner = TuiDomainRunner(engine, codebase_path=args.codebase_path)
    if startup_state is None:
        startup_state = TuiStartupState.ready(engine, {})
    MetisTuiApp(runner, startup_state=startup_state).run()
