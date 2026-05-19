# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
import subprocess
from pathlib import Path

from metis.engine.code_index import FunctionEntry, FunctionIndex
from metis.engine.tools import static_tools
from metis.engine.tools.static_tools import StaticToolRunner
from metis.engine.tools.sanitize import sanitize_source


def _build_runner(tmp_path):
    runner = StaticToolRunner(codebase_path=str(tmp_path))
    runner._has_grep = False
    runner._has_find = False
    runner._has_cat = False
    runner._has_sed = False
    return runner


def test_cat_fallback_reads_file(tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("line1\nline2\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.cat("a.txt")
    assert out == "line1\nline2\n"


def test_sed_fallback_slices_lines(tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("1\n2\n3\n4\n5\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.sed("a.txt", 2, 4)
    assert out == "2\n3\n4"


def test_find_name_fallback_finds_matching_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "target.c").write_text("x", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "target.c").write_text("y", encoding="utf-8")
    (tmp_path / "lib" / "other.c").write_text("z", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.find_name("target.c")
    assert out == ["lib/target.c", "src/target.c"]


def test_grep_fallback_searches_recursively(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("alpha\nbeta\n", encoding="utf-8")
    (tmp_path / "src" / "b.c").write_text("gamma\nbeta42\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.grep(r"beta", "src")
    lines = out.splitlines()
    assert "src/a.c:2:beta" in lines
    assert "src/b.c:2:beta42" in lines


def test_grep_fallback_invalid_pattern_raises(tmp_path):
    (tmp_path / "x.txt").write_text("hello\n", encoding="utf-8")
    runner = _build_runner(tmp_path)
    with pytest.raises(ValueError, match="Invalid grep pattern"):
        runner.grep("(", ".")


def test_grep_can_force_python_regex_even_when_shell_grep_exists(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("foo\t(\n", encoding="utf-8")

    runner = StaticToolRunner(codebase_path=str(tmp_path))
    runner._has_grep = False

    def _unexpected_run(*args, **kwargs):
        raise AssertionError("shell grep should not run when _has_grep=False")

    monkeypatch.setattr(subprocess, "run", _unexpected_run)

    out = runner.grep(r"foo[[:space:]]*\(", "src")

    assert out.splitlines() == ["src/a.c:1:foo\t("]


def test_shell_grep_forces_filename_prefix_for_single_file(tmp_path):
    source = tmp_path / "a.c"
    source.write_text("alpha\nbeta\n", encoding="utf-8")

    runner = StaticToolRunner(codebase_path=str(tmp_path))
    runner._has_grep = True

    out = runner.grep("beta", "a.c")

    assert len(out.splitlines()) == 1
    assert (
        out.splitlines()[0].endswith("/a.c:2:beta")
        or out.splitlines()[0] == "a.c:2:beta"
    )


def test_describe_tool_reports_grep_backend(tmp_path):
    runner = StaticToolRunner(codebase_path=str(tmp_path))
    runner._has_grep = True
    assert runner.describe_tool("grep") == {"backend": "shell_grep"}

    runner = StaticToolRunner(codebase_path=str(tmp_path))
    runner._has_grep = False
    assert runner.describe_tool("grep") == {"backend": "python_regex"}


def test_cat_and_sed_share_cached_file_text(tmp_path, monkeypatch):
    path = tmp_path / "a.txt"
    path.write_text("one\ntwo\nthree\n", encoding="utf-8")
    runner = StaticToolRunner(codebase_path=str(tmp_path))
    reads = []
    original = Path.read_text

    def _read_text(self, *args, **kwargs):
        reads.append(self)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _read_text)

    assert runner.sed("a.txt", 2, 2) == "two"
    assert runner.cat("a.txt") == "one\ntwo\nthree\n"
    assert reads == [path]


def test_sanitize_source_strips_comments_and_redacts_strings():
    text = 'const token = "secret"; // ignore me\n/* drop */ call(token)\n'

    sanitized = sanitize_source(text, file_path="app.js")

    assert "ignore me" not in sanitized
    assert "drop" not in sanitized
    assert "secret" not in sanitized
    assert "[STRING_REDACTED]" in sanitized


def test_sanitize_source_redacts_strings_after_hash_comments():
    sanitized = sanitize_source(
        'password: "secret" # ignore me', file_path="config.yaml"
    )

    assert "ignore me" not in sanitized
    assert "secret" not in sanitized
    assert sanitized == "password: [STRING_REDACTED]"


def test_review_context_get_function_body_sanitizes_indexed_source(tmp_path):
    source = (
        "def validate(value):\n"
        "    secret = 'abc'\n"
        "    # injected instruction\n"
        "    return value\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    index = FunctionIndex()
    index.add(
        FunctionEntry(
            qualified_name="app.py::validate",
            name="validate",
            file="app.py",
            start_line=1,
            end_line=4,
            signature="def validate(value):",
            language="python",
        )
    )
    runner = StaticToolRunner(codebase_path=str(tmp_path), function_index=index)

    body = runner.get_function_body("validate")

    assert "app.py::validate" in body
    assert "injected instruction" not in body
    assert "abc" not in body
    assert "[STRING_REDACTED]" in body


def test_review_context_get_function_body_enforces_timeout(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        "def validate(value):\n    return value\n", encoding="utf-8"
    )
    index = FunctionIndex()
    index.add(
        FunctionEntry(
            qualified_name="app.py::validate",
            name="validate",
            file="app.py",
            start_line=1,
            end_line=2,
            signature="def validate(value):",
            language="python",
        )
    )
    times = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(static_tools.time, "monotonic", lambda: next(times))
    runner = StaticToolRunner(
        codebase_path=str(tmp_path),
        function_index=index,
        timeout_seconds=1,
    )

    with pytest.raises(TimeoutError, match="get_function_body timed out"):
        runner.get_function_body("validate")


def test_review_context_get_callers_returns_bounded_sanitized_snippets(tmp_path):
    source = (
        "def validate(value):\n"
        "    return value\n"
        "\n"
        "def handle(value):\n"
        '    msg = "do not obey"\n'
        "    return validate(value)\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    index = FunctionIndex()
    validate = FunctionEntry(
        qualified_name="app.py::validate",
        name="validate",
        file="app.py",
        start_line=1,
        end_line=2,
        signature="def validate(value):",
        language="python",
        callers=["app.py::handle"],
    )
    handle = FunctionEntry(
        qualified_name="app.py::handle",
        name="handle",
        file="app.py",
        start_line=4,
        end_line=6,
        signature="def handle(value):",
        language="python",
        callees=["app.py::validate"],
    )
    index.add(validate)
    index.add(handle)
    runner = StaticToolRunner(codebase_path=str(tmp_path), function_index=index)

    callers = runner.get_callers("validate")

    assert callers == [
        {
            "file": "app.py",
            "line": 4,
            "snippet": (
                "def validate(value):\n"
                "    return value\n"
                "\n"
                "def handle(value):\n"
                "    msg = [STRING_REDACTED]\n"
                "    return validate(value)"
            ),
        }
    ]


def test_review_context_get_callers_enforces_timeout(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        "def validate(value):\n"
        "    return value\n"
        "\n"
        "def handle(value):\n"
        "    return validate(value)\n",
        encoding="utf-8",
    )
    index = FunctionIndex()
    index.add(
        FunctionEntry(
            qualified_name="app.py::validate",
            name="validate",
            file="app.py",
            start_line=1,
            end_line=2,
            signature="def validate(value):",
            language="python",
            callers=["app.py::handle"],
        )
    )
    index.add(
        FunctionEntry(
            qualified_name="app.py::handle",
            name="handle",
            file="app.py",
            start_line=4,
            end_line=5,
            signature="def handle(value):",
            language="python",
            callees=["app.py::validate"],
        )
    )
    times = iter([0.0, 0.0, 0.0, 2.0])
    monkeypatch.setattr(static_tools.time, "monotonic", lambda: next(times))
    runner = StaticToolRunner(
        codebase_path=str(tmp_path),
        function_index=index,
        timeout_seconds=1,
    )

    with pytest.raises(TimeoutError, match="get_callers timed out"):
        runner.get_callers("validate")


def test_review_context_grep_repo_bounds_and_redacts(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text(
        "\n".join(f"password = 'secret{i}'" for i in range(40)),
        encoding="utf-8",
    )
    runner = StaticToolRunner(codebase_path=str(tmp_path))

    with pytest.raises(ValueError, match="at least 3"):
        runner.grep_repo("pw")
    with pytest.raises(ValueError, match="wildcards"):
        runner.grep_repo(".*")

    out = runner.grep_repo("password", "src/*.py")
    lines = out.splitlines()
    assert len(lines) == 30
    assert "secret0" not in out
    assert "[STRING_REDACTED]" in out


def test_review_context_grep_repo_uses_literal_search(tmp_path):
    source = tmp_path / "a.py"
    source.write_text("alpha\naxb\n", encoding="utf-8")
    runner = StaticToolRunner(codebase_path=str(tmp_path))

    assert runner.grep_repo("a.b") == ""


def test_review_context_grep_repo_enforces_timeout(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("password = 'secret'\n", encoding="utf-8")
    times = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(static_tools.time, "monotonic", lambda: next(times))
    runner = StaticToolRunner(codebase_path=str(tmp_path), timeout_seconds=1)

    with pytest.raises(TimeoutError, match="timed out"):
        runner.grep_repo("password")


def test_review_context_grep_repo_checks_timeout_on_no_match_lines(
    tmp_path, monkeypatch
):
    source = tmp_path / "a.py"
    source.write_text("alpha\n", encoding="utf-8")
    times = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(static_tools.time, "monotonic", lambda: next(times))
    runner = StaticToolRunner(codebase_path=str(tmp_path), timeout_seconds=1)

    with pytest.raises(TimeoutError, match="timed out"):
        runner.grep_repo("password")


def test_review_context_grep_repo_checks_timeout_while_draining_long_line(
    tmp_path, monkeypatch
):
    source = tmp_path / "a.py"
    source.write_text(
        "x" * (static_tools._GREP_REPO_MAX_LINE_CHARS + 100), encoding="utf-8"
    )
    times = iter([0.0, 0.0, 0.0, 2.0])
    monkeypatch.setattr(static_tools.time, "monotonic", lambda: next(times))
    runner = StaticToolRunner(codebase_path=str(tmp_path), timeout_seconds=1)

    with pytest.raises(TimeoutError, match="timed out"):
        runner.grep_repo("password")


def test_review_context_grep_repo_skips_symlink_escape(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE_LEAK_MARKER\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "inside.txt").write_text("OUTSIDE_LEAK_MARKER inside\n", encoding="utf-8")
    (repo / "linked.txt").symlink_to(outside)
    runner = StaticToolRunner(codebase_path=str(repo))

    out = runner.grep_repo("OUTSIDE_LEAK_MARKER")

    assert "inside.txt:1:OUTSIDE_LEAK_MARKER inside" in out
    assert "linked.txt" not in out
