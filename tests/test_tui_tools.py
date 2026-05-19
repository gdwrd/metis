# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.tui.tools import TuiAgentToolPolicy, TuiAgentToolRunner


class _ArtifactPaths:
    def __init__(self, base):
        self.review_sarif = base / "results" / "tui" / "run" / "review.sarif"
        self.triage_sarif = base / "results" / "tui" / "run" / "triage.sarif"
        self.security_report = base / "results" / "tui" / "run" / "security-report.md"


class _Artifacts:
    def __init__(self, base):
        self.paths = _ArtifactPaths(base)


class _DomainRunner:
    def __init__(self, base):
        self.artifacts = _Artifacts(base)
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        self.artifacts.paths.review_sarif.parent.mkdir(parents=True, exist_ok=True)
        if request.name == "security_report":
            self.artifacts.paths.security_report.write_text("report", encoding="utf-8")
        else:
            self.artifacts.paths.review_sarif.write_text("sarif", encoding="utf-8")


class _LoggingArtifacts(_Artifacts):
    def __init__(self, base):
        super().__init__(base)
        self.log_path = (
            base / "results" / "tui" / "run" / "commands" / "001-review_code.jsonl"
        )

    @property
    def manifest(self):
        return {"commands": [{"log": str(self.log_path)}]}


class _LoggingDomainRunner(_DomainRunner):
    def __init__(self, base):
        super().__init__(base)
        self.artifacts = _LoggingArtifacts(base)

    def execute(self, request):
        super().execute(request)
        self.artifacts.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts.log_path.write_text(
            "\n".join(
                [
                    '{"type":"command.started","message":"Started /review_code"}',
                    '{"type":"sarif.review.written","message":"Review SARIF written"}',
                ]
            ),
            encoding="utf-8",
        )


def test_agent_tool_policy_rejects_unsafe_tool_names(tmp_path):
    policy = TuiAgentToolPolicy(tmp_path)

    with pytest.raises(ValueError, match="not allowed"):
        policy.validate_tool("shell")
    with pytest.raises(ValueError, match="Unknown"):
        policy.validate_tool("download")


def test_agent_tool_policy_rejects_path_escape(tmp_path):
    policy = TuiAgentToolPolicy(tmp_path)

    with pytest.raises(ValueError, match="Absolute"):
        policy.validate_path(str(tmp_path / "a.py"))
    with pytest.raises(ValueError, match="Parent"):
        policy.validate_path("../a.py")


def test_agent_tool_policy_rejects_symlink_escape(tmp_path):
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(outside)
    policy = TuiAgentToolPolicy(tmp_path)

    with pytest.raises(ValueError, match="escapes"):
        policy.validate_path("link.txt")


def test_agent_tool_runner_exposes_project_tree_and_read_file(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    runner = TuiAgentToolRunner(tmp_path)

    tree = runner.run("project_tree", path=".", max_depth=2)
    content = runner.run("read_file", path="src/main.py")

    assert "src/" in tree
    assert "main.py" in tree
    assert "print('hello')" in content
    assert str(tmp_path) in runner.instructions()


def test_agent_tool_runner_project_tree_skips_symlinked_directory_escape(tmp_path):
    outside = tmp_path.parent / "outside-tree"
    outside.mkdir()
    (outside / "secret.py").write_text("leak\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    runner = TuiAgentToolRunner(tmp_path)

    tree = runner.run("project_tree", path=".", max_depth=2)

    assert "src/" in tree
    assert "main.py" in tree
    assert "linked" not in tree
    assert "secret.py" not in tree


def test_agent_tool_runner_supports_search_and_file_slice(tmp_path):
    (tmp_path / "app.py").write_text("alpha\nneedle\nomega\n", encoding="utf-8")
    runner = TuiAgentToolRunner(tmp_path)

    assert "needle" in runner.run("search_text", pattern="needle", path=".")
    assert runner.run("file_slice", path="app.py", start_line=2, end_line=2) == "needle"


def test_agent_tool_runner_executes_review_code_and_copies_sarif_output(tmp_path):
    domain = _DomainRunner(tmp_path)
    runner = TuiAgentToolRunner(tmp_path, domain_runner=domain)

    result = runner.run("review_code", output_file="results/review.sarif")

    assert domain.requests[0].name == "review_code"
    assert domain.requests[0].args == ()
    assert (tmp_path / "results" / "review.sarif").read_text(
        encoding="utf-8"
    ) == "sarif"
    assert "default_sarif=" in result
    assert "output_file=" in result


def test_agent_tool_runner_includes_domain_log_tail(tmp_path):
    domain = _LoggingDomainRunner(tmp_path)
    runner = TuiAgentToolRunner(tmp_path, domain_runner=domain)

    result = runner.run("review_code", output_file="results/review.sarif")

    assert "log_file=" in result
    assert "log_tail:" in result
    assert "command.started: Started /review_code" in result
    assert "sarif.review.written: Review SARIF written" in result


def test_agent_tool_runner_normalizes_domain_input_paths_to_codebase(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    domain = _DomainRunner(tmp_path)
    runner = TuiAgentToolRunner(tmp_path, domain_runner=domain)

    runner.run("review_file", path="src/main.py")

    assert domain.requests[0].args == (str(tmp_path / "src" / "main.py"),)


def test_agent_tool_runner_rejects_non_sarif_domain_output(tmp_path):
    domain = _DomainRunner(tmp_path)
    runner = TuiAgentToolRunner(tmp_path, domain_runner=domain)

    with pytest.raises(ValueError, match=".sarif"):
        runner.run("review_code", output_file="results/review.json")


def test_agent_tool_runner_rejects_domain_output_outside_results(tmp_path):
    domain = _DomainRunner(tmp_path)
    runner = TuiAgentToolRunner(tmp_path, domain_runner=domain)

    with pytest.raises(ValueError, match="under results"):
        runner.run("security_report", output_file="README.md")


def test_agent_tool_runner_executes_security_report_and_copies_markdown(tmp_path):
    triage = tmp_path / "results" / "triage.sarif"
    triage.parent.mkdir()
    triage.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
    domain = _DomainRunner(tmp_path)
    runner = TuiAgentToolRunner(tmp_path, domain_runner=domain)

    result = runner.run(
        "security_report",
        path="results/triage.sarif",
        output_file="results/security-report.md",
    )

    assert domain.requests[0].name == "security_report"
    assert domain.requests[0].args == (str(triage),)
    assert (tmp_path / "results" / "security-report.md").read_text(
        encoding="utf-8"
    ) == "report"
    assert "default_report=" in result
    assert "output_file=" in result


def test_agent_tool_runner_rejects_non_markdown_security_report_output(tmp_path):
    domain = _DomainRunner(tmp_path)
    runner = TuiAgentToolRunner(tmp_path, domain_runner=domain)

    with pytest.raises(ValueError, match=".md"):
        runner.run("security_report", output_file="results/security-report.sarif")
