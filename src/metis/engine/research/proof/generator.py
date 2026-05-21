# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from metis.engine.research.models import (
    EvidenceKind,
    EvidenceLedgerEntry,
    EvidenceStatus,
    FlowStep,
    Hypothesis,
    HypothesisStatus,
    SourceTrust,
    utc_now,
)

_STATIC_SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".rs",
    ".sv",
    ".svh",
    ".v",
    ".vh",
}
_HARDWARE_EXTENSIONS = {".sv", ".svh", ".v", ".vh"}
_PYTHON_UNSAFE_CALLS = {
    "__import__",
    "compile",
    "eval",
    "exec",
    "open",
    "os.remove",
    "os.rmdir",
    "os.system",
    "pathlib.Path.unlink",
    "requests.delete",
    "requests.get",
    "requests.patch",
    "requests.post",
    "requests.put",
    "shutil.rmtree",
    "socket.socket",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.run",
}
_PYTHON_UNSAFE_NODES = (
    ast.AsyncFor,
    ast.AsyncWith,
    ast.Await,
    ast.Delete,
    ast.Import,
    ast.ImportFrom,
    ast.Raise,
    ast.Try,
    ast.With,
    ast.Yield,
    ast.YieldFrom,
)


@dataclass(frozen=True)
class ProofDecision:
    hypothesis_id: str
    status: str
    reason: str | None = None
    artifact_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class LocalProofRunResult:
    hypotheses: list[Hypothesis]
    artifact_paths: list[str] = field(default_factory=list)
    decisions: list[ProofDecision] = field(default_factory=list)

    @property
    def metric_summary(self) -> dict[str, object]:
        return {
            "generated": sum(
                1 for decision in self.decisions if decision.status == "generated"
            ),
            "skipped": sum(
                1 for decision in self.decisions if decision.status == "skipped"
            ),
            "refused": sum(
                1 for decision in self.decisions if decision.status == "refused"
            ),
            "decisions": [
                {
                    "hypothesis_id": decision.hypothesis_id,
                    "status": decision.status,
                    "reason": decision.reason,
                    "artifact_paths": list(decision.artifact_paths),
                }
                for decision in self.decisions
            ],
        }


class LocalProofGenerator:
    """Generate bounded local proof artifacts for proven research hypotheses."""

    def __init__(self, repository) -> None:
        self._repository = repository

    def generate_for_hypotheses(
        self,
        hypotheses: list[Hypothesis],
        *,
        root: str | os.PathLike[str],
        proofs_dir: str | os.PathLike[str] | None = None,
    ) -> LocalProofRunResult:
        root_path = Path(root).resolve()
        output_root = Path(
            proofs_dir or self._repository.get_research_proofs_dir()
        ).resolve()
        self._require_inside_codebase(output_root, purpose="Proof output directory")

        updated: list[Hypothesis] = []
        artifact_paths: list[str] = []
        decisions: list[ProofDecision] = []
        for hypothesis in hypotheses:
            generated = self._generate_one(
                hypothesis,
                root_path=root_path,
                output_root=output_root,
            )
            updated.append(generated.hypothesis)
            artifact_paths.extend(generated.artifact_paths)
            decisions.append(generated.decision)
        return LocalProofRunResult(
            hypotheses=updated,
            artifact_paths=artifact_paths,
            decisions=decisions,
        )

    def _generate_one(
        self,
        hypothesis: Hypothesis,
        *,
        root_path: Path,
        output_root: Path,
    ) -> "_GeneratedProof":
        if hypothesis.status != HypothesisStatus.PROVEN:
            return _GeneratedProof(
                hypothesis=_with_no_proof_evidence(
                    hypothesis,
                    reason=f"status is {hypothesis.status.value}",
                ),
                decision=ProofDecision(
                    hypothesis_id=hypothesis.id,
                    status="skipped",
                    reason=f"status is {hypothesis.status.value}",
                ),
            )

        refusal = self._refusal_reason(hypothesis)
        if refusal:
            return _GeneratedProof(
                hypothesis=_with_no_proof_evidence(hypothesis, reason=refusal),
                decision=ProofDecision(
                    hypothesis_id=hypothesis.id,
                    status="refused",
                    reason=refusal,
                ),
            )

        location = _primary_location(hypothesis)
        if location is None or not location.file or not location.symbol:
            reason = "missing source location or symbol"
            return _GeneratedProof(
                hypothesis=_with_no_proof_evidence(hypothesis, reason=reason),
                decision=ProofDecision(
                    hypothesis_id=hypothesis.id,
                    status="refused",
                    reason=reason,
                ),
            )

        safe_id = _safe_hypothesis_dir_name(hypothesis.id)
        if safe_id is None:
            reason = "hypothesis id is not safe for a proof artifact path"
            return _GeneratedProof(
                hypothesis=_with_no_proof_evidence(hypothesis, reason=reason),
                decision=ProofDecision(
                    hypothesis_id=hypothesis.id,
                    status="refused",
                    reason=reason,
                ),
            )

        try:
            source_path = self._resolve_source(root_path, location.file)
        except ValueError as exc:
            reason = str(exc)
            return _GeneratedProof(
                hypothesis=_with_no_proof_evidence(hypothesis, reason=reason),
                decision=ProofDecision(
                    hypothesis_id=hypothesis.id,
                    status="refused",
                    reason=reason,
                ),
            )

        source_ref = self._relative_to_codebase(source_path)
        source_suffix = source_path.suffix.lower()
        if source_suffix != ".py" and source_suffix not in _STATIC_SOURCE_EXTENSIONS:
            reason = (
                "only Python, native, and hardware static local proofs "
                "are currently supported"
            )
            return _GeneratedProof(
                hypothesis=_with_no_proof_evidence(hypothesis, reason=reason),
                decision=ProofDecision(
                    hypothesis_id=hypothesis.id,
                    status="refused",
                    reason=reason,
                ),
            )

        target_dir = (output_root / safe_id).resolve()
        self._require_inside_codebase(target_dir, purpose="Proof artifact directory")
        _require_inside(target_dir, output_root, purpose="Proof artifact directory")
        target_dir.mkdir(parents=True, exist_ok=True)
        if source_path.suffix == ".py":
            artifacts = self._write_python_proofs(
                hypothesis,
                target_dir=target_dir,
                source_path=source_path,
                source_ref=source_ref,
                location=location,
            )
        else:
            artifacts = self._write_static_source_proofs(
                hypothesis,
                target_dir=target_dir,
                source_path=source_path,
                source_ref=source_ref,
                location=location,
            )

        if not artifacts:
            reason = "no safe local proof artifact template matched"
            return _GeneratedProof(
                hypothesis=_with_no_proof_evidence(hypothesis, reason=reason),
                decision=ProofDecision(
                    hypothesis_id=hypothesis.id,
                    status="refused",
                    reason=reason,
                ),
            )

        evidence_entries = [
            EvidenceLedgerEntry(
                hypothesis_id=hypothesis.id,
                obligation="proof_artifact",
                status=EvidenceStatus.SATISFIED,
                kind=EvidenceKind.PROOF_ARTIFACT,
                claim=artifact.claim,
                evidence=[
                    artifact.ref,
                    f"run: python -m pytest {artifact.ref}",
                ],
                file=artifact.ref,
                symbol=location.symbol,
                tool="local_proof_generator",
                tool_input=hypothesis.id,
                tool_output_excerpt=artifact.tool_output_excerpt,
                source_trust=SourceTrust.TEST,
            )
            for artifact in artifacts
        ]
        updated = hypothesis.model_copy(
            update={
                "evidence": [*hypothesis.evidence, *evidence_entries],
                "updated_at": utc_now(),
            }
        )
        return _GeneratedProof(
            hypothesis=updated,
            artifact_paths=[str(artifact.path) for artifact in artifacts],
            decision=ProofDecision(
                hypothesis_id=hypothesis.id,
                status="generated",
                artifact_paths=tuple(artifact.ref for artifact in artifacts),
            ),
        )

    def _write_python_proofs(
        self,
        hypothesis: Hypothesis,
        *,
        target_dir: Path,
        source_path: Path,
        source_ref: str,
        location: FlowStep,
    ) -> list["_ProofArtifact"]:
        symbol = location.symbol or ""
        artifacts: list[_ProofArtifact] = []
        static_path = target_dir / "test_static_proof.py"
        static_ref = self._relative_to_codebase(static_path)
        static_depth = len(Path(static_ref).parts) - 1
        static_path.write_text(
            _python_static_trace_template(
                source_ref=source_ref,
                repo_root_parent_depth=static_depth,
                symbol=symbol,
                expected_guard=str(hypothesis.expected_guard or ""),
                route=str(hypothesis.source or ""),
            ),
            encoding="utf-8",
        )
        artifacts.append(
            _ProofArtifact(
                path=static_path,
                ref=static_ref,
                claim=(
                    "Generated a safe local pytest static-trace proof for the "
                    f"missing guard on {location.symbol}."
                ),
                tool_output_excerpt=(
                    "Static proof parses the local source file and asserts that "
                    "the registered route lacks the expected guard."
                ),
            )
        )

        if _supports_python_mocked_handler(source_path, symbol):
            mocked_path = target_dir / "test_mocked_handler_proof.py"
            mocked_ref = self._relative_to_codebase(mocked_path)
            mocked_depth = len(Path(mocked_ref).parts) - 1
            mocked_path.write_text(
                _python_mocked_handler_template(
                    source_ref=source_ref,
                    repo_root_parent_depth=mocked_depth,
                    symbol=symbol,
                    expected_guard=str(hypothesis.expected_guard or ""),
                    route=str(hypothesis.source or ""),
                ),
                encoding="utf-8",
            )
            artifacts.append(
                _ProofArtifact(
                    path=mocked_path,
                    ref=mocked_ref,
                    claim=(
                        "Generated a safe mocked-handler pytest proof for the "
                        f"missing guard on {location.symbol}."
                    ),
                    tool_output_excerpt=(
                        "Mocked-handler proof compiles only the target function "
                        "body with local stubs and verifies it is reachable "
                        "without the expected guard decorator."
                    ),
                )
            )
        return artifacts

    def _write_static_source_proofs(
        self,
        hypothesis: Hypothesis,
        *,
        target_dir: Path,
        source_path: Path,
        source_ref: str,
        location: FlowStep,
    ) -> list["_ProofArtifact"]:
        symbol = location.symbol or ""
        artifact_path = target_dir / "test_static_source_proof.py"
        artifact_ref = self._relative_to_codebase(artifact_path)
        repo_root_parent_depth = len(Path(artifact_ref).parts) - 1
        artifact_path.write_text(
            _static_source_proof_template(
                source_ref=source_ref,
                repo_root_parent_depth=repo_root_parent_depth,
                symbol=symbol,
                line=location.line or 1,
                language=_source_language(source_path),
                source_marker=_safe_marker(hypothesis.source),
                sink_marker=_safe_marker(hypothesis.sink),
                asset_marker=_safe_marker(hypothesis.asset),
                forbidden_guard_markers=_guard_markers_for(hypothesis),
            ),
            encoding="utf-8",
        )
        return [
            _ProofArtifact(
                path=artifact_path,
                ref=artifact_ref,
                claim=(
                    "Generated a safe local pytest static-source proof for the "
                    f"missing guard on {location.symbol}."
                ),
                tool_output_excerpt=(
                    "Static source proof extracts the local symbol body and "
                    "asserts that source/sink markers are present while known "
                    "guard markers are absent."
                ),
            )
        ]

    def _refusal_reason(self, hypothesis: Hypothesis) -> str | None:
        if not hypothesis.expected_guard or not hypothesis.missing_guard:
            return "only missing-guard proof artifacts are currently supported"
        text = " ".join(
            str(value or "")
            for value in (
                hypothesis.source,
                hypothesis.sink,
                hypothesis.asset,
                hypothesis.impact,
            )
        ).lower()
        if ("http://" in text or "https://" in text) and not any(
            host in text for host in ("localhost", "127.0.0.1", "::1")
        ):
            return "proof would reference a non-local network target"
        if any(term in text for term in ("credential", "password", "secret", "token")):
            return "proof would involve credential or secret-bearing material"
        if any(
            term in text
            for term in ("callback_url", "callback url", "webhook", "persistence")
        ):
            return "proof would risk persistence or callback behavior"
        return None

    def _resolve_source(self, root_path: Path, file_name: str) -> Path:
        raw_path = Path(file_name)
        base_path = Path(self._repository._config.codebase_path).resolve()
        candidates: list[Path] = []
        if raw_path.is_absolute():
            candidates.append(raw_path)
        else:
            candidates.extend((root_path / raw_path, base_path / raw_path))
            parts = raw_path.parts
            if parts and parts[0] == root_path.name and len(parts) > 1:
                candidates.append(root_path / Path(*parts[1:]))
            if parts and parts[0] == base_path.name and len(parts) > 1:
                without_base = Path(*parts[1:])
                candidates.append(base_path / without_base)
                without_base_parts = without_base.parts
                if (
                    without_base_parts
                    and without_base_parts[0] == root_path.name
                    and len(without_base_parts) > 1
                ):
                    candidates.append(root_path / Path(*without_base_parts[1:]))

        seen: set[Path] = set()
        matches: list[Path] = []
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                resolved.relative_to(root_path)
            except ValueError:
                continue
            if resolved.is_file():
                matches.append(resolved)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError("Proof source path is ambiguous inside research root")
        raise ValueError("Proof source path could not be resolved inside research root")

    def _relative_to_codebase(self, path: Path) -> str:
        base_path = Path(self._repository._config.codebase_path).resolve()
        return path.resolve().relative_to(base_path).as_posix()

    def _require_inside_codebase(self, path: Path, *, purpose: str) -> None:
        base_path = Path(self._repository._config.codebase_path).resolve()
        try:
            path.resolve().relative_to(base_path)
        except ValueError as exc:
            raise ValueError(
                f"{purpose} must use a path inside the configured codebase path: "
                f"{base_path}"
            ) from exc


@dataclass(frozen=True)
class _GeneratedProof:
    hypothesis: Hypothesis
    decision: ProofDecision
    artifact_paths: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _ProofArtifact:
    path: Path
    ref: str
    claim: str
    tool_output_excerpt: str


def _primary_location(hypothesis: Hypothesis) -> FlowStep | None:
    if hypothesis.locations:
        return hypothesis.locations[0]
    if hypothesis.path:
        return hypothesis.path[0]
    return None


def _safe_hypothesis_dir_name(hypothesis_id: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", hypothesis_id):
        return None
    if ".." in hypothesis_id or "/" in hypothesis_id or "\\" in hypothesis_id:
        return None
    return hypothesis_id


def _with_no_proof_evidence(hypothesis: Hypothesis, *, reason: str) -> Hypothesis:
    entry = EvidenceLedgerEntry(
        hypothesis_id=hypothesis.id,
        obligation="proof_artifact",
        status=EvidenceStatus.NOT_APPLICABLE,
        kind=EvidenceKind.NEGATIVE_EVIDENCE,
        claim=f"No local proof artifact generated: {reason}",
        evidence=[f"reason={reason}"],
        file=_decision_file_for(hypothesis),
        line=_decision_line_for(hypothesis),
        symbol=_decision_symbol_for(hypothesis),
        tool="local_proof_generator",
        tool_input=hypothesis.id,
        source_trust=SourceTrust.TOOL_OUTPUT,
    )
    return hypothesis.model_copy(
        update={"evidence": [*hypothesis.evidence, entry], "updated_at": utc_now()}
    )


def _decision_file_for(hypothesis: Hypothesis) -> str | None:
    location = _primary_location(hypothesis)
    return location.file if location is not None else None


def _decision_line_for(hypothesis: Hypothesis) -> int | None:
    location = _primary_location(hypothesis)
    return location.line if location is not None else None


def _decision_symbol_for(hypothesis: Hypothesis) -> str | None:
    location = _primary_location(hypothesis)
    return location.symbol if location is not None else None


def _require_inside(path: Path, root: Path, *, purpose: str) -> None:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{purpose} must stay inside {root.resolve()}") from exc


def _supports_python_mocked_handler(source_path: Path, symbol: str) -> bool:
    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return False
    function = _find_python_function_node(tree, symbol)
    if function is None or isinstance(function, ast.AsyncFunctionDef):
        return False
    return _python_function_body_is_safe_for_mock(function)


def _find_python_function_node(
    tree: ast.AST,
    symbol: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if node.name == symbol:
                return node
    return None


def _python_function_body_is_safe_for_mock(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    body_nodes = [child for statement in function.body for child in ast.walk(statement)]
    for node in body_nodes:
        if isinstance(node, _PYTHON_UNSAFE_NODES):
            return False
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return False
            call_name = _python_call_name(node.func)
            if call_name in _PYTHON_UNSAFE_CALLS:
                return False
    return True


def _python_call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _source_language(source_path: Path) -> str:
    suffix = source_path.suffix.lower()
    if suffix in _HARDWARE_EXTENSIONS:
        return "hardware"
    return "native"


def _safe_marker(value: object | None) -> str:
    text = str(value or "")
    return "" if text.lower() == "unknown" else text


def _guard_markers_for(hypothesis: Hypothesis) -> tuple[str, ...]:
    vulnerability_class = str(hypothesis.vulnerability_class or "")
    expected_guard = str(hypothesis.expected_guard or "").lower()
    if vulnerability_class == "CWE-416" or "post-free" in expected_guard:
        return (
            " = null",
            "= null",
            "=null",
            " = nullptr",
            "= nullptr",
            "=nullptr",
            "refcount",
            "ownership",
            "lock",
        )
    if vulnerability_class == "CWE-1262" or "privilege" in expected_guard:
        return (
            "privileged",
            "secure_state",
            "lifecycle",
            "locked",
            "authorized",
            "allow_debug",
            "check_",
            "validate",
            "permission",
        )
    return tuple(
        item
        for item in re.split(r"[^A-Za-z0-9_]+", expected_guard)
        if len(item) >= 4
    )


def _python_static_trace_template(
    *,
    source_ref: str,
    repo_root_parent_depth: int,
    symbol: str,
    expected_guard: str,
    route: str,
) -> str:
    return f'''# Generated by Metis. Safe local pytest artifact; no network or live target use.

from __future__ import annotations

import ast
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[{repo_root_parent_depth}]
TARGET_FILE = REPO_ROOT / {source_ref!r}
TARGET_SYMBOL = {symbol!r}
EXPECTED_GUARD = {expected_guard!r}
EXPECTED_ROUTE = {route!r}


def test_missing_expected_guard_static_trace():
    source = TARGET_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(TARGET_FILE))
    function = _find_function(tree, TARGET_SYMBOL)
    decorators = [_decorator_name(item) for item in function.decorator_list]
    routes = [_route_path(item) for item in function.decorator_list]

    assert EXPECTED_ROUTE in routes
    assert EXPECTED_GUARD not in decorators


def _find_function(tree, symbol):
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == symbol:
            return node
    raise AssertionError(f"Function {{symbol}} not found in {{TARGET_FILE}}")


def _decorator_name(node):
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _decorator_name(node.value)
        return f"{{parent}}.{{node.attr}}" if parent else node.attr
    return None


def _route_path(node):
    if not isinstance(node, ast.Call):
        return None
    name = _decorator_name(node.func)
    if name not in {{"route", "get", "post", "put", "patch", "delete"}}:
        return None
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    for keyword in node.keywords:
        if keyword.arg in {{"path", "rule", "route"}}:
            value = keyword.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
    return None
'''


def _python_mocked_handler_template(
    *,
    source_ref: str,
    repo_root_parent_depth: int,
    symbol: str,
    expected_guard: str,
    route: str,
) -> str:
    return f'''# Generated by Metis. Safe local pytest artifact; no network or live target use.

from __future__ import annotations

import ast
import builtins
import copy
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[{repo_root_parent_depth}]
TARGET_FILE = REPO_ROOT / {source_ref!r}
TARGET_SYMBOL = {symbol!r}
EXPECTED_GUARD = {expected_guard!r}
EXPECTED_ROUTE = {route!r}
UNSAFE_CALL_NAMES = {_PYTHON_UNSAFE_CALLS!r}
GUARD_SENTINEL = object()


def test_mocked_handler_reachable_without_expected_guard():
    source = TARGET_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(TARGET_FILE))
    function = _find_function(tree, TARGET_SYMBOL)
    decorators = [_decorator_name(item) for item in function.decorator_list]
    routes = [_route_path(item) for item in function.decorator_list]

    assert EXPECTED_ROUTE in routes
    assert EXPECTED_GUARD not in decorators
    _assert_safe_function_body(function)

    namespace = _mock_namespace(function)
    compiled = ast.Module(body=[_standalone_function(function)], type_ignores=[])
    ast.fix_missing_locations(compiled)
    exec(compile(compiled, filename="<metis-local-proof>", mode="exec"), namespace)

    handler = namespace[TARGET_SYMBOL]
    args, kwargs = _placeholder_call_args(function)
    result = handler(*args, **kwargs)
    assert result is not GUARD_SENTINEL


def _find_function(tree, symbol):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == symbol:
            return node
    raise AssertionError(f"Function {{symbol}} not found in {{TARGET_FILE}}")


def _assert_safe_function_body(function):
    unsafe_nodes = (
        ast.AsyncFor,
        ast.AsyncWith,
        ast.Await,
        ast.Delete,
        ast.Import,
        ast.ImportFrom,
        ast.Raise,
        ast.Try,
        ast.With,
        ast.Yield,
        ast.YieldFrom,
    )
    body_nodes = [child for statement in function.body for child in ast.walk(statement)]
    for node in body_nodes:
        assert not isinstance(node, unsafe_nodes)
        if isinstance(node, ast.Call):
            assert not isinstance(node.func, ast.Attribute)
            assert _call_name(node.func) not in UNSAFE_CALL_NAMES


def _standalone_function(function):
    node = copy.deepcopy(function)
    node.decorator_list = []
    node.returns = None
    for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
        arg.annotation = None
    if node.args.vararg is not None:
        node.args.vararg.annotation = None
    if node.args.kwarg is not None:
        node.args.kwarg.annotation = None
    return node


def _mock_namespace(function):
    namespace = {{"__builtins__": _safe_builtins()}}
    for name in _loaded_global_names(function):
        namespace[name] = _expected_guard if name == EXPECTED_GUARD else _safe_stub
    return namespace


def _safe_builtins():
    names = ("bool", "dict", "enumerate", "int", "len", "list", "range", "set", "str", "tuple")
    return {{name: getattr(builtins, name) for name in names}}


def _loaded_global_names(function):
    params = _param_names(function)
    builtin_names = set(_safe_builtins())
    names = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in params and node.id not in builtin_names:
                names.add(node.id)
    return names


def _param_names(function):
    names = {{
        arg.arg
        for arg in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
    }}
    if function.args.vararg is not None:
        names.add(function.args.vararg.arg)
    if function.args.kwarg is not None:
        names.add(function.args.kwarg.arg)
    return names


def _placeholder_call_args(function):
    positional = [*function.args.posonlyargs, *function.args.args]
    required_positional = len(positional) - len(function.args.defaults)
    args = ["metis-proof-local" for _ in range(max(required_positional, 0))]
    kwargs = {{
        arg.arg: "metis-proof-local"
        for arg, default in zip(function.args.kwonlyargs, function.args.kw_defaults, strict=True)
        if default is None
    }}
    return args, kwargs


def _expected_guard(*args, **kwargs):
    return GUARD_SENTINEL


def _safe_stub(*args, **kwargs):
    return {{"metis_local_stub": True, "args": args, "kwargs": kwargs}}


def _decorator_name(node):
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _decorator_name(node.value)
        return f"{{parent}}.{{node.attr}}" if parent else node.attr
    return None


def _route_path(node):
    if not isinstance(node, ast.Call):
        return None
    name = _decorator_name(node.func)
    if name not in {{"route", "get", "post", "put", "patch", "delete"}}:
        return None
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    for keyword in node.keywords:
        if keyword.arg in {{"path", "rule", "route"}}:
            value = keyword.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
    return None


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{{parent}}.{{node.attr}}" if parent else node.attr
    return None
'''


def _static_source_proof_template(
    *,
    source_ref: str,
    repo_root_parent_depth: int,
    symbol: str,
    line: int,
    language: str,
    source_marker: str,
    sink_marker: str,
    asset_marker: str,
    forbidden_guard_markers: tuple[str, ...],
) -> str:
    return f'''# Generated by Metis. Safe local pytest artifact; no network or live target use.

from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[{repo_root_parent_depth}]
TARGET_FILE = REPO_ROOT / {source_ref!r}
TARGET_SYMBOL = {symbol!r}
TARGET_LINE = {line!r}
LANGUAGE = {language!r}
SOURCE_MARKER = {source_marker!r}
SINK_MARKER = {sink_marker!r}
ASSET_MARKER = {asset_marker!r}
FORBIDDEN_GUARD_MARKERS = {forbidden_guard_markers!r}


def test_static_source_proof_for_missing_guard():
    source = TARGET_FILE.read_text(encoding="utf-8")
    body = _extract_symbol_body(source)
    body_lower = _strip_comments(body).lower()

    for marker in (SOURCE_MARKER, SINK_MARKER, ASSET_MARKER):
        if marker:
            assert marker.lower() in body_lower
    for marker in FORBIDDEN_GUARD_MARKERS:
        assert marker.lower() not in body_lower


def _extract_symbol_body(source):
    lines = source.splitlines()
    if LANGUAGE == "hardware":
        return _extract_hardware_body(lines)
    return _extract_braced_body(lines)


def _extract_hardware_body(lines):
    start = _find_line(lines, f"module {{TARGET_SYMBOL}}")
    if start is None:
        start = max(TARGET_LINE - 1, 0)
    collected = []
    for line in lines[start:]:
        collected.append(line)
        if line.strip().startswith("endmodule"):
            break
    return "\\n".join(collected)


def _extract_braced_body(lines):
    start = _find_line(lines, TARGET_SYMBOL)
    if start is None:
        start = max(TARGET_LINE - 1, 0)
    collected = []
    depth = 0
    seen_open = False
    for line in lines[start:]:
        collected.append(line)
        depth += line.count("{{") - line.count("}}")
        seen_open = seen_open or "{{" in line
        if seen_open and depth <= 0:
            break
    if not seen_open:
        lower = max(start - 5, 0)
        upper = min(start + 25, len(lines))
        return "\\n".join(lines[lower:upper])
    return "\\n".join(collected)


def _find_line(lines, needle):
    needle = needle.lower()
    for index, line in enumerate(lines):
        if needle in line.lower():
            return index
    return None


def _strip_comments(text):
    text = re.sub(r"/\\*.*?\\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//.*", "", text)
'''
