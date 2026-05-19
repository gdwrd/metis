# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    finding_id: str
    rule_id: str
    level: str
    message: str
    locations: tuple[str, ...]
    rule_help: str
    properties_text: str
    component: str
    primitive_tags: tuple[str, ...]
    source_tags: tuple[str, ...]
    sink_tags: tuple[str, ...]
    trust_tags: tuple[str, ...]
    score_hint: float
    evidence_text: str


@dataclass(frozen=True, slots=True)
class AttackChainCandidate:
    chain_id: str
    title: str
    attack_families: tuple[str, ...]
    findings: tuple[SecurityFinding, ...]
    relation_reason: str
    score_hint: float
    preconditions: tuple[str, ...] = ()
    postconditions: tuple[str, ...] = ()
    bridge_hooks: tuple[str, ...] = ()
    source_candidate_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AffectedFileSnippet:
    finding_id: str
    path: str
    start_line: int
    end_line: int
    text: str


_PRIMITIVE_SIGNATURES: dict[str, tuple[str, ...]] = {
    "auth_bypass": (
        "authentication bypass",
        "authorization bypass",
        "access control",
        "missing authorization",
        "idor",
        "cwe-862",
        "cwe-863",
        "cwe-639",
    ),
    "command_execution": (
        "rce",
        "remote code execution",
        "command injection",
        "os command",
        "shell",
        "system(",
        "exec(",
        "popen",
        "cwe-78",
    ),
    "sql_injection": (
        "sql injection",
        "sqli",
        "raw sql",
        "query concatenation",
        "cwe-89",
    ),
    "path_traversal": (
        "path traversal",
        "directory traversal",
        "../",
        "cwe-22",
    ),
    "file_access": (
        "arbitrary file",
        "file read",
        "file write",
        "upload",
        "archive extraction",
        "zip slip",
        "cwe-434",
        "cwe-73",
    ),
    "ssrf": ("ssrf", "server-side request forgery", "metadata service", "cwe-918"),
    "deserialization": (
        "deserialization",
        "unserialize",
        "pickle",
        "yaml.load",
        "cwe-502",
    ),
    "template_injection": (
        "template injection",
        "ssti",
        "server-side template",
        "cwe-1336",
    ),
    "xss": ("cross-site scripting", "xss", "script injection", "cwe-79"),
    "csrf": ("csrf", "cross-site request forgery", "cwe-352"),
    "open_redirect": ("open redirect", "redirect", "cwe-601"),
    "secret_exposure": (
        "secret",
        "credential",
        "api key",
        "password",
        "token exposure",
        "cwe-798",
        "cwe-200",
    ),
    "crypto_weakness": (
        "weak crypto",
        "hardcoded key",
        "predictable token",
        "md5",
        "sha1",
        "cwe-327",
    ),
}

_SOURCE_SIGNATURES: dict[str, tuple[str, ...]] = {
    "request_input": (
        "request",
        "query parameter",
        "param",
        "header",
        "cookie",
        "form",
        "user input",
        "attacker-controlled",
    ),
    "file_upload": ("upload", "multipart", "uploaded file", "archive"),
    "network_input": ("socket", "http client", "webhook", "callback url"),
    "database_state": ("database", "db record", "stored value"),
    "environment_config": ("environment", "config", "env var", "setting"),
}

_SINK_SIGNATURES: dict[str, tuple[str, ...]] = {
    "sql_sink": ("sql", "query", "database"),
    "command_sink": ("command", "shell", "system(", "exec(", "popen"),
    "file_sink": ("file", "path", "read", "write", "open(", "unlink", "rename"),
    "network_sink": ("request forgery", "http request", "metadata service", "urlopen"),
    "template_sink": ("template", "render", "jinja", "erb"),
    "deserialization_sink": ("deserialize", "unserialize", "pickle", "yaml.load"),
    "redirect_sink": ("redirect", "location header"),
    "secret_sink": ("secret", "credential", "token", "password"),
}

_TRUST_SIGNATURES: dict[str, tuple[str, ...]] = {
    "unauthenticated": ("unauthenticated", "anonymous", "pre-auth", "without login"),
    "authenticated_user": ("authenticated user", "logged-in user", "session"),
    "admin_required": ("admin", "administrator", "privileged"),
    "local_attacker": ("local attacker", "local user", "filesystem access"),
}

_HIGH_IMPACT_PRIMITIVES = {
    "auth_bypass",
    "command_execution",
    "sql_injection",
    "path_traversal",
    "file_access",
    "ssrf",
    "deserialization",
    "template_injection",
    "secret_exposure",
}


def extract_security_findings(payload: dict[str, Any]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    ordinal = 1
    for run in payload.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        rules = _sarif_rules(run)
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            finding = _security_finding_from_result(ordinal, result, rules)
            findings.append(finding)
            ordinal += 1
    return findings


def build_attack_chain_candidates(
    findings: list[SecurityFinding],
) -> list[AttackChainCandidate]:
    candidates: list[AttackChainCandidate] = []
    seen: set[tuple[str, ...]] = set()
    covered_findings: set[str] = set()

    for component, component_findings in _group_by_component(findings).items():
        component_families = {
            tag
            for finding in component_findings
            for tag in finding.primitive_tags
            if tag in _HIGH_IMPACT_PRIMITIVES
        }
        high_impact_findings = [
            finding
            for finding in component_findings
            if finding.score_hint >= 7.0
            or set(finding.primitive_tags) & _HIGH_IMPACT_PRIMITIVES
        ]
        if len(high_impact_findings) >= 2 and len(component_families) >= 2:
            key = tuple(f.finding_id for f in high_impact_findings)
            seen.add(key)
            preconditions, postconditions, bridge_hooks = _candidate_bridge_metadata(
                high_impact_findings
            )
            candidates.append(
                AttackChainCandidate(
                    chain_id=f"CHAIN-{len(candidates) + 1:03d}",
                    title=f"Multi-Stage Attack Chain in {component}",
                    attack_families=tuple(sorted(component_families)),
                    findings=tuple(high_impact_findings),
                    relation_reason=(
                        f"{len(high_impact_findings)} high-impact findings share "
                        f"component `{component}` across multiple attack primitives."
                    ),
                    score_hint=_candidate_score(high_impact_findings),
                    preconditions=preconditions,
                    postconditions=postconditions,
                    bridge_hooks=bridge_hooks,
                )
            )
        for family, family_findings in _group_by_attack_family(
            component_findings
        ).items():
            if len(family_findings) < 2:
                continue
            key = tuple(f.finding_id for f in family_findings)
            seen.add(key)
            covered_findings.update(key)
            preconditions, postconditions, bridge_hooks = _candidate_bridge_metadata(
                family_findings
            )
            candidates.append(
                AttackChainCandidate(
                    chain_id=f"CHAIN-{len(candidates) + 1:03d}",
                    title=f"{_humanize_family(family)} chain in {component}",
                    attack_families=(family,),
                    findings=tuple(family_findings),
                    relation_reason=(
                        f"{len(family_findings)} findings share component "
                        f"`{component}` and attack family `{family}`."
                    ),
                    score_hint=_candidate_score(family_findings),
                    preconditions=preconditions,
                    postconditions=postconditions,
                    bridge_hooks=bridge_hooks,
                )
            )

    for finding in findings:
        key = (finding.finding_id,)
        if finding.finding_id in covered_findings or key in seen:
            continue
        seen.add(key)
        families = finding.primitive_tags or ("standalone_security_risk",)
        if (
            finding.score_hint >= 7.0
            or set(finding.primitive_tags) & _HIGH_IMPACT_PRIMITIVES
        ):
            relation_reason = (
                "Single high-impact finding preserved as a standalone attack candidate."
            )
        else:
            relation_reason = (
                "Single finding preserved so the report synthesis can downgrade "
                "or dismiss it with evidence instead of silently dropping it."
            )
        preconditions, postconditions, bridge_hooks = _candidate_bridge_metadata(
            [finding]
        )
        candidates.append(
            AttackChainCandidate(
                chain_id=f"CHAIN-{len(candidates) + 1:03d}",
                title=f"Standalone {_humanize_family(families[0])} candidate",
                attack_families=families,
                findings=(finding,),
                relation_reason=relation_reason,
                score_hint=finding.score_hint,
                preconditions=preconditions,
                postconditions=postconditions,
                bridge_hooks=bridge_hooks,
            )
        )

    return _sort_candidates(candidates)


def build_cross_batch_attack_chain_candidates(
    candidates: list[AttackChainCandidate],
    *,
    max_candidates: int = 50,
    max_pair_checks: int = 5000,
) -> list[AttackChainCandidate]:
    joined: list[AttackChainCandidate] = []
    seen: set[tuple[str, ...]] = set()
    ordered = _sort_candidates(candidates)

    pair_queue = _cross_batch_pair_queue(
        ordered,
        max_pair_checks=max_pair_checks,
    )
    for left, right in pair_queue:
        reasons = _bridge_reasons(left, right)
        if not reasons:
            continue
        finding_ids = tuple(
            dict.fromkeys(
                finding.finding_id for finding in (*left.findings, *right.findings)
            )
        )
        if len(finding_ids) < 2 or finding_ids in seen:
            continue
        seen.add(finding_ids)
        findings = _dedupe_findings((*left.findings, *right.findings))
        preconditions, postconditions, bridge_hooks = _candidate_bridge_metadata(
            list(findings)
        )
        joined.append(
            AttackChainCandidate(
                chain_id=f"XCHAIN-{len(joined) + 1:03d}",
                title=f"Cross-Batch Attack Chain: {left.chain_id} + {right.chain_id}",
                attack_families=tuple(
                    sorted(set(left.attack_families) | set(right.attack_families))
                ),
                findings=findings,
                relation_reason="; ".join(reasons),
                score_hint=min(max(left.score_hint, right.score_hint) + 0.75, 10.0),
                preconditions=preconditions,
                postconditions=postconditions,
                bridge_hooks=bridge_hooks,
                source_candidate_ids=(left.chain_id, right.chain_id),
            )
        )
        if len(joined) >= max_candidates:
            return _sort_candidates(joined)
    return _sort_candidates(joined)


def _cross_batch_pair_queue(
    candidates: list[AttackChainCandidate],
    *,
    max_pair_checks: int,
) -> list[tuple[AttackChainCandidate, AttackChainCandidate]]:
    precondition_index: dict[str, list[AttackChainCandidate]] = {}
    for candidate in candidates:
        for precondition in candidate.preconditions:
            precondition_index.setdefault(precondition, []).append(candidate)

    pairs: list[tuple[AttackChainCandidate, AttackChainCandidate]] = []
    seen_pairs: set[tuple[str, str]] = set()

    def add_pair(left: AttackChainCandidate, right: AttackChainCandidate) -> bool:
        if left.chain_id == right.chain_id:
            return True
        key = (
            min(left.chain_id, right.chain_id),
            max(left.chain_id, right.chain_id),
        )
        if key in seen_pairs:
            return True
        if len(pairs) >= max_pair_checks:
            return False
        seen_pairs.add(key)
        pairs.append((left, right))
        return True

    for source in candidates:
        for postcondition in source.postconditions:
            for sink in precondition_index.get(postcondition, []):
                if not add_pair(source, sink):
                    return pairs

    file_control_sources = [
        candidate
        for candidate in candidates
        if set(candidate.postconditions) & {"filesystem_write", "controlled_file_path"}
    ]
    rce_sinks = [
        candidate
        for candidate in candidates
        if set(candidate.attack_families)
        & {"command_execution", "deserialization", "template_injection"}
        or "code_execution" in candidate.postconditions
    ]
    for source in file_control_sources:
        for sink in rce_sinks:
            if not add_pair(source, sink):
                return pairs

    access_sources = [
        candidate
        for candidate in candidates
        if set(candidate.postconditions) & {"authenticated_access", "privileged_access"}
    ]
    privileged_sinks = [
        candidate
        for candidate in candidates
        if set(candidate.preconditions) & {"authenticated_access", "privileged_access"}
    ]
    for source in access_sources:
        for sink in privileged_sinks:
            if not add_pair(source, sink):
                return pairs

    return pairs


def _sort_candidates(
    candidates: list[AttackChainCandidate],
) -> list[AttackChainCandidate]:
    return sorted(
        candidates,
        key=lambda candidate: (
            -candidate.score_hint,
            -len(candidate.findings),
            candidate.chain_id,
        ),
    )


def format_attack_chain_candidate(candidate: AttackChainCandidate) -> str:
    lines = [
        f"Candidate: {candidate.chain_id}",
        f"Title: {candidate.title}",
        f"Score hint: {candidate.score_hint:.1f}/10.0",
        f"Attack families: {', '.join(candidate.attack_families)}",
        f"Relationship: {candidate.relation_reason}",
        "Source candidates: "
        + (", ".join(candidate.source_candidate_ids) or "direct finding group"),
        "Preconditions: " + (", ".join(candidate.preconditions) or "none"),
        "Postconditions: " + (", ".join(candidate.postconditions) or "none"),
        "Bridge hooks: " + (", ".join(candidate.bridge_hooks) or "none"),
        "Affected findings:",
    ]
    for finding in candidate.findings:
        lines.extend(
            [
                f"- {finding.finding_id} {finding.rule_id} "
                f"({finding.level}) at {', '.join(finding.locations) or 'unknown'}",
                f"  Message: {finding.message}",
                f"  Component: {finding.component}",
                f"  Primitive tags: {', '.join(finding.primitive_tags) or 'none'}",
                f"  Source tags: {', '.join(finding.source_tags) or 'none'}",
                f"  Sink tags: {', '.join(finding.sink_tags) or 'none'}",
                f"  Trust tags: {', '.join(finding.trust_tags) or 'none'}",
                f"  Rule help: {finding.rule_help[:1200]}",
                f"  Triage properties: {finding.properties_text[:1600]}",
            ]
        )
    return "\n".join(lines)


def security_finding_to_dict(finding: SecurityFinding) -> dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "level": finding.level,
        "message": finding.message,
        "locations": list(finding.locations),
        "rule_help": finding.rule_help,
        "properties_text": finding.properties_text,
        "component": finding.component,
        "primitive_tags": list(finding.primitive_tags),
        "source_tags": list(finding.source_tags),
        "sink_tags": list(finding.sink_tags),
        "trust_tags": list(finding.trust_tags),
        "score_hint": finding.score_hint,
    }


def attack_chain_candidate_to_dict(
    candidate: AttackChainCandidate,
) -> dict[str, Any]:
    return {
        "chain_id": candidate.chain_id,
        "title": candidate.title,
        "attack_families": list(candidate.attack_families),
        "finding_ids": [finding.finding_id for finding in candidate.findings],
        "relation_reason": candidate.relation_reason,
        "score_hint": candidate.score_hint,
        "preconditions": list(candidate.preconditions),
        "postconditions": list(candidate.postconditions),
        "bridge_hooks": list(candidate.bridge_hooks),
        "source_candidate_ids": list(candidate.source_candidate_ids),
        "findings": [
            security_finding_to_dict(finding) for finding in candidate.findings
        ],
    }


def affected_file_snippet_to_dict(
    snippet: AffectedFileSnippet,
) -> dict[str, Any]:
    return {
        "finding_id": snippet.finding_id,
        "path": snippet.path,
        "start_line": snippet.start_line,
        "end_line": snippet.end_line,
        "text": snippet.text,
    }


def format_affected_file_snippets(snippets: list[AffectedFileSnippet]) -> str:
    if not snippets:
        return ""
    lines = ["Affected file snippets:"]
    for snippet in snippets:
        lines.extend(
            [
                f"- {snippet.finding_id} {snippet.path}:{snippet.start_line}-{snippet.end_line}",
                "```text",
                snippet.text[:3000],
                "```",
            ]
        )
    return "\n".join(lines)


def _candidate_bridge_metadata(
    findings: list[SecurityFinding],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    primitive_tags = {tag for finding in findings for tag in finding.primitive_tags}
    source_tags = {tag for finding in findings for tag in finding.source_tags}
    sink_tags = {tag for finding in findings for tag in finding.sink_tags}
    trust_tags = {tag for finding in findings for tag in finding.trust_tags}
    evidence = "\n".join(finding.evidence_text.lower() for finding in findings)

    preconditions: set[str] = set()
    postconditions: set[str] = set()
    bridge_hooks: set[str] = set()

    if "request_input" in source_tags:
        postconditions.add("attacker_controlled_input")
        bridge_hooks.add("request input can feed downstream sinks")
    if "authenticated_user" in trust_tags:
        preconditions.add("authenticated_access")
    if "admin_required" in trust_tags:
        preconditions.add("privileged_access")
    if "unauthenticated" in trust_tags:
        postconditions.add("unauthenticated_entrypoint")

    if "auth_bypass" in primitive_tags:
        postconditions.update(("authenticated_access", "privileged_access"))
        bridge_hooks.add("auth bypass can unlock restricted attack surface")
    if "sql_injection" in primitive_tags:
        preconditions.add("attacker_controlled_input")
        postconditions.update(("database_read", "database_write", "auth_state_control"))
        bridge_hooks.add("database state control can feed later trust decisions")
    if "path_traversal" in primitive_tags:
        preconditions.add("attacker_controlled_input")
        postconditions.update(
            ("controlled_file_path", "filesystem_read", "filesystem_write")
        )
        bridge_hooks.add("path control can redirect file operations")
    if "file_access" in primitive_tags or "file_sink" in sink_tags:
        preconditions.add("controlled_file_path")
        if any(word in evidence for word in ("write", "upload", "create", "save")):
            postconditions.add("filesystem_write")
            bridge_hooks.add("file write can plant code or configuration")
        if any(word in evidence for word in ("read", "download", "leak", "secret")):
            postconditions.add("filesystem_read")
            bridge_hooks.add("file read can expose secrets or code")
    if "secret_exposure" in primitive_tags or "secret_sink" in sink_tags:
        preconditions.add("filesystem_read")
        postconditions.add("credential_access")
        bridge_hooks.add("credential access can unlock authenticated surfaces")
    if "ssrf" in primitive_tags:
        preconditions.add("attacker_controlled_url")
        postconditions.update(("internal_network_access", "metadata_access"))
        bridge_hooks.add("internal access can reach protected services")
    if "deserialization" in primitive_tags:
        preconditions.update(("attacker_controlled_payload", "filesystem_write"))
        postconditions.add("code_execution")
        bridge_hooks.add("controlled payload can become code execution")
    if "template_injection" in primitive_tags:
        preconditions.update(("attacker_controlled_payload", "filesystem_write"))
        postconditions.add("code_execution")
        bridge_hooks.add("template control can become code execution")
    if "command_execution" in primitive_tags or "command_sink" in sink_tags:
        preconditions.update(
            (
                "attacker_controlled_command",
                "attacker_controlled_input",
                "controlled_file_path",
                "filesystem_write",
            )
        )
        postconditions.add("code_execution")
        bridge_hooks.add("command sink can become RCE")
    if "xss" in primitive_tags or "csrf" in primitive_tags:
        postconditions.add("browser_action_control")
        bridge_hooks.add("browser action control can trigger authenticated workflows")
    if "open_redirect" in primitive_tags:
        postconditions.add("navigation_control")

    return (
        tuple(sorted(preconditions)),
        tuple(sorted(postconditions)),
        tuple(sorted(bridge_hooks)),
    )


def _bridge_reasons(
    left: AttackChainCandidate, right: AttackChainCandidate
) -> list[str]:
    reasons: list[str] = []
    left_to_right = set(left.postconditions) & set(right.preconditions)
    right_to_left = set(right.postconditions) & set(left.preconditions)
    if left_to_right:
        reasons.append(
            f"{left.chain_id} postconditions satisfy {right.chain_id} preconditions: "
            + ", ".join(sorted(left_to_right))
        )
    if right_to_left:
        reasons.append(
            f"{right.chain_id} postconditions satisfy {left.chain_id} preconditions: "
            + ", ".join(sorted(right_to_left))
        )
    if _file_control_to_rce(left, right):
        reasons.append(
            f"{left.chain_id} filesystem/path control can feed {right.chain_id} code execution sink"
        )
    if _file_control_to_rce(right, left):
        reasons.append(
            f"{right.chain_id} filesystem/path control can feed {left.chain_id} code execution sink"
        )
    if _auth_to_privileged_surface(left, right):
        reasons.append(
            f"{left.chain_id} access-control impact can unlock {right.chain_id} privileged surface"
        )
    if _auth_to_privileged_surface(right, left):
        reasons.append(
            f"{right.chain_id} access-control impact can unlock {left.chain_id} privileged surface"
        )
    return list(dict.fromkeys(reasons))


def _file_control_to_rce(
    source: AttackChainCandidate, sink: AttackChainCandidate
) -> bool:
    source_outputs = set(source.postconditions)
    sink_families = set(sink.attack_families)
    sink_inputs = set(sink.preconditions)
    can_control_file = bool(
        source_outputs & {"filesystem_write", "controlled_file_path"}
    )
    can_execute = (
        bool(
            sink_families
            & {"command_execution", "deserialization", "template_injection"}
        )
        or "code_execution" in sink.postconditions
    )
    accepts_file = bool(
        sink_inputs
        & {"filesystem_write", "controlled_file_path", "attacker_controlled_payload"}
    )
    return can_control_file and can_execute and accepts_file


def _auth_to_privileged_surface(
    source: AttackChainCandidate, sink: AttackChainCandidate
) -> bool:
    return bool(
        set(source.postconditions) & {"authenticated_access", "privileged_access"}
    ) and bool(set(sink.preconditions) & {"authenticated_access", "privileged_access"})


def _dedupe_findings(
    findings: tuple[SecurityFinding, ...],
) -> tuple[SecurityFinding, ...]:
    by_id: dict[str, SecurityFinding] = {}
    for finding in findings:
        by_id.setdefault(finding.finding_id, finding)
    return tuple(by_id.values())


def _security_finding_from_result(
    ordinal: int, result: dict[str, Any], rules: dict[str, dict[str, Any]]
) -> SecurityFinding:
    rule_id = str(result.get("ruleId") or "unknown")
    rule = rules.get(rule_id, {})
    message = result.get("message", {})
    if isinstance(message, dict):
        message_text = str(message.get("text") or message.get("markdown") or "")
    else:
        message_text = str(message or "")
    level = str(result.get("level") or "warning")
    locations = _locations(result)
    properties = result.get("properties", {})
    properties_text = (
        json.dumps(properties, sort_keys=True)[:4000]
        if isinstance(properties, dict)
        else ""
    )
    rule_help = rule.get("help", {}) if isinstance(rule, dict) else {}
    rule_help_text = (
        str(rule_help.get("text") or rule_help.get("markdown") or "")
        if isinstance(rule_help, dict)
        else ""
    )
    evidence = "\n".join(
        (
            rule_id,
            level,
            message_text,
            " ".join(locations),
            rule_help_text,
            properties_text,
        )
    )
    primitive_tags = _tags_for(evidence, _PRIMITIVE_SIGNATURES)
    source_tags = _tags_for(evidence, _SOURCE_SIGNATURES)
    sink_tags = _tags_for(evidence, _SINK_SIGNATURES)
    trust_tags = _tags_for(evidence, _TRUST_SIGNATURES)
    return SecurityFinding(
        finding_id=f"F-{ordinal:04d}",
        rule_id=rule_id,
        level=level,
        message=message_text,
        locations=tuple(locations),
        rule_help=rule_help_text,
        properties_text=properties_text,
        component=_component_from_locations(locations),
        primitive_tags=primitive_tags,
        source_tags=source_tags,
        sink_tags=sink_tags,
        trust_tags=trust_tags,
        score_hint=_score_hint(level, primitive_tags, trust_tags),
        evidence_text=evidence,
    )


def _sarif_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    driver = run.get("tool", {}).get("driver", {})
    if not isinstance(driver, dict):
        return rules
    for rule in driver.get("rules", []) or []:
        if isinstance(rule, dict) and isinstance(rule.get("id"), str):
            rules[rule["id"]] = rule
    return rules


def _locations(result: dict[str, Any]) -> list[str]:
    locations = []
    for location in result.get("locations", []) or []:
        if not isinstance(location, dict):
            continue
        physical = location.get("physicalLocation", {})
        if not isinstance(physical, dict):
            continue
        artifact = physical.get("artifactLocation", {})
        region = physical.get("region", {})
        uri = artifact.get("uri") if isinstance(artifact, dict) else ""
        line = region.get("startLine") if isinstance(region, dict) else ""
        locations.append(f"{uri}:{line}" if line else str(uri))
    return locations


def _component_from_locations(locations: list[str]) -> str:
    if not locations:
        return "unknown"
    uri = locations[0].split(":", 1)[0]
    parts = [part for part in uri.split("/") if part]
    if len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0] if parts else "unknown"


def _tags_for(text: str, signatures: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    lowered = text.lower()
    return tuple(
        tag
        for tag, needles in signatures.items()
        if any(needle in lowered for needle in needles)
    )


def _score_hint(
    level: str, primitive_tags: tuple[str, ...], trust_tags: tuple[str, ...]
) -> float:
    score = {
        "error": 7.0,
        "warning": 5.5,
        "note": 3.0,
        "none": 2.0,
    }.get(level.lower(), 5.0)
    if any(
        tag in primitive_tags
        for tag in (
            "command_execution",
            "deserialization",
            "template_injection",
        )
    ):
        score = max(score, 9.0)
    elif any(
        tag in primitive_tags
        for tag in (
            "auth_bypass",
            "sql_injection",
            "ssrf",
            "path_traversal",
            "file_access",
        )
    ):
        score = max(score, 8.0)
    elif any(tag in primitive_tags for tag in ("xss", "csrf", "secret_exposure")):
        score = max(score, 7.0)
    if "unauthenticated" in trust_tags:
        score = min(score + 0.5, 10.0)
    if "admin_required" in trust_tags:
        score = max(score - 1.0, 0.0)
    return score


def _group_by_component(
    findings: list[SecurityFinding],
) -> dict[str, list[SecurityFinding]]:
    grouped: dict[str, list[SecurityFinding]] = {}
    for finding in findings:
        grouped.setdefault(finding.component, []).append(finding)
    return grouped


def _group_by_attack_family(
    findings: list[SecurityFinding],
) -> dict[str, list[SecurityFinding]]:
    grouped: dict[str, list[SecurityFinding]] = {}
    for finding in findings:
        families = finding.primitive_tags or ("unclassified_security_risk",)
        for family in families:
            grouped.setdefault(family, []).append(finding)
    return grouped


def _candidate_score(findings: list[SecurityFinding]) -> float:
    if not findings:
        return 0.0
    score = max(finding.score_hint for finding in findings)
    primitive_count = len(
        {tag for finding in findings for tag in finding.primitive_tags}
    )
    source_sink_bonus = any(finding.source_tags for finding in findings) and any(
        finding.sink_tags for finding in findings
    )
    if len(findings) >= 3:
        score += 0.5
    if primitive_count >= 2:
        score += 0.5
    if source_sink_bonus:
        score += 0.5
    return min(score, 10.0)


def _humanize_family(family: str) -> str:
    acronyms = {
        "csrf": "CSRF",
        "idor": "IDOR",
        "rce": "RCE",
        "sql": "SQL",
        "ssrf": "SSRF",
        "xss": "XSS",
    }
    words = []
    for word in family.split("_"):
        words.append(acronyms.get(word, word.title()))
    return " ".join(words)
