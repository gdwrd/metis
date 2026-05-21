# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


MarkerKind = Literal["source", "sink", "sanitizer", "guard"]


@dataclass(frozen=True)
class VulnerabilityRule:
    family: str
    cwe: str
    source_markers: tuple[str, ...] = ()
    sink_markers: tuple[str, ...] = ()
    sanitizer_markers: tuple[str, ...] = ()
    guard_markers: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()


COMMON_SOURCE_MARKERS = (
    "req",
    "request",
    "param",
    "params",
    "query",
    "form",
    "file",
    "files",
    "args",
    "argv",
    "stdin",
    "query_string",
    "$_get",
    "$_post",
    "$_request",
    "$_cookie",
    "@argv",
    "$argv",
    "$env",
    "arg",
    "input",
    "environ",
    "getenv",
    "os.getenv",
    "io.read",
    "process.env",
    "env",
    "socket",
    "network",
    "http",
    "url",
    "uri",
    "ipc",
    "body",
    "headers",
    "header",
    "cookie",
    "cookies",
    "payload",
    "upload",
    "webhook",
    "callback",
    "msg.sender",
    "msg.value",
    "tx.origin",
    "work",
    "thread",
    "irq",
    "interrupt",
    "handler",
    "bus_write",
    "mmio",
    "jtag",
    "debug_req",
    "strap",
    "write_en",
    "host_wdata",
)

COMMON_GUARD_MARKERS = (
    "require_",
    "check_",
    "authorize",
    "permission",
    "owner",
    "tenant",
    "admin",
    "authenticated",
    "login_required",
    "jwt_required",
    "policy",
    "acl",
    "privileged",
    "secure_state",
    "lifecycle",
    "locked",
    "authorized",
    "allow_debug",
)

COMMON_SANITIZER_MARKERS = (
    "sanitize",
    "validate",
    "escape",
    "schema",
    "canonical",
    "normalize",
    "safe_join",
    "allowlist",
    "whitelist",
    "parse_url",
    "new_url",
    "zeroize",
    "memset_s",
    "clear",
)

CONFIG_KEYWORDS = ("config", "settings", "environ", "getenv")


VULNERABILITY_RULES = (
    VulnerabilityRule(
        family="command_injection",
        cwe="CWE-78",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "os.system",
            "subprocess.run",
            "subprocess.call",
            "subprocess.popen",
            "system",
            "check_output",
            "popen",
            "spawn",
            "spawn_sync",
            "child_process",
            "child_process.exec",
            "child_process.execfile",
            "child_process.spawn",
            "processbuilder",
            "runtime.exec",
            "getruntime().exec",
            "process.start",
            "system.diagnostics.process.start",
            "exec.command",
            "os/exec",
            "cmd",
            "exec",
            "execsync",
            "shell_exec",
            "passthru",
            "proc_open",
            "backticks",
            "subprocess",
            "powershell",
            "sh -c",
            "os.execute",
            "io.popen",
            "command::new",
            "std::process::command",
        ),
        sanitizer_markers=(
            "escapeshellarg",
            "escapeshellcmd",
            "shellescape",
            "shlex.quote",
            "shellwords.escape",
            "processbuilder.command",
            "exec.commandcontext",
            "validate",
            "allowlist",
            "schema",
            "sanitize",
        ),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=(
            "bash",
            "c",
            "cpp",
            "csharp",
            "go",
            "java",
            "lua",
            "perl",
            "python",
            "javascript",
            "typescript",
            "php",
            "ruby",
            "rust",
        ),
        aliases=("rce", "shell_injection"),
    ),
    VulnerabilityRule(
        family="code_injection",
        cwe="CWE-94",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "eval",
            "function",
            "new function",
            "vm.runin",
            "vm.runinnewcontext",
            "vm.runinthiscontext",
            "compile",
            "exec",
            "execfile",
            "loadstring",
            "load",
            "create_function",
            "reflection",
            "method.invoke",
            "assembly.load",
            "type.gettype",
            "class.forname",
            "class_eval",
            "instance_eval",
            "erb.new",
            "template.compile",
        ),
        sanitizer_markers=("validate", "allowlist", "sanitize", "schema"),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=(
            "python",
            "javascript",
            "typescript",
            "php",
            "ruby",
            "lua",
            "java",
            "csharp",
        ),
        aliases=("rce", "dynamic_code"),
    ),
    VulnerabilityRule(
        family="sql_injection",
        cwe="CWE-89",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "sql_query",
            "query",
            "queryrow",
            "querycontext",
            "rawquery",
            "raw_query",
            "rawsql",
            "raw_sql",
            "find_by_sql",
            "where",
            "mysql_query",
            "mysqli_query",
            "pg_query",
            "sqlite_query",
            "pdo::query",
            "pdo.query",
            "pdo.exec",
            "db.query",
            "db.exec",
            "db.raw",
            "dbh.do",
            "statement.execute",
            "statement.executequery",
            "statement.executeupdate",
            "sqlcommand",
            "executereader",
            "executenonquery",
            "executescalar",
            "database/sql",
            "execute",
            "executemany",
            "exec",
        ),
        sanitizer_markers=(
            "parameterize",
            "parameterized",
            "prepare",
            "prepared",
            "preparedstatement",
            "createcommand",
            "command.parameters",
            "parameters.add",
            "parameters.addwithvalue",
            "bind_param",
            "bindparameter",
            "bindvalue",
            "quote",
            "real_escape_string",
            "intval",
            "filter_input",
            "escape",
            "sqlalchemy.text",
            "activerecord.sanitize_sql",
        ),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=(
            "python",
            "javascript",
            "typescript",
            "php",
            "perl",
            "ruby",
            "go",
            "java",
            "csharp",
        ),
        aliases=("sqli",),
    ),
    VulnerabilityRule(
        family="nosql_injection",
        cwe="CWE-943",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "find",
            "findone",
            "aggregate",
            "where",
            "eval",
            "$where",
            "elasticsearch",
            "opensearch",
            "search",
        ),
        sanitizer_markers=("validate", "schema", "allowlist", "sanitize"),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("javascript", "typescript", "python", "ruby", "go"),
        aliases=("query_injection",),
    ),
    VulnerabilityRule(
        family="template_injection",
        cwe="CWE-1336",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "render_template_string",
            "template",
            "from_string",
            "jinja2.template",
            "erb.new",
            "handlebars.compile",
            "mustache.render",
        ),
        sanitizer_markers=("escape", "autoescape", "sanitize", "validate"),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("python", "javascript", "typescript", "ruby", "php"),
        aliases=("ssti",),
    ),
    VulnerabilityRule(
        family="path_traversal",
        cwe="CWE-22",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "open",
            "readfile",
            "fopen",
            "send_file",
            "sendfile",
            "filepath",
            "path.join",
            "writefile",
            "create_read_stream",
            "extractall",
            "extract",
        ),
        sanitizer_markers=(
            "safe_join",
            "canonical",
            "normalize",
            "realpath",
            "resolve",
            "validate",
        ),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("python", "javascript", "typescript", "php", "go", "ruby"),
        aliases=("file_disclosure", "zip_slip"),
    ),
    VulnerabilityRule(
        family="ssrf",
        cwe="CWE-918",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "urlopen",
            "requests.get",
            "requests.post",
            "fetch",
            "http.get",
            "http.post",
            "axios.get",
            "axios.post",
            "curl_exec",
            "net/http",
            "httpclient",
        ),
        sanitizer_markers=(
            "parse_url",
            "new_url",
            "allowlist",
            "validate",
            "is_private",
        ),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("python", "javascript", "typescript", "php", "go", "ruby"),
        aliases=("open_redirect_adjacent",),
    ),
    VulnerabilityRule(
        family="deserialization",
        cwe="CWE-502",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "pickle.loads",
            "yaml.load",
            "marshal.load",
            "loads",
            "deserialize",
            "unserialize",
            "objectinputstream",
            "binaryformatter",
            "readobject",
        ),
        sanitizer_markers=("safe_load", "validate", "schema", "allowlist"),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("python", "javascript", "typescript", "php", "java", "csharp"),
        aliases=("unsafe_deserialization",),
    ),
    VulnerabilityRule(
        family="xxe",
        cwe="CWE-611",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "parsexml",
            "xmlreader",
            "saxparser",
            "documentbuilder",
            "loadxml",
        ),
        sanitizer_markers=(
            "disable_external",
            "no_network",
            "resolve_entities=false",
            "defusedxml",
        ),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("python", "javascript", "typescript", "php", "java", "csharp"),
        aliases=("xml_external_entity",),
    ),
    VulnerabilityRule(
        family="xss",
        cwe="CWE-79",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "innerhtml",
            "outerhtml",
            "insertadjacenthtml",
            "document.write",
            "dangerouslysetinnerhtml",
            "html_safe",
            "raw",
        ),
        sanitizer_markers=(
            "escape",
            "htmlspecialchars",
            "sanitize",
            "dompurify",
            "encode",
        ),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("javascript", "typescript", "php", "ruby", "python"),
        aliases=("dom_xss",),
    ),
    VulnerabilityRule(
        family="secrets_exposure",
        cwe="CWE-798",
        source_markers=(
            "config",
            "settings",
            "env",
            "secret",
            "token",
            "password",
            "apikey",
        ),
        sink_markers=(
            "secret",
            "key",
            "token",
            "password",
            "credential",
            "apikey",
            "private_key",
        ),
        sanitizer_markers=("redact", "mask", "vault", "kms", "secretsmanager"),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("terraform", "yaml", "json", "dockerfile", "python"),
        aliases=("secrets", "credential_exposure"),
    ),
    VulnerabilityRule(
        family="crypto_misuse",
        cwe="CWE-327",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=("md5", "sha1", "des", "ecb", "math.random", "rand", "srand"),
        sanitizer_markers=(
            "crypto.random",
            "securerandom",
            "secrets.",
            "hmac",
            "constant_time",
        ),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("python", "javascript", "typescript", "php", "ruby", "go"),
        aliases=("weak_randomness",),
    ),
    VulnerabilityRule(
        family="memory_lifetime",
        cwe="CWE-416",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "memcpy",
            "strncpy",
            "strcpy",
            "sprintf",
            "free",
            "kfree",
            "vfree",
            "delete",
            "drop",
            "destroy",
            "release",
        ),
        sanitizer_markers=(
            "bounds_check",
            "memset_s",
            "zeroize",
            "clear",
            "refcount",
            "lock",
        ),
        guard_markers=("mutex_lock", "spin_lock", "refcount", *COMMON_GUARD_MARKERS),
        languages=("c", "cpp", "rust"),
        aliases=("uaf", "overflow"),
    ),
    VulnerabilityRule(
        family="evm_external_call",
        cwe="CWE-841",
        source_markers=("msg.sender", "msg.value", "tx.origin", "calldata", "payable"),
        sink_markers=("call", "delegatecall", "staticcall", "send", "transfer"),
        sanitizer_markers=(
            "nonreentrant",
            "checks_effects",
            "safeerc20",
            "require",
            "assert",
        ),
        guard_markers=("onlyowner", "onlyrole", "require", *COMMON_GUARD_MARKERS),
        languages=("solidity",),
        aliases=("reentrancy", "unsafe_delegatecall"),
    ),
    VulnerabilityRule(
        family="iac_exposure",
        cwe="CWE-284",
        source_markers=(
            "cidr",
            "principal",
            "policy",
            "public_read",
            "wildcard",
        ),
        sink_markers=(
            "0.0.0.0/0",
            "::/0",
            "public_read",
            "public",
            "admin",
            "wildcard",
            "*:*",
            "kms",
            "iam",
        ),
        sanitizer_markers=(
            "condition",
            "least_privilege",
            "private",
            "encrypted",
            "block_public",
        ),
        guard_markers=COMMON_GUARD_MARKERS,
        languages=("terraform", "yaml", "json", "dockerfile"),
        aliases=("cloud_exposure",),
    ),
    VulnerabilityRule(
        family="hardware_security",
        cwe="CWE-1262",
        source_markers=COMMON_SOURCE_MARKERS,
        sink_markers=(
            "register_write",
            "write_reg",
            "mmio_write",
            "csr_write",
            "privilege",
            "debug_enable",
            "boot_key",
            "seed",
            "secret",
            "key",
            "fuse",
            "otp",
        ),
        sanitizer_markers=("secure_state", "lifecycle", "locked", "zeroize", "clear"),
        guard_markers=(
            "privileged",
            "secure_state",
            "lifecycle",
            "locked",
            "allow_debug",
        ),
        languages=("systemverilog", "verilog", "c", "cpp"),
        aliases=("debug_bypass", "rtl_privilege"),
    ),
)


def markers_for(
    kind: MarkerKind, *, families: tuple[str, ...] | None = None
) -> tuple[str, ...]:
    selected = set(families or ())
    values: list[str] = []
    for rule in VULNERABILITY_RULES:
        if (
            selected
            and rule.family not in selected
            and not selected.intersection(rule.aliases)
        ):
            continue
        values.extend(getattr(rule, f"{kind}_markers"))
    return _dedupe(values)


def normalized_markers_for(
    kind: MarkerKind, *, families: tuple[str, ...] | None = None
) -> tuple[str, ...]:
    return tuple(
        sorted(markers_for(kind, families=families), key=lambda item: item.lower())
    )


def rule_for_family(family: str) -> VulnerabilityRule:
    for rule in VULNERABILITY_RULES:
        if rule.family == family or family in rule.aliases:
            return rule
    raise KeyError(f"unknown vulnerability rule family: {family}")


def _dedupe(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return tuple(result)


SOURCE_KEYWORDS = _dedupe([*COMMON_SOURCE_MARKERS, *markers_for("source")])
SINK_KEYWORDS = markers_for("sink")
SANITIZER_KEYWORDS = _dedupe([*COMMON_SANITIZER_MARKERS, *markers_for("sanitizer")])
GUARD_KEYWORDS = _dedupe([*COMMON_GUARD_MARKERS, *markers_for("guard")])
