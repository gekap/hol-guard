"""Deterministic plain-language semantics for Guard action explanations.

The module is intentionally local, pure, and side-effect free. It consumes typed
facts supplied by Core's canonical action pipeline and never executes commands,
performs network requests, or calls a model. The dashboard, Desktop, and Cloud
must consume the resulting versioned contract instead of reinterpreting shell
text independently.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Iterable, Sequence

from .action_explanation_contract import (
    ACTION_EXPLANATION_REDACTION_VERSION,
    ACTION_EXPLANATION_RENDERER_VERSION,
    ACTION_EXPLANATION_SCHEMA_VERSION,
    ACTION_EXPLANATION_VERSION,
    ACTION_KINDS,
    GuardActionExplanationV1,
    parse_action_explanation,
)

_SECRET_MARKERS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "credentials", ".aws", ".ssh", ".gnupg", ".env",
    "id_rsa", "id_ed25519", "keychain",
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:sk-[a-z0-9_-]{12,}|gh[pousr]_[a-z0-9]{20,}|"
    r"(?:api[_-]?key|token|password|secret)\s*[=:]\s*\S+)"
)
_URL_RE = re.compile(r"(?i)https?://([^/\s?#]+)")
_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True, slots=True)
class CommandSemanticInput:
    """Typed facts from Core's canonical command/action model."""

    action_identity: str
    canonical_identity: str | None
    actor_label: str
    executable: str | None
    arguments: tuple[str, ...] = ()
    command_display: str | None = None
    normalized_command_display: str | None = None
    dialect: str | None = None
    transport: str | None = None
    working_scope_display: str | None = None
    extension_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    policy_source: str | None = None
    parse_confidence: str | None = None
    proof_level: str | None = None
    receipt_id: str | None = None
    catalog_digest: str | None = None
    exact_details_authorized: bool = False
    retained: bool = True


@dataclass(frozen=True, slots=True)
class SemanticRule:
    rule_id: str
    action_kind: str
    executables: frozenset[str]
    required_tokens: tuple[frozenset[str], ...] = ()
    forbidden_tokens: frozenset[str] = frozenset()
    headline: str = "Review an action"
    summary: str = "An AI app wants to perform an action."
    impact: str | None = None
    recommendation: str | None = None
    target_strategy: str = "generic"
    confidence: str = "derived"
    consequence_level: str = "medium"
    safer_alternatives: tuple[str, ...] = ()

    def matches(self, executable: str, tokens: frozenset[str]) -> bool:
        if executable not in self.executables:
            return False
        if self.forbidden_tokens & tokens:
            return False
        return all(group & tokens for group in self.required_tokens)


@dataclass(frozen=True, slots=True)
class SemanticMatch:
    rule: SemanticRule | None
    target_label: str
    headline: str
    summary: str
    impact: str | None
    recommendation: str | None
    confidence: str
    uncertainty_reasons: tuple[str, ...] = ()
    safer_alternatives: tuple[str, ...] = ()


_DELETE_EXECUTABLES = frozenset({"rm", "rmdir", "unlink", "del", "erase", "remove-item", "ri"})
_COPY_EXECUTABLES = frozenset({"cp", "copy", "copy-item", "cpi", "robocopy", "xcopy"})
_MOVE_EXECUTABLES = frozenset({"mv", "move", "move-item", "mi", "rename", "rename-item", "ren"})
_PERMISSION_EXECUTABLES = frozenset({"chmod", "chown", "chgrp", "icacls", "set-acl", "takeown"})
_READ_EXECUTABLES = frozenset({"cat", "type", "get-content", "gc", "more", "less", "head", "tail"})
_NETWORK_EXECUTABLES = frozenset({"curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm", "http", "https"})
_REMOTE_COPY_EXECUTABLES = frozenset({"scp", "sftp", "rsync"})
_PACKAGE_EXECUTABLES = frozenset({"npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "gem", "cargo", "go", "composer", "dotnet", "nuget", "winget", "choco", "brew", "apt", "apt-get", "dnf", "yum", "apk", "pacman"})


SEMANTIC_RULES: tuple[SemanticRule, ...] = (
    SemanticRule(
        rule_id="filesystem.delete.recursive", action_kind="file_delete",
        executables=_DELETE_EXECUTABLES,
        required_tokens=(frozenset({"-r", "-rf", "-fr", "--recursive", "/s", "-recurse"}),),
        headline="Delete a folder and everything inside it",
        summary="{actor} wants to permanently remove {target}, including files and subfolders.",
        impact="Files that are not backed up may be difficult or impossible to recover.",
        recommendation="Confirm that the folder is the intended one and that important work is backed up.",
        target_strategy="filesystem", confidence="exact", consequence_level="high",
        safer_alternatives=("Preview the folder contents first.", "Move the folder to the recycle bin or trash when possible."),
    ),
    SemanticRule(
        rule_id="filesystem.delete", action_kind="file_delete", executables=_DELETE_EXECUTABLES,
        headline="Delete a file or folder", summary="{actor} wants to permanently remove {target}.",
        impact="The removed item may not be recoverable.",
        recommendation="Confirm the target and keep a backup of anything important.",
        target_strategy="filesystem", confidence="exact", consequence_level="high",
        safer_alternatives=("Inspect the target first.", "Use the recycle bin or trash when available."),
    ),
    SemanticRule(
        rule_id="filesystem.copy", action_kind="file_write", executables=_COPY_EXECUTABLES,
        headline="Copy files or folders", summary="{actor} wants to copy data involving {target}.",
        impact="Existing files at the destination may be replaced, and additional copies may contain sensitive information.",
        recommendation="Confirm the destination and whether replacing existing files is intended.",
        target_strategy="filesystem", confidence="derived", consequence_level="medium",
        safer_alternatives=("Copy into a new empty folder first.",),
    ),
    SemanticRule(
        rule_id="filesystem.move", action_kind="file_write", executables=_MOVE_EXECUTABLES,
        headline="Move or rename files", summary="{actor} wants to move or rename data involving {target}.",
        impact="Programs or links that expect the old location may stop working, and existing destination files may be replaced.",
        recommendation="Confirm both the source and destination before continuing.",
        target_strategy="filesystem", confidence="derived", consequence_level="medium",
        safer_alternatives=("Copy first and remove the original after verifying the result.",),
    ),
    SemanticRule(
        rule_id="filesystem.permissions", action_kind="permission_change", executables=_PERMISSION_EXECUTABLES,
        headline="Change who can access files", summary="{actor} wants to change ownership or access permissions for {target}.",
        impact="The change may expose private data or prevent you and your apps from opening the affected files.",
        recommendation="Use the narrowest permissions needed and verify the exact target.",
        target_strategy="filesystem", confidence="derived", consequence_level="high",
        safer_alternatives=("Inspect current permissions first.", "Apply the change to one item before using it recursively."),
    ),
    SemanticRule(
        rule_id="credentials.read", action_kind="credential_access", executables=_READ_EXECUTABLES,
        headline="Read saved credentials", summary="{actor} wants to read {target}.",
        impact="The contents may include passwords, private keys, access tokens, or other secrets.",
        recommendation="Only continue when this app needs the credential and you trust where the data will be used.",
        target_strategy="sensitive", confidence="exact", consequence_level="high",
        safer_alternatives=("Use a credential helper or narrowly scoped environment variable instead.",),
    ),
    SemanticRule(
        rule_id="network.upload", action_kind="network_request", executables=_NETWORK_EXECUTABLES,
        required_tokens=(frozenset({"-d", "--data", "--data-binary", "--form", "-f", "--upload-file", "--body", "-infile"}),),
        headline="Send data to a website", summary="{actor} wants to send data to {target}.",
        impact="The destination may retain, process, or redistribute the sent information.",
        recommendation="Confirm the destination and make sure no private files or credentials are included.",
        target_strategy="network", confidence="derived", consequence_level="high",
        safer_alternatives=("Send only the minimum required fields.", "Use a trusted first-party endpoint."),
    ),
    SemanticRule(
        rule_id="network.download", action_kind="network_request", executables=_NETWORK_EXECUTABLES,
        required_tokens=(frozenset({"-o", "--output", "-outfile", "--remote-name", "-o-"}),),
        headline="Download a file from the internet",
        summary="{actor} wants to download content from {target} and save it on this computer.",
        impact="Downloaded files can replace local data or contain unsafe software.",
        recommendation="Verify the source and inspect the downloaded file before opening or running it.",
        target_strategy="network", confidence="derived", consequence_level="medium",
        safer_alternatives=("Download without running the file automatically.", "Verify a checksum or signature when available."),
    ),
    SemanticRule(
        rule_id="network.request", action_kind="network_request", executables=_NETWORK_EXECUTABLES,
        headline="Connect to a website or service", summary="{actor} wants to contact {target}.",
        impact="The destination can observe request details and may return untrusted content.",
        recommendation="Confirm that the destination is expected and trusted.",
        target_strategy="network", confidence="derived", consequence_level="medium",
        safer_alternatives=("Use a read-only or preview request when available.",),
    ),
    SemanticRule(
        rule_id="network.remote-copy", action_kind="network_request", executables=_REMOTE_COPY_EXECUTABLES,
        headline="Transfer files to or from another computer", summary="{actor} wants to transfer data involving {target}.",
        impact="Files may leave this computer, arrive from an untrusted host, or replace existing data.",
        recommendation="Confirm the remote computer, direction, and exact files.",
        target_strategy="remote", confidence="derived", consequence_level="high",
        safer_alternatives=("Use a dedicated empty destination folder.", "Verify the remote host identity first."),
    ),
    SemanticRule(
        rule_id="package.publish", action_kind="package_change", executables=_PACKAGE_EXECUTABLES,
        required_tokens=(frozenset({"publish", "upload", "push"}),),
        headline="Publish a software package", summary="{actor} wants to publish {target} to a package service.",
        impact="Published code or files may become available to other people and can be difficult to retract completely.",
        recommendation="Review the package contents, destination account, version, and included secrets before publishing.",
        target_strategy="package", confidence="exact", consequence_level="high",
        safer_alternatives=("Run a package dry run or inspect the archive first.",),
    ),
    SemanticRule(
        rule_id="package.remove", action_kind="package_change", executables=_PACKAGE_EXECUTABLES,
        required_tokens=(frozenset({"remove", "rm", "uninstall", "erase"}),),
        headline="Remove software packages", summary="{actor} wants to remove {target}.",
        impact="Apps, scripts, or project builds that depend on the package may stop working.",
        recommendation="Confirm the package and scope before removing it.",
        target_strategy="package", confidence="exact", consequence_level="medium",
        safer_alternatives=("Check which projects depend on the package first.",),
    ),
    SemanticRule(
        rule_id="package.install", action_kind="package_change", executables=_PACKAGE_EXECUTABLES,
        required_tokens=(frozenset({"install", "add", "i", "get"}),),
        headline="Install software packages", summary="{actor} wants to install {target}.",
        impact="Package installation can run third-party code and change project or system files.",
        recommendation="Confirm the package name, source, version, and whether installation is limited to this project.",
        target_strategy="package", confidence="exact", consequence_level="medium",
        safer_alternatives=("Pin an exact version.", "Install inside an isolated project environment."),
    ),
)


def explain_command(input: CommandSemanticInput) -> GuardActionExplanationV1:
    """Build a validated ``guard.action-explanation.v1`` contract."""

    executable = _normalize_executable(input.executable)
    args = tuple(str(arg) for arg in input.arguments)
    tokens = frozenset(_normalized_tokens(args))
    rule = next((candidate for candidate in SEMANTIC_RULES if candidate.matches(executable, tokens)), None)
    if rule and rule.rule_id == "credentials.read" and not _contains_sensitive_marker(args):
        rule = None
    match = _render_match(rule, input, args)
    technical_available = bool(input.retained and input.exact_details_authorized and input.command_display)
    command_display = _redact_technical_value(input.command_display) if technical_available else None
    normalized_display = _redact_technical_value(input.normalized_command_display) if technical_available else None
    arguments_display = [_redact_technical_value(arg) or "[redacted]" for arg in args] if technical_available else None
    action_kind = match.rule.action_kind if match.rule else "unknown"
    if action_kind not in ACTION_KINDS:
        action_kind = "unknown"
    omitted: list[str] = []
    if not technical_available:
        omitted.extend(["technical.command_display", "technical.arguments_display"])
    if input.working_scope_display and not input.exact_details_authorized:
        omitted.append("technical.working_scope_display")
    payload: dict[str, object] = {
        "schema_version": ACTION_EXPLANATION_SCHEMA_VERSION,
        "explanation_version": ACTION_EXPLANATION_VERSION,
        "renderer_version": ACTION_EXPLANATION_RENDERER_VERSION,
        "action_identity": _bounded(input.action_identity, 256),
        "canonical_identity": _bounded(input.canonical_identity, 256),
        "catalog_digest": _bounded(input.catalog_digest, 256),
        "locale": "en-US", "kind": action_kind, "confidence": match.confidence,
        "uncertainty_reasons": list(match.uncertainty_reasons),
        "everyday": {
            "headline_message_id": f"guard.everyday.{match.rule.rule_id if match.rule else 'unknown'}.headline",
            "headline": _bounded(match.headline, 240),
            "summary_message_id": f"guard.everyday.{match.rule.rule_id if match.rule else 'unknown'}.summary",
            "summary": _bounded(match.summary, 1000),
            "impact_message_id": f"guard.everyday.{match.rule.rule_id}.impact" if match.rule and match.impact else None,
            "impact": _bounded(match.impact, 1000),
            "why_guard_intervened_message_id": None, "why_guard_intervened": None,
            "recommendation_message_id": f"guard.everyday.{match.rule.rule_id}.recommendation" if match.rule and match.recommendation else None,
            "recommendation": _bounded(match.recommendation, 1000),
            "actor_label": _bounded(_safe_actor(input.actor_label), 160),
            "targets": [], "consequences": [], "safer_alternatives": [],
        },
        "technical": {
            "available": technical_available,
            "unavailable_reason": None if technical_available else ("not_retained" if not input.retained else "not_authorized"),
            "action_type": action_kind,
            "command_display": _bounded(command_display, 12000),
            "normalized_command_display": _bounded(normalized_display, 12000),
            "executable": _bounded(executable or None, 512),
            "arguments_display": [_bounded(value, 2000) or "" for value in arguments_display] if arguments_display is not None else None,
            "dialect": _bounded(input.dialect, 128), "transport": _bounded(input.transport, 128),
            "working_scope_display": _bounded(_safe_scope(input.working_scope_display), 1000) if input.exact_details_authorized else None,
            "wrappers": [], "segments": [],
            "extension_ids": [_bounded(value, 256) or "" for value in input.extension_ids],
            "rule_ids": [_bounded(value, 256) or "" for value in input.rule_ids],
            "reason_codes": [_bounded(value, 256) or "" for value in input.reason_codes],
            "policy_source": _bounded(input.policy_source, 256),
            "parse_confidence": _bounded(input.parse_confidence, 128),
            "proof_level": _bounded(input.proof_level, 128),
            "receipt_id": _bounded(input.receipt_id, 256),
            "action_id": _bounded(input.action_identity, 256),
        },
        "redaction": {
            "level": "none" if technical_available else "redacted",
            "policy_version": ACTION_EXPLANATION_REDACTION_VERSION,
            "omitted_fields": omitted, "truncated_fields": [],
            "secret_like_values_removed": _secret_like_value_present((input.command_display or "", *args)),
        },
    }
    return parse_action_explanation(payload)


def stable_semantic_catalog_digest() -> str:
    material = [{
        "rule_id": rule.rule_id, "action_kind": rule.action_kind,
        "executables": sorted(rule.executables),
        "required_tokens": [sorted(group) for group in rule.required_tokens],
        "forbidden_tokens": sorted(rule.forbidden_tokens),
        "headline": rule.headline, "summary": rule.summary,
    } for rule in SEMANTIC_RULES]
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _render_match(rule: SemanticRule | None, input: CommandSemanticInput, args: Sequence[str]) -> SemanticMatch:
    actor = _safe_actor(input.actor_label)
    if rule is None:
        return SemanticMatch(
            rule=None, target_label="the requested target",
            headline="Review an action Guard could not fully explain",
            summary=f"{actor} wants to perform an action, but Guard could not confirm the exact intent or target.",
            impact="The action may change files, software, settings, or data outside the information Guard could verify.",
            recommendation="Open the technical details when available and confirm the exact action before continuing.",
            confidence="limited", uncertainty_reasons=("semantic_rule_unavailable",),
            safer_alternatives=("Ask the app to explain or preview the action without running it.",),
        )
    target = _target_label(rule.target_strategy, args)
    return SemanticMatch(
        rule=rule, target_label=target, headline=rule.headline,
        summary=rule.summary.format(actor=actor, target=target), impact=rule.impact,
        recommendation=rule.recommendation,
        confidence=rule.confidence if rule.confidence in {"exact", "derived", "limited"} else "limited",
        safer_alternatives=rule.safer_alternatives,
    )


def _normalize_executable(value: str | None) -> str:
    if not value:
        return ""
    normalized = value.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if normalized.endswith(suffix):
            normalized = normalized[:-len(suffix)]
            break
    return normalized


def _normalized_tokens(arguments: Iterable[str]) -> Iterable[str]:
    for argument in arguments:
        value = argument.strip().casefold()
        if value:
            yield value
            if "=" in value:
                yield value.split("=", 1)[0]


def _target_label(strategy: str, arguments: Sequence[str]) -> str:
    positional = [arg for arg in arguments if arg and not arg.startswith("-") and not arg.startswith("/")]
    if strategy == "sensitive" or _contains_sensitive_marker(arguments):
        return "saved credentials or another sensitive file"
    if strategy == "network":
        for argument in arguments:
            match = _URL_RE.search(argument)
            if match:
                return f"the service at {_bounded(match.group(1).strip('[]').casefold(), 253)}"
        return "an external website or service"
    if strategy == "remote":
        for argument in arguments:
            if ":" in argument and not _DRIVE_RE.match(argument):
                host = argument.split(":", 1)[0].split("@")[-1]
                if host:
                    return f"another computer ({_bounded(host, 160)})"
        return "another computer"
    if strategy == "package":
        packages = [arg for arg in positional if arg.casefold() not in {"install", "add", "i", "get", "remove", "rm", "uninstall", "erase", "publish", "upload", "push"}]
        if packages:
            shown = ", ".join(_safe_basename(value) for value in packages[:3])
            return f"the software package{'s' if len(packages) != 1 else ''} {shown}"
        return "one or more software packages"
    if strategy == "filesystem":
        candidates = [arg for arg in arguments if arg and not arg.startswith("-")]
        if candidates:
            label = _safe_basename(candidates[-1])
            return f"the item named {label}" if label else "files or folders in the selected location"
        return "files or folders in the selected location"
    return "the requested target"


def _safe_basename(value: str) -> str:
    normalized = value.strip().rstrip("/\\").replace("\\", "/")
    if not normalized:
        return "the selected item"
    name = normalized.rsplit("/", 1)[-1]
    if _contains_sensitive_marker((normalized,)):
        return "a sensitive item"
    if _SECRET_VALUE_RE.search(name):
        return "[redacted]"
    return _bounded(name, 120) or "the selected item"


def _safe_actor(value: str) -> str:
    return _SECRET_VALUE_RE.sub("[redacted]", value.strip()) or "An AI app"


def _safe_scope(value: str | None) -> str | None:
    if not value:
        return None
    if _contains_sensitive_marker((value,)):
        return "[sensitive location]"
    return _redact_technical_value(value)


def _contains_sensitive_marker(values: Iterable[str]) -> bool:
    joined = " ".join(values).casefold()
    return any(marker in joined for marker in _SECRET_MARKERS)


def _secret_like_value_present(values: Iterable[str]) -> bool:
    return any(_SECRET_VALUE_RE.search(value or "") is not None for value in values)


def _redact_technical_value(value: str | None) -> str | None:
    return None if value is None else _SECRET_VALUE_RE.sub("[redacted]", value)


def _bounded(value: str | None, limit: int) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return value[: max(0, limit - 1)] + "…"
