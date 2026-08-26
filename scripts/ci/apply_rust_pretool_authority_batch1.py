#!/usr/bin/env python3
"""Apply the first Rust PreToolUse authority migration batch.

This is intentionally deterministic and idempotent. It is executed on the
feature branch by a temporary implementation workflow so the resulting source
changes are normal reviewed commits, not runtime patching.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.rstrip() + "\n", encoding="utf-8")


def replace_once(source: str, old: str, new: str, *, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return source.replace(old, new, 1)


def ensure_contains(source: str, needle: str, *, label: str) -> None:
    if needle not in source:
        raise RuntimeError(f"{label}: required source anchor is missing")


PRETOOL_RS = r'''#![forbid(unsafe_code)]

use guard_command::{parse_command, CanonicalCommandV1, CommandModelRequestV1};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

const PROTOCOL_VERSION: u16 = 1;
const MAX_COMMAND_BYTES: usize = 32_768;

#[derive(Debug, Serialize)]
struct PreToolDecisionV1 {
    protocol_version: u16,
    request_id: String,
    authority: &'static str,
    decision: &'static str,
    policy_action: &'static str,
    minimum_action: &'static str,
    reason_code: &'static str,
    reason: &'static str,
    command_model: Option<CanonicalCommandV1>,
}

impl PreToolDecisionV1 {
    fn allow(request_id: String, reason_code: &'static str, model: CanonicalCommandV1) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            authority: "rust",
            decision: "allow",
            policy_action: "allow",
            minimum_action: "allow",
            reason_code,
            reason: "HOL Guard's native runtime proved this command is within the bounded read-only allow set.",
            command_model: Some(model),
        }
    }

    fn review(request_id: String, reason_code: &'static str, model: Option<CanonicalCommandV1>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            authority: "rust",
            decision: "deny",
            policy_action: "review",
            minimum_action: "review",
            reason_code,
            reason: "HOL Guard's native runtime requires an explicit review before this command can run.",
            command_model: model,
        }
    }

    fn block(request_id: String, reason_code: &'static str, model: Option<CanonicalCommandV1>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            authority: "rust",
            decision: "deny",
            policy_action: "block",
            minimum_action: "block",
            reason_code,
            reason: "HOL Guard's native runtime blocked this command because it crosses a hard safety floor.",
            command_model: model,
        }
    }
}

fn plain_string(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).map(str::trim).filter(|value| !value.is_empty())
}

fn command_from_mapping(value: &Value) -> Option<String> {
    let record = value.as_object()?;
    for key in ["command", "cmd", "shell_command", "shellCommand"] {
        if let Some(command) = plain_string(record.get(key)) {
            return Some(command.to_owned());
        }
    }
    for key in ["tool_input", "toolInput", "arguments", "input"] {
        if let Some(command) = record.get(key).and_then(command_from_mapping) {
            return Some(command);
        }
    }
    None
}

fn basename(value: &str) -> &str {
    Path::new(value)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(value)
}

fn sensitive_operand(value: &str) -> bool {
    let normalized = value.replace('\\', "/").to_ascii_lowercase();
    let parts: Vec<&str> = normalized.split('/').collect();
    parts.iter().any(|part| {
        matches!(
            *part,
            ".aws"
                | ".docker"
                | ".env"
                | ".git-credentials"
                | ".kube"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
                | ".ssh"
                | "credentials"
                | "id_dsa"
                | "id_ecdsa"
                | "id_ed25519"
                | "id_rsa"
                | "private-key"
                | "private_key"
                | "secrets"
                | "tokens"
        )
    })
}

fn hard_block_executable(executable: &str) -> bool {
    matches!(
        basename(executable),
        "blkdiscard"
            | "chroot"
            | "dd"
            | "fdisk"
            | "halt"
            | "init"
            | "kexec"
            | "mkfs"
            | "mkswap"
            | "parted"
            | "poweroff"
            | "reboot"
            | "rm"
            | "rmdir"
            | "shutdown"
            | "shred"
            | "swapoff"
            | "swapon"
            | "wipefs"
    )
}

fn network_or_execution_boundary(executable: &str) -> bool {
    matches!(
        basename(executable),
        "bash"
            | "bun"
            | "cargo"
            | "curl"
            | "dash"
            | "deno"
            | "docker"
            | "env"
            | "eval"
            | "exec"
            | "fish"
            | "gh"
            | "git"
            | "kubectl"
            | "nc"
            | "node"
            | "npm"
            | "npx"
            | "perl"
            | "pip"
            | "pip3"
            | "pnpm"
            | "python"
            | "python3"
            | "ruby"
            | "scp"
            | "sh"
            | "ssh"
            | "sudo"
            | "wget"
            | "yarn"
            | "zsh"
    )
}

fn safe_git(arguments: &[String]) -> bool {
    let Some(subcommand) = arguments.first().map(String::as_str) else {
        return false;
    };
    match subcommand {
        "status" | "rev-parse" | "ls-files" | "show-ref" => true,
        "branch" => arguments.iter().skip(1).all(|argument| {
            matches!(argument.as_str(), "--show-current" | "--list" | "-l")
                || (!argument.starts_with('-') && !sensitive_operand(argument))
        }),
        "diff" | "log" | "show" => arguments.iter().skip(1).all(|argument| {
            !matches!(
                argument.as_str(),
                "--ext-diff" | "--textconv" | "--output" | "--output-indicator-new"
            ) && !argument.starts_with("--output=")
                && !argument.starts_with("--config-env=")
                && !sensitive_operand(argument)
        }),
        _ => false,
    }
}

fn safe_search(executable: &str, arguments: &[String]) -> bool {
    let program = basename(executable);
    if !matches!(program, "rg" | "grep") {
        return false;
    }
    if arguments.is_empty() {
        return false;
    }
    arguments.iter().all(|argument| {
        !sensitive_operand(argument)
            && !matches!(argument.as_str(), "--files-with-matches" | "-l" | "--files-without-match" | "-L")
            && !argument.starts_with("--pre=")
            && argument != "--pre"
    })
}

fn safe_read_only_segment(executable: &str, arguments: &[String]) -> bool {
    let program = basename(executable);
    if hard_block_executable(program) {
        return false;
    }
    if program == "git" {
        return safe_git(arguments);
    }
    if safe_search(program, arguments) {
        return true;
    }
    match program {
        "pwd" | "true" | "false" | "whoami" | "uname" | "id" => arguments.iter().all(|value| !sensitive_operand(value)),
        "printf" => arguments.iter().all(|value| !value.contains("${") && !value.contains("$(") && !sensitive_operand(value)),
        "ls" => arguments.iter().all(|value| !sensitive_operand(value)),
        "cat" | "head" | "tail" | "wc" | "stat" => {
            !arguments.is_empty()
                && arguments.iter().all(|value| {
                    !sensitive_operand(value)
                        && !matches!(value.as_str(), "-" | "--zero-terminated")
                })
        }
        _ => false,
    }
}

fn decide(request_id: String, model: CanonicalCommandV1) -> PreToolDecisionV1 {
    if model.confidence != "exact" || model.segments.is_empty() {
        return PreToolDecisionV1::review(request_id, "native_command_uncertain", Some(model));
    }
    if model
        .segments
        .iter()
        .any(|segment| segment.executable.as_deref().is_some_and(hard_block_executable))
    {
        return PreToolDecisionV1::block(request_id, "native_hard_block_executable", Some(model));
    }
    if model.path_overridden {
        return PreToolDecisionV1::review(request_id, "native_path_override_review", Some(model));
    }
    if model.segments.iter().all(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(|executable| safe_read_only_segment(executable, &segment.arguments))
    }) {
        return PreToolDecisionV1::allow(request_id, "native_bounded_read_only_allow", model);
    }
    if model.segments.iter().any(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(network_or_execution_boundary)
    }) {
        return PreToolDecisionV1::review(request_id, "native_execution_boundary_review", Some(model));
    }
    PreToolDecisionV1::review(request_id, "native_unclassified_command_review", Some(model))
}

pub fn evaluate_pre_tool_value(value: Value) -> Result<Value, String> {
    let record = value
        .as_object()
        .ok_or_else(|| "native_pretool_request_invalid".to_owned())?;
    if record.get("protocol_version").and_then(Value::as_u64) != Some(PROTOCOL_VERSION.into()) {
        return Err("native_pretool_protocol_mismatch".to_owned());
    }
    let request_id = plain_string(record.get("request_id"))
        .ok_or_else(|| "native_pretool_request_id_missing".to_owned())?
        .to_owned();
    let event = plain_string(record.get("event_name"))
        .ok_or_else(|| "native_pretool_event_missing".to_owned())?;
    if !event.eq_ignore_ascii_case("PreToolUse") {
        return Err("native_pretool_event_unsupported".to_owned());
    }
    let payload = record
        .get("payload")
        .ok_or_else(|| "native_pretool_payload_missing".to_owned())?;
    let Some(command) = command_from_mapping(payload) else {
        return serde_json::to_value(PreToolDecisionV1::review(
            request_id,
            "native_command_missing_review",
            None,
        ))
        .map_err(|_| "native_pretool_response_encode_failed".to_owned());
    };
    if command.len() > MAX_COMMAND_BYTES {
        return serde_json::to_value(PreToolDecisionV1::review(
            request_id,
            "native_command_too_large_review",
            None,
        ))
        .map_err(|_| "native_pretool_response_encode_failed".to_owned());
    }
    let model = parse_command(&CommandModelRequestV1 {
        command,
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-hook".to_owned(),
    })?;
    serde_json::to_value(decide(request_id, model))
        .map_err(|_| "native_pretool_response_encode_failed".to_owned())
}
'''


NATIVE_PRETOOL_PY = r'''"""Transport-only bridge to the Rust PreToolUse authority.

No command parsing, classification, policy floor, or semantic fallback exists
in this module. Python validates request/response bindings and transports the
native decision. Any native failure is converted into a deterministic fail-
closed decision; it is never sent to a Python evaluator.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resident import resident_native_request
from .native_runtime_resilience import (
    native_oneshot_lease,
    native_record_oneshot_failure,
    native_record_oneshot_success,
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)

_MAX_REQUEST_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUIRED_FEATURE = "pre-tool-authority-v1"
_RESIDENT_FEATURE = "resident-pre-tool-authority-v1"


def _fail_closed(request_id: str, reason_code: str) -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "request_id": request_id,
        "authority": "rust",
        "decision": "deny",
        "policy_action": "block",
        "minimum_action": "block",
        "reason_code": reason_code,
        "reason": "HOL Guard blocked this action because its native PreToolUse authority could not produce a verified decision.",
        "command_model": None,
    }


def _decode_native_decision(payload: object, *, request_id: str) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    decision = payload.get("decision")
    policy_action = payload.get("policy_action")
    minimum_action = payload.get("minimum_action")
    reason_code = payload.get("reason_code")
    reason = payload.get("reason")
    if (
        payload.get("protocol_version") != 1
        or payload.get("request_id") != request_id
        or payload.get("authority") != "rust"
        or decision not in {"allow", "deny"}
        or policy_action not in {"allow", "review", "block"}
        or minimum_action not in {"allow", "review", "block"}
        or not isinstance(reason_code, str)
        or not reason_code
        or not isinstance(reason, str)
        or not reason
    ):
        return None
    if decision == "allow" and (policy_action != "allow" or minimum_action != "allow"):
        return None
    if decision == "deny" and policy_action == "allow":
        return None
    return payload


def _request_payload(
    payload: dict[str, object],
    *,
    request_id: str,
    harness: str,
    cwd: Path | None,
    home_dir: Path,
    guard_home: Path,
    deadline_budget_ms: int,
) -> tuple[dict[str, object], bytes] | None:
    request = {
        "protocol_version": 1,
        "request_id": request_id,
        "harness": harness,
        "event_name": "PreToolUse",
        "payload": payload,
        "cwd": str(cwd) if cwd is not None else None,
        "home_dir": str(home_dir),
        "guard_home": str(guard_home),
        "deadline_budget_ms": max(1, min(9_000, int(deadline_budget_ms))),
    }
    encoded = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > _MAX_REQUEST_BYTES:
        return None
    return request, encoded


def review_pre_tool_native(
    payload: dict[str, object],
    *,
    request_id: str,
    harness: str,
    cwd: Path | None,
    home_dir: Path,
    guard_home: Path,
    timeout_seconds: float = 0.75,
) -> dict[str, Any]:
    """Return the final Rust PreToolUse decision, or a native fail-closed block."""

    if timeout_seconds <= 0:
        return _fail_closed(request_id, "native_pretool_deadline_exhausted")
    prepared = _request_payload(
        payload,
        request_id=request_id,
        harness=harness,
        cwd=cwd,
        home_dir=home_dir,
        guard_home=guard_home,
        deadline_budget_ms=int(timeout_seconds * 1_000),
    )
    if prepared is None:
        return _fail_closed(request_id, "native_pretool_request_too_large")
    request, request_bytes = prepared
    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _REQUIRED_FEATURE not in status.capabilities.features
    ):
        return _fail_closed(request_id, status.reason or "native_pretool_unavailable")

    timeout_seconds = min(timeout_seconds, 9.0)
    environment = _isolated_environment()
    features = set(status.capabilities.features)
    if {_RESIDENT_FEATURE, _RESIDENT_PROTOCOL_FEATURE} <= features:
        resident_envelope = json.dumps(
            {"operation": "pre_tool_decision", "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        resident_output = resident_native_request(
            executable=status.identity.path,
            identity_sha256=status.identity.sha256,
            guard_home=guard_home,
            environment=environment,
            payload=resident_envelope,
            timeout_seconds=timeout_seconds,
        )
        if resident_output is not None:
            try:
                resident_payload = json.loads(resident_output)
            except (UnicodeDecodeError, json.JSONDecodeError):
                resident_payload = None
            if _native_error(resident_payload) == "native_overloaded":
                native_record_overload(status.identity.sha256, guard_home)
                return _fail_closed(request_id, "native_pretool_overloaded")
            decoded = _decode_native_decision(resident_payload, request_id=request_id)
            if decoded is not None:
                native_record_resident_success(status.identity.sha256, guard_home)
                return decoded
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_pretool_resident_failed",
        )

    with native_oneshot_lease(status.identity.sha256, guard_home) as acquired:
        if not acquired:
            return _fail_closed(request_id, "native_pretool_oneshot_capacity")
        result = run_isolated_hook_process(
            (str(status.identity.path), "pretool", "--stdin"),
            input_text=request_bytes.decode("utf-8"),
            cwd=status.identity.path.parent,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit=_MAX_RESPONSE_BYTES,
        )
        if result.returncode != 0 or result.timed_out or result.output_limit_exceeded or result.containment_failed:
            native_record_oneshot_failure(
                status.identity.sha256,
                guard_home,
                reason="native_pretool_oneshot_failed",
            )
            return _fail_closed(request_id, "native_pretool_oneshot_failed")
        try:
            decoded = _decode_native_decision(json.loads(result.stdout), request_id=request_id)
        except json.JSONDecodeError:
            decoded = None
        if decoded is None:
            native_record_oneshot_failure(
                status.identity.sha256,
                guard_home,
                reason="native_pretool_invalid_response",
            )
            return _fail_closed(request_id, "native_pretool_invalid_response")
        native_record_oneshot_success(status.identity.sha256, guard_home)
        return decoded


__all__ = ["review_pre_tool_native"]
'''


NATIVE_COMMAND_COMPAT = r'''"""Retired command-shadow compatibility surface.

PreToolUse decisions are authoritative Rust decisions transported by
``native_pretool``. This module deliberately contains no Python parser,
classifier, evaluator, or policy-floor implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .native_pretool import review_pre_tool_native


def review_command_model_native(
    command: str,
    *,
    guard_home: Path,
    dialect: str = "posix",
    transport: str = "shell_string",
    extraction_provenance: str = "guard-shell",
    timeout_seconds: float = 0.25,
) -> dict[str, Any] | None:
    """Compatibility probe returning only Rust-produced command-model evidence."""

    if dialect != "posix" or transport != "shell_string":
        return None
    payload: dict[str, object] = {
        "tool_input": {"command": command},
        "extraction_provenance": extraction_provenance,
    }
    decision = review_pre_tool_native(
        payload,
        request_id="command-model-compat",
        harness="guard-command-model",
        cwd=None,
        home_dir=Path.home(),
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
    )
    model = decision.get("command_model")
    return model if isinstance(model, dict) else None


def native_command_shadow_proposal(*_args: object, **_kwargs: object) -> None:
    """The shadow proposal path is retired; Rust is the live authority."""

    return None


__all__ = ["native_command_shadow_proposal", "review_command_model_native"]
'''


NATIVE_PRETOOL_CLI = r'''"""Early CLI interception for Rust-authoritative PreToolUse hooks."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from uuid import uuid4

from .native_pretool import review_pre_tool_native


def _flag_value(argv: list[str], name: str) -> str | None:
    try:
        index = argv.index(name)
    except ValueError:
        return None
    if index + 1 >= len(argv):
        return None
    return argv[index + 1]


def _event_name(payload: object) -> str:
    if not isinstance(payload, dict):
        return ""
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _render(decision: dict[str, object]) -> dict[str, object]:
    allow = decision.get("decision") == "allow"
    reason = str(decision.get("reason") or "HOL Guard native PreToolUse decision")
    reason_code = str(decision.get("reason_code") or "native_pretool_decision")
    permission = "allow" if allow else "deny"
    result: dict[str, object] = {
        "decision": permission,
        "permissionDecision": permission,
        "continue": allow,
        "policy_action": decision.get("policy_action"),
        "minimum_action": decision.get("minimum_action"),
        "reason": reason,
        "reason_code": reason_code,
        "native_authority": "rust",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        },
    }
    if not allow:
        result["stopReason"] = reason
    return result


def maybe_handle_native_pretool_cli(argv: list[str] | tuple[str, ...]) -> int | None:
    """Intercept only Guard hook PreToolUse; restore stdin for every other command."""

    values = list(argv)
    if "hook" not in values or "--harness" not in values:
        return None
    raw = sys.stdin.read()
    sys.stdin = io.StringIO(raw)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if _event_name(payload) != "PreToolUse" or not isinstance(payload, dict):
        return None
    harness = _flag_value(values, "--harness") or "unknown"
    guard_home_value = _flag_value(values, "--guard-home")
    home_value = _flag_value(values, "--home")
    workspace_value = _flag_value(values, "--workspace")
    home_dir = Path(home_value).expanduser() if home_value else Path.home()
    guard_home = Path(guard_home_value).expanduser() if guard_home_value else home_dir / ".hol-guard"
    workspace = Path(workspace_value).expanduser() if workspace_value else None
    decision = review_pre_tool_native(
        payload,
        request_id=uuid4().hex,
        harness=harness,
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
    )
    print(json.dumps(_render(decision), separators=(",", ":"), ensure_ascii=False))
    return 0 if decision.get("decision") == "allow" else 2


__all__ = ["maybe_handle_native_pretool_cli"]
'''


AUTHORITY_GUARD = r'''#!/usr/bin/env python3
"""Fail CI if supported PreToolUse can reach Python semantic evaluation."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_IMPORT_PARTS = {
    "command_evaluation",
    "command_model",
    "command_rules",
    "hook_review_engine",
    "risk",
    "secret_file_requests",
}
FORBIDDEN_CALLS = {
    "evaluate_command",
    "evaluate_command_request",
    "HookReviewEngine",
    "run_guard_command",
}


def imports_and_calls(path: Path) -> tuple[set[str], set[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    return imports, calls


def main() -> int:
    transport = ROOT / "src/codex_plugin_scanner/guard/native_pretool.py"
    imports, calls = imports_and_calls(transport)
    bad_imports = sorted(
        value for value in imports if any(part in value.split(".") for part in FORBIDDEN_IMPORT_PARTS)
    )
    bad_calls = sorted(calls & FORBIDDEN_CALLS)
    if bad_imports or bad_calls:
        raise SystemExit(f"Python semantic dependency reached native PreTool transport: imports={bad_imports}, calls={bad_calls}")

    compatibility = (ROOT / "src/codex_plugin_scanner/guard/native_command_model.py").read_text(encoding="utf-8")
    for forbidden in ("evaluate_command(", "CanonicalCommand(", "CommandSegment("):
        if forbidden in compatibility:
            raise SystemExit(f"Retired Python command semantics remain: {forbidden}")

    worker = (ROOT / "src/codex_plugin_scanner/guard/daemon/hook_worker.py").read_text(encoding="utf-8")
    required_worker = (
        'if event_name == "PreToolUse":',
        "review_pre_tool_native(",
        "_harness_json_from_native_pretool",
    )
    for required in required_worker:
        if required not in worker:
            raise SystemExit(f"Daemon PreToolUse Rust authority anchor missing: {required}")
    pretool_branch = worker.split('if event_name == "PreToolUse":', 1)[1].split('if event_name != "PostToolUse":', 1)[0]
    for forbidden in ("self.engine.review", "run_guard_command", "evaluate_command"):
        if forbidden in pretool_branch:
            raise SystemExit(f"PreToolUse branch reaches Python semantics: {forbidden}")

    cli = (ROOT / "src/codex_plugin_scanner/cli.py").read_text(encoding="utf-8")
    if "maybe_handle_native_pretool_cli" not in cli:
        raise SystemExit("CLI PreToolUse native interception is missing")

    runtime = (ROOT / "rust/crates/guard-runtime/src/main.rs").read_text(encoding="utf-8")
    for required in ("PreToolDecision", "evaluate_pre_tool_value", 'command == "pretool"'):
        if required not in runtime:
            raise SystemExit(f"Rust PreToolUse authority anchor missing: {required}")
    print("Rust PreToolUse authority: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


INTEGRATION = r'''#!/usr/bin/env python3
"""Real-binary integration checks for Rust-authoritative PreToolUse."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


def request(command: str, request_id: str) -> bytes:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": request_id,
            "harness": "integration",
            "event_name": "PreToolUse",
            "payload": {"hook_event_name": "PreToolUse", "tool_input": {"command": command}},
            "cwd": os.getcwd(),
            "home_dir": os.getcwd(),
            "guard_home": os.getcwd(),
            "deadline_budget_ms": 5_000,
        },
        separators=(",", ":"),
    ).encode()


def run(runtime: Path, command: str, request_id: str) -> dict[str, object]:
    completed = subprocess.run(
        [str(runtime), "pretool", "--stdin"],
        input=request(command, request_id),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        timeout=10,
    )
    result = json.loads(completed.stdout)
    assert result["authority"] == "rust"
    assert result["request_id"] == request_id
    return result


def main() -> int:
    runtime = Path(os.environ["HOL_GUARD_NATIVE_BINARY"]).resolve(strict=True)
    assert run(runtime, "pwd", "allow-pwd")["decision"] == "allow"
    assert run(runtime, "git status --short", "allow-git-status")["decision"] == "allow"
    assert run(runtime, "rg -n native src", "allow-rg")["decision"] == "allow"

    destructive = run(runtime, "rm -rf /", "block-rm")
    assert destructive["decision"] == "deny"
    assert destructive["policy_action"] == "block"

    network = run(runtime, "curl https://example.com/upload", "review-curl")
    assert network["decision"] == "deny"
    assert network["policy_action"] == "review"

    uncertain = run(runtime, "bash -lc 'echo unsafe'", "review-wrapper")
    assert uncertain["decision"] == "deny"

    malformed = subprocess.run(
        [str(runtime), "pretool", "--stdin"],
        input=b'{"protocol_version":1,',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    assert malformed.returncode != 0

    with tempfile.TemporaryDirectory(prefix="hol-guard-rust-pretool-") as temp:
        environment = dict(os.environ)
        environment["HOL_GUARD_NATIVE"] = "force"
        environment["HOL_GUARD_NATIVE_BINARY"] = str(runtime)
        probe = subprocess.run(
            [
                os.environ.get("PYTHON", "python3"),
                "-c",
                "from pathlib import Path; "
                "from codex_plugin_scanner.guard.native_pretool import review_pre_tool_native; "
                "r=review_pre_tool_native({'hook_event_name':'PreToolUse','tool_input':{'command':'pwd'}},request_id='python-transport',harness='integration',cwd=Path.cwd(),home_dir=Path.cwd(),guard_home=Path(r'" + temp.replace("'", "\\'") + "')); "
                "assert r['authority']=='rust' and r['decision']=='allow'",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=True,
        )
        assert probe.returncode == 0

    print("Rust PreToolUse real-binary integration: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


PERMANENT_WORKFLOW = r'''name: Rust PreToolUse authority

on:
  pull_request:
    branches: [release/3.0]
    paths:
      - "rust/**"
      - "src/codex_plugin_scanner/cli.py"
      - "src/codex_plugin_scanner/guard/native_*.py"
      - "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
      - "src/codex_plugin_scanner/guard/cli/commands_hook*.py"
      - "scripts/ci/check_rust_pretool_authority.py"
      - "scripts/integration/rust_pretool_authority.py"
      - ".github/workflows/rust-command-shadow.yml"
  push:
    branches: [release/3.0]
    paths:
      - "rust/**"
      - "src/codex_plugin_scanner/cli.py"
      - "src/codex_plugin_scanner/guard/native_*.py"
      - "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
      - "src/codex_plugin_scanner/guard/cli/commands_hook*.py"
      - "scripts/ci/check_rust_pretool_authority.py"
      - "scripts/integration/rust_pretool_authority.py"
      - ".github/workflows/rust-command-shadow.yml"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: rust-pretool-authority-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

jobs:
  real-binary-integration:
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
        with:
          persist-credentials: false
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405
        with:
          python-version: "3.12"
      - uses: astral-sh/setup-uv@fac544c07dec837d0ccb6301d7b5580bf5edae39
        with:
          version: "0.9.26"
          enable-cache: true
      - run: uv sync --frozen --extra dev --python 3.12
      - name: Install pinned Rust toolchain
        run: |
          rustup toolchain install 1.88.0 --profile minimal --component rustfmt --component clippy
          rustup default 1.88.0
      - name: Enforce source authority
        run: uv run --no-sync python scripts/ci/check_rust_pretool_authority.py
      - name: Build native runtime
        env:
          HOL_GUARD_BUILD_SHA: ${{ github.sha }}
        run: |
          VERSION=$(uv run --no-sync python scripts/sync_repo_version.py --check)
          export HOL_GUARD_PACKAGE_VERSION="$VERSION"
          cargo fmt --manifest-path rust/Cargo.toml --all --check
          cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings
          cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime
      - name: Run real-binary PreToolUse integration
        env:
          HOL_GUARD_NATIVE: force
          HOL_GUARD_NATIVE_BINARY: ${{ github.workspace }}/rust/target/release/hol-guard-runtime
          PYTHON: ${{ github.workspace }}/.venv/bin/python
        run: uv run --no-sync python scripts/integration/rust_pretool_authority.py
'''


TASKS = """# Rust Authority Migration Batch 1: Tasks T001-T100

Base branch: `release/3.0`

Invariant: supported `PreToolUse` decisions are produced only by the Rust runtime. Python may transport or render a native result but may not parse, classify, lower, replace, or synthesize the semantic decision. There is no strict mode. Rust is the default authority, and native failure fails closed.

""" + "\n".join(
    f"- [x] T{index:03d} {description}"
    for index, description in enumerate(
        [
            "Pin the release/3.0 migration baseline.",
            "Define the Rust-only PreToolUse authority invariant.",
            "Add a native PreToolUse request operation.",
            "Add a native final-decision response contract.",
            "Bind responses to exact request identifiers.",
            "Require protocol-version equality.",
            "Reject non-PreToolUse native requests.",
            "Extract command text inside Rust.",
            "Bound command request bytes.",
            "Reuse the Rust canonical command parser.",
            "Return review for uncertain parsing.",
            "Return review for missing commands.",
            "Return review for oversized commands.",
            "Create a Rust hard-block executable floor.",
            "Block destructive filesystem executables.",
            "Block disk and partition mutation executables.",
            "Block shutdown and reboot executables.",
            "Review shell interpreter boundaries.",
            "Review network transfer boundaries.",
            "Review package-manager boundaries.",
            "Review container and cluster boundaries.",
            "Review PATH overrides.",
            "Add conservative bounded read-only allows.",
            "Allow a bounded pwd probe.",
            "Allow bounded identity probes.",
            "Allow bounded uname probes.",
            "Allow bounded ls operands.",
            "Allow bounded cat operands.",
            "Allow bounded head operands.",
            "Allow bounded tail operands.",
            "Allow bounded wc operands.",
            "Allow bounded stat operands.",
            "Allow bounded printf literals.",
            "Allow bounded ripgrep searches.",
            "Allow bounded grep searches.",
            "Reject sensitive search operands.",
            "Reject search preprocessor execution.",
            "Add bounded Git status authority.",
            "Add bounded Git rev-parse authority.",
            "Add bounded Git ls-files authority.",
            "Add bounded Git show-ref authority.",
            "Add bounded Git branch reads.",
            "Add bounded Git diff reads.",
            "Add bounded Git log reads.",
            "Add bounded Git show reads.",
            "Reject Git external diff execution.",
            "Reject Git textconv execution.",
            "Reject Git output-file writes.",
            "Expose native PreToolUse capabilities.",
            "Expose resident native PreToolUse capability.",
            "Add native one-shot pretool command.",
            "Add resident pre_tool_decision operation.",
            "Encode bounded native responses.",
            "Keep unsafe Rust forbidden.",
            "Create a transport-only Python bridge.",
            "Remove Python command parsing from the bridge.",
            "Remove Python command classification from the bridge.",
            "Remove Python policy evaluation from the bridge.",
            "Validate native response shape in Python.",
            "Validate authority identity in Python.",
            "Validate native allow consistency.",
            "Validate native deny consistency.",
            "Fail closed on native unavailability.",
            "Fail closed on native incompatibility.",
            "Fail closed on resident overload.",
            "Fail closed on resident malformed output.",
            "Fail closed on resident transport failure.",
            "Fail closed on one-shot capacity failure.",
            "Fail closed on one-shot timeout.",
            "Fail closed on one-shot containment failure.",
            "Fail closed on one-shot malformed output.",
            "Record native resident successes.",
            "Record native resident failures.",
            "Record native one-shot successes.",
            "Record native one-shot failures.",
            "Retire Python command-shadow semantics.",
            "Keep a non-authoritative compatibility probe.",
            "Return no Python shadow proposal.",
            "Route daemon PreToolUse to Rust first.",
            "Prevent HookReviewEngine use in daemon PreToolUse.",
            "Render native allow decisions for harnesses.",
            "Render native deny decisions for harnesses.",
            "Preserve native reason codes in harness output.",
            "Preserve native policy actions in harness output.",
            "Add early CLI PreToolUse interception.",
            "Restore stdin for non-PreToolUse commands.",
            "Use native authority in CLI fallback.",
            "Return hook exit zero only for native allow.",
            "Return hook exit two for native deny.",
            "Add a static Python semantic-reachability guard.",
            "Reject evaluator imports in native transport.",
            "Reject evaluator calls in native transport.",
            "Reject Python command model construction.",
            "Verify daemon Rust authority anchors.",
            "Verify CLI Rust authority anchor.",
            "Verify native runtime authority anchors.",
            "Add real-binary benign-command integration.",
            "Add real-binary destructive-command integration.",
            "Add real-binary review-command integration.",
            "Add malformed-request integration coverage.",
        ],
        start=1,
    )
) + "\n"


def patch_runtime() -> None:
    path = "rust/crates/guard-runtime/src/main.rs"
    source = read(path)
    if "mod pretool;" not in source:
        source = replace_once(source, "mod hardening;", "mod hardening;\nmod pretool;", label=path)
    if "PreToolDecision(Value)" not in source:
        source = replace_once(
            source,
            "    CommandModel(CommandModelRequestV1),\n    Health(Value),",
            "    CommandModel(CommandModelRequestV1),\n    PreToolDecision(Value),\n    Health(Value),",
            label=path,
        )
    source = source.replace('"pre-tool-command-model-shadow-v1".into(),', '"pre-tool-authority-v1".into(),')
    source = source.replace('"resident-command-model-shadow-v1".into(),', '"resident-pre-tool-authority-v1".into(),')
    if "fn evaluate_pre_tool_bytes" not in source:
        anchor = "fn evaluate_command_model_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {\n    let value = strict_json_value(bytes)?;\n    let request: CommandModelRequestV1 = serde_json::from_value(value)\n        .map_err(|_| \"native_command_model_invalid_json\".to_owned())?;\n    evaluate_command_model_request(&request)\n}\n"
        ensure_contains(source, anchor, label=path)
        source = source.replace(
            anchor,
            anchor
            + "\nfn evaluate_pre_tool_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {\n"
            + "    let value = strict_json_value(bytes)?;\n"
            + "    let response = pretool::evaluate_pre_tool_value(value)?;\n"
            + "    encode_response(&response)\n"
            + "}\n",
            1,
        )
    if "ResidentOperationV1::PreToolDecision" not in source:
        anchor = "        ResidentRequestV1::Operation(ResidentOperationV1::CommandModel(request)) => {\n            evaluate_command_model_request(&request)\n        }\n"
        ensure_contains(source, anchor, label=path)
        source = source.replace(
            anchor,
            anchor
            + "        ResidentRequestV1::Operation(ResidentOperationV1::PreToolDecision(request)) => {\n"
            + "            encode_response(&pretool::evaluate_pre_tool_value(request)?)\n"
            + "        }\n",
            1,
        )
    if 'command == "pretool"' not in source:
        anchor = "        [command, flag] if command == \"command-model\" && flag == \"--stdin\" => {\n            let bytes = read_stdin_bounded()?;\n            let response = evaluate_command_model_bytes(&bytes)?;\n            write_bytes_response(&response)\n        }\n"
        ensure_contains(source, anchor, label=path)
        source = source.replace(
            anchor,
            anchor
            + "        [command, flag] if command == \"pretool\" && flag == \"--stdin\" => {\n"
            + "            let bytes = read_stdin_bounded()?;\n"
            + "            let response = evaluate_pre_tool_bytes(&bytes)?;\n"
            + "            write_bytes_response(&response)\n"
            + "        }\n",
            1,
        )
        source = source.replace(
            "hook --stdin | command-model --stdin | serve --socket PATH",
            "hook --stdin | command-model --stdin | pretool --stdin | serve --socket PATH",
        )
    write(path, source)


def patch_hook_worker() -> None:
    path = "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    source = read(path)
    if "from ..native_pretool import review_pre_tool_native" not in source:
        source = replace_once(
            source,
            "from ..native_runtime import native_mode, review_post_tool_native",
            "from ..native_pretool import review_pre_tool_native\nfrom ..native_runtime import native_mode, review_post_tool_native",
            label=path,
        )
    old = "        event_name = self._hook_event_name(payload)\n        if event_name != \"PostToolUse\":\n            raise HookWorkerUnsupported(f\"fast path only supports PostToolUse, got event={event_name}\")\n\n        request = self._request_from_payload("
    if 'if event_name == "PreToolUse":' not in source:
        ensure_contains(source, old, label=path)
        new = "        event_name = self._hook_event_name(payload)\n        if event_name == \"PreToolUse\":\n            harness = self._runtime_harness(params) or default_harness\n            request_id = str(payload.get(\"request_id\") or payload.get(\"requestId\") or \"native-pretool\")\n            decision = review_pre_tool_native(\n                payload,\n                request_id=request_id,\n                harness=harness,\n                cwd=workspace,\n                home_dir=home_dir,\n                guard_home=guard_home,\n                timeout_seconds=max(0.05, min(9.0, (deadline - __import__(\"time\").monotonic()) if deadline is not None else 0.75)),\n            )\n            return _harness_json_from_native_pretool(harness, decision)\n        if event_name != \"PostToolUse\":\n            raise HookWorkerUnsupported(f\"fast path supports PreToolUse and PostToolUse, got event={event_name}\")\n\n        request = self._request_from_payload("
        source = source.replace(old, new, 1)
    if "def _harness_json_from_native_pretool" not in source:
        anchor = "def _canonical_hook_harness(harness: str) -> str:\n    return harness.strip().lower().replace(\"_\", \"-\")\n"
        ensure_contains(source, anchor, label=path)
        addition = '''\n\ndef _harness_json_from_native_pretool(\n    harness: str,\n    decision: Mapping[str, object],\n) -> dict[str, object]:\n    allow = decision.get("decision") == "allow"\n    permission = "allow" if allow else "deny"\n    reason = str(decision.get("reason") or "HOL Guard native PreToolUse decision")\n    reason_code = str(decision.get("reason_code") or "native_pretool_decision")\n    payload: dict[str, object] = {\n        "decision": permission,\n        "permissionDecision": permission,\n        "continue": allow,\n        "policy_action": decision.get("policy_action"),\n        "minimum_action": decision.get("minimum_action"),\n        "reason": reason,\n        "reason_code": reason_code,\n        "native_authority": "rust",\n        "hookSpecificOutput": {\n            "hookEventName": "PreToolUse",\n            "permissionDecision": permission,\n            "permissionDecisionReason": reason,\n        },\n    }\n    if not allow:\n        payload["stopReason"] = reason\n    return payload\n'''
        source = source.replace(anchor, anchor + addition, 1)
    write(path, source)


def patch_cli() -> None:
    path = "src/codex_plugin_scanner/cli.py"
    source = read(path)
    if "maybe_handle_native_pretool_cli" in source:
        return
    tree = ast.parse(source)
    main = next((node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "main"), None)
    if main is None or not main.body:
        raise RuntimeError(f"{path}: main() was not found")
    insertion_line = main.body[0].lineno
    if isinstance(main.body[0], ast.Expr) and isinstance(main.body[0].value, ast.Constant) and isinstance(main.body[0].value.value, str):
        insertion_line = main.body[0].end_lineno + 1
    lines = source.splitlines(keepends=True)
    snippet = (
        "    from .guard.native_pretool_cli import maybe_handle_native_pretool_cli\n"
        "\n"
        "    native_pretool_result = maybe_handle_native_pretool_cli(sys.argv[1:])\n"
        "    if native_pretool_result is not None:\n"
        "        return native_pretool_result\n"
        "\n"
    )
    lines.insert(insertion_line - 1, snippet)
    write(path, "".join(lines))


def main() -> int:
    write("rust/crates/guard-runtime/src/pretool.rs", PRETOOL_RS)
    patch_runtime()
    write("src/codex_plugin_scanner/guard/native_pretool.py", NATIVE_PRETOOL_PY)
    write("src/codex_plugin_scanner/guard/native_command_model.py", NATIVE_COMMAND_COMPAT)
    write("src/codex_plugin_scanner/guard/native_pretool_cli.py", NATIVE_PRETOOL_CLI)
    patch_hook_worker()
    patch_cli()
    write("scripts/ci/check_rust_pretool_authority.py", AUTHORITY_GUARD)
    write("scripts/integration/rust_pretool_authority.py", INTEGRATION)
    write(".github/workflows/rust-command-shadow.yml", PERMANENT_WORKFLOW)
    write("docs/guard/rust-migration-batch-1-tasks.md", TASKS)
    print("Applied Rust PreToolUse authority batch 1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
