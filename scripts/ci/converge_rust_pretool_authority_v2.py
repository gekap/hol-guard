#!/usr/bin/env python3
"""Converge onto Rust PreToolUse authority without breaking command-model evidence APIs."""

from __future__ import annotations

from pathlib import Path


def patch_guard_command() -> None:
    path = Path("rust/crates/guard-command/src/lib.rs")
    source = path.read_text(encoding="utf-8")
    if "pub struct PreToolDecisionV1" in source and "pub fn evaluate_pre_tool" in source:
        return
    marker = "\n#[cfg(test)]\nmod tests {\n"
    if marker not in source:
        raise RuntimeError("guard-command test marker not found")
    addition = r'''

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreToolDecisionV1 {
    pub decision: String,
    pub minimum_action: String,
    pub reason_code: String,
    pub reason: String,
    pub explicitly_benign: bool,
    pub command_model: CanonicalCommandV1,
}

fn native_pretool_decision(
    command_model: CanonicalCommandV1,
    minimum_action: &str,
    reason_code: &str,
    reason: &str,
) -> PreToolDecisionV1 {
    let explicitly_benign = minimum_action == "allow";
    PreToolDecisionV1 {
        decision: if explicitly_benign { "allow" } else { "deny" }.to_owned(),
        minimum_action: minimum_action.to_owned(),
        reason_code: reason_code.to_owned(),
        reason: reason.to_owned(),
        explicitly_benign,
        command_model,
    }
}

fn native_sensitive_command(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase().replace('\\', "/");
    let sensitive = [
        "/.ssh/",
        "/.aws/credentials",
        "/.docker/config.json",
        "/.kube/config",
        "/.git-credentials",
        "/.npmrc",
        "/.pypirc",
        "/.netrc",
        "id_rsa",
        "id_ed25519",
        "aws_secret_access_key",
        "private_key",
    ];
    sensitive.iter().any(|needle| lowered.contains(needle))
        || lowered.contains("printenv")
        || lowered.contains("os.environ")
        || lowered.contains("process.env")
}

fn native_destructive_command(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    (lowered.contains("rm -rf") || lowered.contains("rm -fr"))
        && [" /", " -- /", " $home", " ~"]
            .iter()
            .any(|needle| lowered.contains(needle))
}

fn native_exfiltration_command(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    let network = ["curl", "wget", "nc ", "netcat", "scp ", "rsync "];
    let upload = [" -d ", " --data", " --upload-file", " -t ", "@-", "@~", "@/"];
    network.iter().any(|needle| lowered.contains(needle))
        && upload.iter().any(|needle| lowered.contains(needle))
}

fn native_exact_safe_command(model: &CanonicalCommandV1) -> bool {
    if model.confidence != "exact" || model.path_overridden || model.segments.is_empty() {
        return false;
    }
    model.segments.iter().all(|segment| {
        let Some(executable) = segment.executable.as_deref() else {
            return false;
        };
        let basename = executable_basename(executable);
        match basename {
            "pwd" | "true" | "echo" | "printf" | "which" => true,
            "git" => segment.arguments.first().is_some_and(|value| {
                matches!(
                    value.as_str(),
                    "status" | "diff" | "log" | "show" | "rev-parse" | "ls-files"
                )
            }),
            "rg" | "grep" => !native_sensitive_command(&segment.text),
            _ => false,
        }
    })
}

pub fn evaluate_pre_tool(request: &CommandModelRequestV1) -> Result<PreToolDecisionV1, String> {
    let model = parse_command(request)?;
    let normalized = model.normalized_text.clone();
    if native_destructive_command(&normalized) {
        return Ok(native_pretool_decision(
            model,
            "block",
            "native_destructive_command",
            "HOL Guard blocked a destructive command before execution.",
        ));
    }
    if native_sensitive_command(&normalized) && native_exfiltration_command(&normalized) {
        return Ok(native_pretool_decision(
            model,
            "block",
            "native_secret_exfiltration",
            "HOL Guard blocked a command that combines sensitive data access with network transfer.",
        ));
    }
    if native_sensitive_command(&normalized) {
        return Ok(native_pretool_decision(
            model,
            "review",
            "native_sensitive_access_review",
            "HOL Guard requires review before this command can access sensitive local data.",
        ));
    }
    if model.path_overridden {
        return Ok(native_pretool_decision(
            model,
            "review",
            "native_path_override_review",
            "HOL Guard requires review because this command overrides executable resolution.",
        ));
    }
    if native_exact_safe_command(&model) {
        return Ok(native_pretool_decision(
            model,
            "allow",
            "native_exact_safe_command",
            "The Rust command authority proved this bounded command explicitly benign.",
        ));
    }
    Ok(native_pretool_decision(
        model,
        "review",
        "native_command_review_required",
        "HOL Guard requires review because the Rust authority could not prove this command explicitly benign.",
    ))
}
'''
    path.write_text(source.replace(marker, addition + marker, 1), encoding="utf-8")


def patch_runtime() -> None:
    path = Path("rust/crates/guard-runtime/src/main.rs")
    source = path.read_text(encoding="utf-8")
    source = source.replace(
        "use guard_command::{parse_command, CommandModelRequestV1};",
        "use guard_command::{evaluate_pre_tool, parse_command, CommandModelRequestV1};",
        1,
    )
    if "PreToolUse(CommandModelRequestV1)" not in source:
        source = source.replace(
            "    CommandModel(CommandModelRequestV1),\n    Health(Value),\n",
            "    CommandModel(CommandModelRequestV1),\n    PreToolUse(CommandModelRequestV1),\n    Health(Value),\n",
            1,
        )
    capability_anchor = '        "resident-command-model-shadow-v1".into(),\n'
    if '"pre-tool-command-authority-v1".into()' not in source:
        if capability_anchor not in source:
            raise RuntimeError("runtime capability anchor not found")
        source = source.replace(
            capability_anchor,
            capability_anchor + '        "pre-tool-command-authority-v1".into(),\n',
            1,
        )
    function_anchor = "\nfn evaluate_command_model_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {\n"
    if "fn evaluate_pre_tool_bytes(" not in source:
        addition = r'''

fn evaluate_pre_tool_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let request: CommandModelRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_pre_tool_invalid_json".to_owned())?;
    encode_response(&evaluate_pre_tool(&request)?)
}
'''
        if function_anchor not in source:
            raise RuntimeError("runtime command-model function anchor not found")
        source = source.replace(function_anchor, addition + function_anchor, 1)
    resident_anchor = '''        ResidentRequestV1::Operation(ResidentOperationV1::CommandModel(request)) => {
            evaluate_command_model_request(&request)
        }
        ResidentRequestV1::Operation(ResidentOperationV1::Health(_request)) => {
'''
    if "ResidentOperationV1::PreToolUse" not in source:
        replacement = '''        ResidentRequestV1::Operation(ResidentOperationV1::CommandModel(request)) => {
            evaluate_command_model_request(&request)
        }
        ResidentRequestV1::Operation(ResidentOperationV1::PreToolUse(request)) => {
            encode_response(&evaluate_pre_tool(&request)?)
        }
        ResidentRequestV1::Operation(ResidentOperationV1::Health(_request)) => {
'''
        if resident_anchor not in source:
            raise RuntimeError("runtime resident command marker not found")
        source = source.replace(resident_anchor, replacement, 1)
    command_anchor = '''        [command, flag] if command == "command-model" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = evaluate_command_model_bytes(&bytes)?;
            write_bytes_response(&response)
        }
'''
    if 'command == "pre-tool"' not in source:
        replacement = command_anchor + '''        [command, flag] if command == "pre-tool" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = evaluate_pre_tool_bytes(&bytes)?;
            write_bytes_response(&response)
        }
'''
        if command_anchor not in source:
            raise RuntimeError("runtime command dispatch marker not found")
        source = source.replace(command_anchor, replacement, 1)
    source = source.replace(
        "hook --stdin | command-model --stdin | serve --socket PATH",
        "hook --stdin | command-model --stdin | pre-tool --stdin | serve --socket PATH",
    )
    path.write_text(source, encoding="utf-8")


def patch_native_command_bridge() -> None:
    path = Path("src/codex_plugin_scanner/guard/native_command_model.py")
    source = path.read_text(encoding="utf-8")
    source = source.replace(
        '"""Shadow-only Python bridge to the native command model.\n\nThis module never makes a PreToolUse decision. It exists to exercise and compare\nthe native parser through the same version-matched resident runtime used by the\nPostToolUse path. Python remains authoritative until later rollout gates land.\n"""',
        '"""Transport bridges to native command evidence and Rust PreToolUse authority.\n\nPython validates request-bound native responses but does not parse commands,\nclassify risk, or calculate the authoritative minimum action.\n"""',
    )
    source = source.replace("from .runtime.command_evaluation import evaluate_command\n", "")
    constant_anchor = '_NATIVE_SHADOW_PROPOSAL_VERSION = "guard.command-shadow-proposal.rust-parser.v1"\n'
    if "_PRETOOL_REQUIRED_FEATURE" not in source:
        if constant_anchor not in source:
            raise RuntimeError("native command constant anchor not found")
        source = source.replace(
            constant_anchor,
            constant_anchor + '_PRETOOL_REQUIRED_FEATURE = "pre-tool-command-authority-v1"\n',
            1,
        )
    insertion_anchor = "\ndef _canonical_command_from_native(\n"
    if "def review_pre_tool_native(" not in source:
        addition = r'''

def _decode_pre_tool(payload: object, *, command: str) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    decision = payload.get("decision")
    action = payload.get("minimum_action")
    model = payload.get("command_model")
    if (
        decision not in {"allow", "deny"}
        or action not in {"allow", "review", "block"}
        or not isinstance(payload.get("reason_code"), str)
        or not isinstance(payload.get("reason"), str)
        or not isinstance(payload.get("explicitly_benign"), bool)
        or not isinstance(model, dict)
        or model.get("normalized_text") != command.strip()
    ):
        return None
    if payload["explicitly_benign"] != (decision == "allow" and action == "allow"):
        return None
    return payload


def review_pre_tool_native(
    command: str,
    *,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path | None,
    timeout_seconds: float = 0.5,
) -> dict[str, Any] | None:
    del cwd, home_dir
    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _PRETOOL_REQUIRED_FEATURE not in status.capabilities.features
        or timeout_seconds <= 0
    ):
        return None
    request = {
        "command": command,
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
    }
    encoded = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > _MAX_REQUEST_BYTES:
        return None
    timeout_seconds = min(timeout_seconds, 1.0)
    environment = _isolated_environment()
    if {_RESIDENT_PROTOCOL_FEATURE} <= set(status.capabilities.features):
        resident_envelope = json.dumps(
            {"operation": "pre_tool_use", "request": request},
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
                return None
            decoded = _decode_pre_tool(resident_payload, command=command)
            if decoded is not None:
                native_record_resident_success(status.identity.sha256, guard_home)
                return decoded
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_pre_tool_resident_unavailable",
        )
    with native_oneshot_lease(status.identity.sha256, guard_home) as acquired:
        if not acquired:
            return None
        result = run_isolated_hook_process(
            (str(status.identity.path), "pre-tool", "--stdin"),
            input_text=encoded.decode("utf-8"),
            cwd=status.identity.path.parent,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit=_MAX_RESPONSE_BYTES,
        )
        if result.returncode != 0 or result.timed_out or result.output_limit_exceeded or result.containment_failed:
            native_record_oneshot_failure(
                status.identity.sha256,
                guard_home,
                reason="native_pre_tool_oneshot_failed",
            )
            return None
        try:
            decoded = _decode_pre_tool(json.loads(result.stdout), command=command)
        except json.JSONDecodeError:
            decoded = None
        if decoded is None:
            native_record_oneshot_failure(
                status.identity.sha256,
                guard_home,
                reason="native_pre_tool_oneshot_invalid",
            )
            return None
        native_record_oneshot_success(status.identity.sha256, guard_home)
        return decoded

'''
        if insertion_anchor not in source:
            raise RuntimeError("native command canonical conversion anchor not found")
        source = source.replace(insertion_anchor, addition + insertion_anchor, 1)
    function_start = source.find("\ndef native_command_shadow_proposal(")
    function_end = source.find("\n\n__all__ = [", function_start)
    if function_start == -1 or function_end == -1:
        raise RuntimeError("native command shadow proposal region not found")
    replacement = r'''

def native_command_shadow_proposal(
    command: str,
    *,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path | None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
) -> CommandShadowProposal | None:
    del compatibility_action_class, compatibility_reason
    payload = review_pre_tool_native(
        command,
        guard_home=guard_home,
        cwd=cwd,
        home_dir=home_dir,
    )
    if payload is None:
        return None
    action = payload.get("minimum_action")
    if action not in {"allow", "review", "block"}:
        return None
    return CommandShadowProposal(
        decision=action,
        cohorts=frozenset({CommandShadowCohort.BASELINE}),
        version=_NATIVE_SHADOW_PROPOSAL_VERSION,
    )
'''
    source = source[:function_start] + replacement + source[function_end:]
    source = source.replace(
        '    "review_command_model_native",\n]',
        '    "review_command_model_native",\n    "review_pre_tool_native",\n]',
    )
    path.write_text(source, encoding="utf-8")


def patch_hook_worker() -> None:
    path = Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py")
    source = path.read_text(encoding="utf-8")
    native_import = "from ..native_runtime import native_mode, review_post_tool_native\n"
    if "from ..native_command_model import review_pre_tool_native" not in source:
        if native_import not in source:
            raise RuntimeError("HookWorker native import marker not found")
        source = source.replace(
            native_import,
            "from ..native_command_model import review_pre_tool_native\n" + native_import,
            1,
        )
    dispatch = '''        event_name = self._hook_event_name(payload)
        if event_name != "PostToolUse":
            raise HookWorkerUnsupported(f"fast path only supports PostToolUse, got event={event_name}")

        request = self._request_from_payload(
'''
    if dispatch in source:
        replacement = '''        event_name = self._hook_event_name(payload)
        if event_name == "PreToolUse":
            command = _pre_tool_command(payload)
            if command is None:
                return post_tool_fail_safe_response(
                    harness,
                    reason="HOL Guard could not extract a command for native PreToolUse review.",
                    reason_code="native_pre_tool_command_missing",
                )
            native = review_pre_tool_native(
                command,
                guard_home=guard_home,
                cwd=workspace,
                home_dir=home_dir,
            )
            if native is None:
                return post_tool_fail_safe_response(
                    harness,
                    reason="HOL Guard could not complete the native PreToolUse decision safely.",
                    reason_code="native_pre_tool_unavailable",
                )
            return _harness_json_from_native_pre_tool(harness, native)
        if event_name != "PostToolUse":
            raise HookWorkerUnsupported(f"fast path supports PreToolUse and PostToolUse, got event={event_name}")

        request = self._request_from_payload(
'''
        source = source.replace(dispatch, replacement, 1)
    elif 'event_name == "PreToolUse"' not in source:
        raise RuntimeError("HookWorker dispatch marker not found")
    helper_anchor = "\ndef _canonical_hook_harness(harness: str) -> str:\n"
    if "def _pre_tool_command(" not in source:
        helper = '''
def _pre_tool_command(payload: Mapping[str, object]) -> str | None:
    for candidate in (payload.get("tool_input"), payload.get("arguments"), payload):
        if not isinstance(candidate, Mapping):
            continue
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


def _harness_json_from_native_pre_tool(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    action = response.get("minimum_action")
    reason = str(response.get("reason") or "HOL Guard requires native review before execution.")
    reason_code = str(response.get("reason_code") or "native_pre_tool_review")
    if action == "allow" and response.get("decision") == "allow":
        return {
            "decision": "allow",
            "continue": True,
            "policy_action": "allow",
            "reason_code": reason_code,
            "hookSpecificOutput": {"hookEventName": "PreToolUse"},
        }
    return post_tool_fail_safe_response(harness, reason=reason, reason_code=reason_code)

'''
        if helper_anchor not in source:
            raise RuntimeError("HookWorker helper marker not found")
        source = source.replace(helper_anchor, "\n" + helper + helper_anchor, 1)
    path.write_text(source, encoding="utf-8")


def main() -> int:
    patch_guard_command()
    patch_runtime()
    patch_native_command_bridge()
    patch_hook_worker()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
