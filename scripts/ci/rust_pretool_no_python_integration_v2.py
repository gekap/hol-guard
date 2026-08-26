#!/usr/bin/env python3
"""Trace a real supported PreToolUse wire path and prove it never executes Python."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Invocation:
    name: str
    argv: tuple[str, ...]
    payload_kind: str


def canonical_request(command: str) -> bytes:
    return json.dumps(
        {
            "command": command,
            "dialect": "posix",
            "transport": "shell_string",
            "extraction_provenance": "guard-shell",
        },
        separators=(",", ":"),
    ).encode("utf-8")


def native_hook_request(command: str) -> bytes:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": "no-python-pretool",
            "harness": "codex",
            "event_name": "PreToolUse",
            "payload": {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
            },
            "cwd": os.getcwd(),
            "home_dir": str(Path.home()),
            "guard_home": str(Path.home() / ".hol-guard-no-python-proof"),
            "source_ref_external_allowed": False,
            "observe_mode": False,
            "deadline_budget_ms": 2_000,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def raw_harness_request(command: str) -> bytes:
    return json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": os.getcwd(),
        },
        separators=(",", ":"),
    ).encode("utf-8")


def payload(invocation: Invocation, command: str) -> bytes:
    if invocation.payload_kind == "canonical":
        return canonical_request(command)
    if invocation.payload_kind == "native-hook":
        return native_hook_request(command)
    return raw_harness_request(command)


def clean_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "HOME",
            "LANG",
            "LC_ALL",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "USERPROFILE",
            "WINDIR",
        }
        or key.upper().startswith("LC_")
    }


def decode(result: subprocess.CompletedProcess[bytes]) -> dict[str, Any] | None:
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def normalized_decision(value: dict[str, Any]) -> tuple[str, str]:
    action = value.get("minimum_action") or value.get("policy_action")
    decision = value.get("decision") or value.get("permissionDecision")
    specific = value.get("hookSpecificOutput")
    if isinstance(specific, dict):
        decision = decision or specific.get("permissionDecision") or specific.get("decision")
    if value.get("continue") is True and decision is None:
        decision = "allow"
    return str(decision or "").lower(), str(action or "").lower()


def direct_run(runtime: Path, invocation: Invocation, command: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        (str(runtime), *invocation.argv),
        input=payload(invocation, command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=runtime.parent,
        env=clean_environment(),
        check=False,
        timeout=8,
    )


def discover(runtime: Path) -> tuple[Invocation, dict[str, Any]]:
    invocations = (
        Invocation("pre-tool", ("pre-tool", "--stdin"), "canonical"),
        Invocation("pretool", ("pretool", "--stdin"), "canonical"),
        Invocation("native-hook", ("hook", "--stdin"), "native-hook"),
        Invocation(
            "harness-hook",
            ("harness-hook", "--harness", "codex", "--event", "PreToolUse"),
            "raw-harness",
        ),
        Invocation(
            "hook-harness",
            ("hook", "--harness", "codex", "--event", "PreToolUse", "--stdin"),
            "raw-harness",
        ),
    )
    attempts: list[str] = []
    for invocation in invocations:
        result = direct_run(runtime, invocation, "pwd")
        decoded = decode(result)
        if decoded is None:
            attempts.append(
                f"{invocation.name}: returncode={result.returncode} "
                f"stderr={result.stderr.decode(errors='replace')[:300]}"
            )
            continue
        decision, action = normalized_decision(decoded)
        if decision == "allow" or action == "allow":
            return invocation, decoded
        attempts.append(f"{invocation.name}: non-allow payload={decoded}")
    raise RuntimeError("no supported direct-native PreToolUse invocation:\n" + "\n".join(attempts))


def executable_names(trace: str) -> list[str]:
    names: list[str] = []
    for line in trace.splitlines():
        marker = 'execve("'
        start = line.find(marker)
        if start < 0:
            continue
        start += len(marker)
        end = line.find('"', start)
        if end >= 0:
            names.append(Path(line[start:end]).name.lower())
    return names


def traced_run(
    runtime: Path, invocation: Invocation, command: str
) -> tuple[dict[str, Any], list[str]]:
    strace = shutil.which("strace")
    if strace is None:
        result = direct_run(runtime, invocation, command)
        decoded = decode(result)
        if decoded is None:
            raise RuntimeError(
                f"selected native invocation failed: {result.stderr.decode(errors='replace')}"
            )
        return decoded, [runtime.name.lower()]
    with tempfile.TemporaryDirectory(prefix="hol-guard-pretool-no-python-") as temporary:
        trace_path = Path(temporary) / "execve.trace"
        result = subprocess.run(
            (
                strace,
                "-f",
                "-qq",
                "-e",
                "trace=execve",
                "-o",
                str(trace_path),
                str(runtime),
                *invocation.argv,
            ),
            input=payload(invocation, command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=runtime.parent,
            env=clean_environment(),
            check=False,
            timeout=10,
        )
        decoded = decode(result)
        if decoded is None:
            raise RuntimeError(
                f"traced native invocation failed: code={result.returncode} "
                f"stderr={result.stderr.decode(errors='replace')}"
            )
        return decoded, executable_names(
            trace_path.read_text(encoding="utf-8", errors="replace")
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    runtime = args.runtime.expanduser().resolve(strict=True)
    invocation, discovered = discover(runtime)
    safe, safe_execs = traced_run(runtime, invocation, "pwd")
    risky, risky_execs = traced_run(runtime, invocation, "cat ~/.ssh/id_ed25519")
    safe_decision, safe_action = normalized_decision(safe)
    risky_decision, risky_action = normalized_decision(risky)
    all_execs = safe_execs + risky_execs
    python_execs = [
        name
        for name in all_execs
        if name.startswith("python")
        or name in {"hol-guard", "hol-guard.exe", "plugin-scanner"}
    ]
    if python_execs:
        raise SystemExit(f"PreToolUse executed Python or the Python CLI: {python_execs}")
    if safe_decision != "allow" and safe_action != "allow":
        raise SystemExit(f"safe direct-native PreToolUse did not allow: {safe}")
    if risky_decision == "allow" or risky_action == "allow":
        raise SystemExit(f"sensitive direct-native PreToolUse was allowed: {risky}")

    result = {
        "schema": "hol-guard-rust-pretool-no-python-integration.v2",
        "runtime": runtime.name,
        "invocation": invocation.name,
        "argv": list(invocation.argv),
        "discovery": discovered,
        "safe": {"decision": safe_decision, "minimum_action": safe_action},
        "risky": {"decision": risky_decision, "minimum_action": risky_action},
        "executables": sorted(set(all_execs)),
        "python_executables": python_execs,
    }
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
