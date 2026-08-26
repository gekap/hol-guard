#!/usr/bin/env python3
"""Exercise the compiled PreToolUse authority and reject Python process execution."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def request(command: str) -> bytes:
    return json.dumps(
        {
            "command": command,
            "dialect": "posix",
            "transport": "shell_string",
            "extraction_provenance": "guard-shell",
        },
        separators=(",", ":"),
    ).encode("utf-8")


def decode(result: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    if result.returncode != 0:
        raise RuntimeError(
            f"native PreToolUse failed: code={result.returncode} stderr={result.stderr.decode(errors='replace')}"
        )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("native PreToolUse response is not an object")
    return value


def executable_names(trace: str) -> list[str]:
    names: list[str] = []
    for line in trace.splitlines():
        marker = 'execve("'
        start = line.find(marker)
        if start < 0:
            continue
        start += len(marker)
        end = line.find('"', start)
        if end < 0:
            continue
        names.append(Path(line[start:end]).name.lower())
    return names


def run_direct(runtime: Path, command: str) -> tuple[dict[str, Any], list[str]]:
    clean_env = {
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
    strace = shutil.which("strace")
    if strace is None:
        result = subprocess.run(
            (str(runtime), "pre-tool", "--stdin"),
            input=request(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=runtime.parent,
            env=clean_env,
            check=False,
            timeout=5,
        )
        return decode(result), [runtime.name.lower()]
    with tempfile.TemporaryDirectory(prefix="hol-guard-pretool-trace-") as temporary:
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
                "pre-tool",
                "--stdin",
            ),
            input=request(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=runtime.parent,
            env=clean_env,
            check=False,
            timeout=8,
        )
        names = executable_names(trace_path.read_text(encoding="utf-8", errors="replace"))
        return decode(result), names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    runtime = args.runtime.expanduser().resolve(strict=True)

    safe, safe_execs = run_direct(runtime, "git status --short")
    risky, risky_execs = run_direct(runtime, "cat ~/.ssh/id_ed25519")
    all_execs = safe_execs + risky_execs
    python_execs = [
        name
        for name in all_execs
        if name.startswith("python")
        or name in {"hol-guard", "hol-guard.exe", "plugin-scanner"}
    ]
    if python_execs:
        raise SystemExit(f"PreToolUse executed Python or the Python CLI: {python_execs}")
    if safe.get("decision") != "allow" or safe.get("minimum_action") != "allow":
        raise SystemExit(f"bounded safe command was not natively allowed: {safe}")
    if risky.get("decision") == "allow" or risky.get("minimum_action") == "allow":
        raise SystemExit(f"sensitive command was natively allowed: {risky}")

    result = {
        "schema": "hol-guard-rust-pretool-no-python-integration.v1",
        "runtime": runtime.name,
        "safe": {
            "decision": safe.get("decision"),
            "minimum_action": safe.get("minimum_action"),
            "reason_code": safe.get("reason_code"),
        },
        "risky": {
            "decision": risky.get("decision"),
            "minimum_action": risky.get("minimum_action"),
            "reason_code": risky.get("reason_code"),
        },
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
