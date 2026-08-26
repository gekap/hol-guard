#!/usr/bin/env python3
"""Prove supported live PreToolUse paths are direct native and never Python."""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path
from typing import Final

SCHEMA: Final = "hol-guard-rust-pretool-no-python.v2"
EVENT_TOKENS: Final = (
    "PreToolUse",
    "preToolUse",
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeTool",
    "tool_call",
)
NATIVE_TOKENS: Final = (
    "hol-guard-runtime",
    "hol_guard_runtime",
    "native-pretool",
    "native_pretool",
    "pre-tool",
    "pre_tool_use",
)
PYTHON_TOKENS: Final = (
    "python -m",
    "python3 -m",
    "sys.executable",
    "isolated_guard_cli_command",
    "hol-guard hook",
    "guard hook --harness",
    "codex_plugin_scanner.cli",
)


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


def native_bridge_failures(root: Path) -> list[str]:
    failures: list[str] = []
    path = root / "src/codex_plugin_scanner/guard/native_command_model.py"
    if not path.exists():
        return failures
    source = read(path)
    for token in (
        "review_pre_tool_native(",
        "native_pre_tool_native(",
        '"operation": "pre_tool_use"',
        '"operation": "pre-tool-use"',
        "Python remains authoritative",
        "evaluate_command(",
    ):
        if token in source:
            failures.append(f"{path.relative_to(root)} contains live PreToolUse Python residue: {token}")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        failures.append(f"{path.relative_to(root)} does not parse: {exc}")
    else:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if (node.module or "").endswith("command_evaluation") and any(
                alias.name == "evaluate_command" for alias in node.names
            ):
                failures.append(f"{path.relative_to(root)} imports the Python command evaluator")
    return failures


def daemon_failures(root: Path) -> list[str]:
    failures: list[str] = []
    path = root / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    source = read(path)
    for pattern in (
        r'event_name\s*==\s*["\']PreToolUse["\']',
        r'review_pre_tool_native\s*\(',
        r'_harness_json_from_native_pre_tool\s*\(',
        r'_pre_tool_command\s*\(',
    ):
        if re.search(pattern, source):
            failures.append(f"{path.relative_to(root)} retains a Python PreToolUse runtime branch: {pattern}")
    return failures


def cli_failures(root: Path) -> list[str]:
    failures: list[str] = []
    cli = root / "src/codex_plugin_scanner/guard/cli"
    for path in cli.rglob("*.py"):
        source = read(path)
        if "PreToolUse" not in source and "preToolUse" not in source:
            continue
        live_python = re.search(
            r'(?:PreToolUse|preToolUse)[\s\S]{0,1800}'
            r'(?:HookReviewEngine|self\.engine\.review|run_guard_command\(|evaluate_command\()',
            source,
        )
        if live_python:
            failures.append(f"{path.relative_to(root)} retains live Python PreToolUse evaluation")
    return failures


def launcher_evidence(root: Path) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    native_sources: list[str] = []
    roots = (
        root / "src/codex_plugin_scanner/guard/adapters",
        root / "src/codex_plugin_scanner/guard/cli",
    )
    paths = [path for base in roots for path in base.rglob("*.py")]
    for path in paths:
        source = read(path)
        if not any(token in source for token in EVENT_TOKENS):
            continue
        for event in EVENT_TOKENS:
            cursor = 0
            while True:
                index = source.find(event, cursor)
                if index < 0:
                    break
                region = source[max(0, index - 1800) : min(len(source), index + 3600)]
                lowered = region.lower()
                native = any(token.lower() in lowered for token in NATIVE_TOKENS)
                python = [token for token in PYTHON_TOKENS if token.lower() in lowered]
                if native:
                    native_sources.append(path.relative_to(root).as_posix())
                if python and not native:
                    failures.append(
                        f"{path.relative_to(root)} {event} launcher is Python-only: {python}"
                    )
                cursor = index + len(event)
    if not native_sources:
        failures.append("no installed PreToolUse event source is bound to a native launcher")
    return failures, sorted(set(native_sources))


def rust_failures(root: Path) -> list[str]:
    runtime = read(root / "rust/crates/guard-runtime/src/main.rs")
    command = read(root / "rust/crates/guard-command/src/lib.rs")
    combined = runtime + "\n" + command
    failures = [
        f"Rust PreToolUse authority is missing {token}"
        for token in ("PreToolUse", "evaluate_pre_tool", "pre-tool")
        if token not in combined
    ]
    if not re.search(r"pre[-_]tool.*authority|authority.*pre[-_]tool", combined, re.IGNORECASE):
        failures.append("Rust runtime does not advertise PreToolUse authority")
    return failures


def run(root: Path) -> dict[str, object]:
    failures = native_bridge_failures(root)
    failures.extend(daemon_failures(root))
    failures.extend(cli_failures(root))
    launcher_failures, launchers = launcher_evidence(root)
    failures.extend(launcher_failures)
    failures.extend(rust_failures(root))
    result = {
        "schema": SCHEMA,
        "status": "passed" if not failures else "failed",
        "native_launcher_sources": launchers,
        "failures": failures,
    }
    if failures:
        raise RuntimeError(json.dumps(result, indent=2, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    result = run(args.root.resolve())
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
