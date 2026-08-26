#!/usr/bin/env python3
"""Prove that supported PreToolUse never enters the Python runtime.

Installation and repair may be implemented in Python, but the installed live
hook command must launch the bundled native runtime or a verified native proxy.
Python may not parse, classify, transport, evaluate, render, or recover a live
PreToolUse decision.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path
from typing import Final

_NATIVE_LAUNCH_TOKENS: Final = (
    "hol-guard-runtime",
    "hol_guard_runtime",
    "native_pretool",
    "native-pretool",
    "pre-tool --stdin",
    '"pre-tool"',
)
_PYTHON_LAUNCH_TOKENS: Final = (
    "python -m",
    "python3 -m",
    "sys.executable",
    "isolated_guard_cli_command",
    "hol-guard hook",
    "guard hook --harness",
    "codex_plugin_scanner.cli",
)
_EVENT_TOKENS: Final = (
    "PreToolUse",
    "preToolUse",
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeTool",
    "tool_call",
)


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


def python_semantic_gate(root: Path) -> list[str]:
    failures: list[str] = []
    command_bridge = root / "src/codex_plugin_scanner/guard/native_command_model.py"
    if command_bridge.exists():
        source = read(command_bridge)
        forbidden = (
            "evaluate_command(",
            "review_pre_tool_native(",
            "native_pre_tool_native(",
            "PreToolUse authority",
            "pre_tool_use\", \"request",
        )
        for token in forbidden:
            if token in source:
                failures.append(f"{command_bridge}: live PreToolUse Python residue: {token}")
        try:
            tree = ast.parse(source, filename=str(command_bridge))
        except SyntaxError as exc:
            failures.append(f"{command_bridge}: parse failed: {exc}")
        else:
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and (node.module or "").endswith(
                    "command_evaluation"
                ):
                    if any(alias.name == "evaluate_command" for alias in node.names):
                        failures.append(
                            f"{command_bridge}: imports the Python command evaluator"
                        )

    hook_worker = root / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    hook_source = read(hook_worker)
    python_pretool_patterns = (
        r'event_name\s*==\s*["\']PreToolUse["\']',
        r'review_pre_tool_native\s*\(',
        r'_harness_json_from_native_pre_tool\s*\(',
        r'_pre_tool_command\s*\(',
    )
    for pattern in python_pretool_patterns:
        if re.search(pattern, hook_source):
            failures.append(
                f"{hook_worker}: live PreToolUse still traverses Python: {pattern}"
            )

    for path in (root / "src/codex_plugin_scanner/guard").rglob("*.py"):
        source = read(path)
        if path == command_bridge or path == hook_worker:
            continue
        # Runtime evaluation modules may still document PreToolUse contracts,
        # but no live PreToolUse branch may invoke the Python command evaluator.
        if "PreToolUse" in source and "evaluate_command(" in source:
            failures.append(
                f"{path}: PreToolUse source invokes the Python command evaluator"
            )
        if re.search(
            r'(?:PreToolUse|preToolUse)[\s\S]{0,1000}(?:HookReviewEngine|self\.engine\.review|run_guard_command\()',
            source,
        ):
            failures.append(
                f"{path}: PreToolUse can reach a Python semantic evaluator"
            )
    return failures


def installed_launcher_gate(root: Path) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    native_evidence: list[str] = []
    adapters = root / "src/codex_plugin_scanner/guard/adapters"
    candidate_paths = [*adapters.rglob("*.py")]
    candidate_paths.extend(
        path
        for path in (root / "src/codex_plugin_scanner/guard/cli").rglob("*.py")
        if "hook" in path.name or "install" in path.name or "repair" in path.name
    )
    for path in candidate_paths:
        source = read(path)
        if not any(event in source for event in _EVENT_TOKENS):
            continue
        lowered = source.lower()
        native = any(token.lower() in lowered for token in _NATIVE_LAUNCH_TOKENS)
        if native:
            native_evidence.append(path.relative_to(root).as_posix())
        # Examine bounded neighborhoods around event declarations. Installation
        # code elsewhere in the same module may legitimately invoke Python.
        for event in _EVENT_TOKENS:
            start = 0
            while True:
                index = source.find(event, start)
                if index < 0:
                    break
                region = source[max(0, index - 1200) : min(len(source), index + 2400)].lower()
                python_tokens = [
                    token for token in _PYTHON_LAUNCH_TOKENS if token.lower() in region
                ]
                native_region = any(
                    token.lower() in region for token in _NATIVE_LAUNCH_TOKENS
                )
                if python_tokens and not native_region:
                    failures.append(
                        f"{path.relative_to(root)}: {event} launcher neighborhood contains "
                        f"Python-only runtime tokens {python_tokens}"
                    )
                start = index + len(event)
    if not native_evidence:
        failures.append("no adapter or installer contains a native PreToolUse launcher")
    return failures, sorted(set(native_evidence))


def rust_authority_gate(root: Path) -> list[str]:
    failures: list[str] = []
    runtime = read(root / "rust/crates/guard-runtime/src/main.rs")
    command = read(root / "rust/crates/guard-command/src/lib.rs")
    combined = runtime + "\n" + command
    for token in (
        "PreToolUse",
        "evaluate_pre_tool",
        "pre-tool",
        "pre-tool-command-authority",
    ):
        if token not in combined:
            failures.append(f"Rust authority source is missing {token}")
    if "python" in runtime.lower() and "fallback" in runtime.lower():
        failures.append("Rust runtime advertises a Python fallback")
    return failures


def run(root: Path) -> dict[str, object]:
    failures = python_semantic_gate(root)
    launcher_failures, launchers = installed_launcher_gate(root)
    failures.extend(launcher_failures)
    failures.extend(rust_authority_gate(root))
    result = {
        "schema": "hol-guard-rust-pretool-no-python.v1",
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
