#!/usr/bin/env python3
"""Prove supported PreToolUse authority is Rust with no production Python fallback."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Final

SCHEMA: Final = "hol-guard-rust-pretool-no-python.v3"


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


def required_tokens(path: Path, tokens: tuple[str, ...]) -> list[str]:
    source = read(path)
    return [f"{path.as_posix()} missing {token}" for token in tokens if token not in source]


def run(root: Path) -> dict[str, object]:
    failures: list[str] = []
    failures.extend(
        required_tokens(
            root / "rust/crates/guard-command/src/pretool.rs",
            ("pub fn evaluate_pre_tool", "PreToolDecisionV1", "~/.npmrc"),
        )
    )
    failures.extend(
        required_tokens(
            root / "rust/crates/guard-runtime/src/main.rs",
            (
                "pre-tool-command-authority-v1",
                'command == "pre-tool"',
                '"hook-edge-v2"',
                "HookEdge(Value)",
            ),
        )
    )
    failures.extend(
        required_tokens(
            root / "rust/crates/guard-runtime/src/oneshot.rs",
            (
                "fn evaluate_pre_tool_bytes",
                "pre_tool_response",
                "evaluate_pre_tool_request",
                "evaluate_hook_edge_value",
                "extract_pre_tool_command",
                "native_pre_tool_unsupported_review",
            ),
        )
    )

    hook_worker = root / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    hook_source = read(hook_worker)
    for required in ("review_hook_edge_native", "native_hook_edge_unavailable"):
        if required not in hook_source:
            failures.append(f"{hook_worker.as_posix()} missing {required}")
    for forbidden in (
        "from ..native_pretool import review_pre_tool_native",
        "HookReviewEngine",
        "ContentScanner",
        "HookDecisionCache",
        "_pre_tool_command(",
    ):
        if forbidden in hook_source:
            failures.append(f"production hook worker retains Python PreTool semantics: {forbidden}")

    edge = root / "src/codex_plugin_scanner/guard/native_hook_edge.py"
    edge_source = read(edge)
    for required in ('"operation": "hook_edge"', '"hook-edge", "--stdin"', "review_hook_edge_native"):
        if required not in edge_source:
            failures.append(f"{edge.as_posix()} missing {required}")
    for forbidden in ("evaluate_command(", "HookReviewEngine", "review_pre_tool_native("):
        if forbidden in edge_source:
            failures.append(f"native hook edge bridge invokes Python PreTool semantics: {forbidden}")

    cli = root / "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py"
    cli_source = read(cli)
    for forbidden in ("native_mode", "_try_source_ref_fast_path", "HookWorkerUnsupported"):
        if forbidden in cli_source:
            failures.append(f"production CLI can escape Rust authority: {forbidden}")

    result = {
        "schema": SCHEMA,
        "status": "passed" if not failures else "failed",
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
