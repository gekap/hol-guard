#!/usr/bin/env python3
"""Apply batch-1 ingress, compatibility, and documentation follow-ups."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def path(name: str) -> Path:
    return ROOT / name


def main() -> int:
    runtime = path("rust/crates/guard-runtime/src/main.rs")
    source = runtime.read_text(encoding="utf-8")
    authority = '        "pre-tool-authority-v1".into(),\n        "resident-pre-tool-authority-v1".into(),'
    compatibility = authority + '\n        "pre-tool-command-model-shadow-v1".into(),\n        "resident-command-model-shadow-v1".into(),'
    if authority in source and "pre-tool-command-model-shadow-v1" not in source:
        source = source.replace(authority, compatibility, 1)
        runtime.write_text(source, encoding="utf-8")

    integration = path("scripts/integration/rust_pretool_authority.py")
    script = integration.read_text(encoding="utf-8")
    if "def exercise_daemon_ingress" not in script:
        insertion = r'''

def exercise_daemon_ingress(runtime: Path) -> None:
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from codex_plugin_scanner.guard.store import GuardStore

    harnesses = (
        "codex",
        "claude-code",
        "copilot",
        "cursor",
        "cline",
        "gemini",
        "hermes",
        "openclaw",
        "opencode",
        "kimi",
        "grok",
        "pi",
        "omp",
        "zcode",
    )
    with tempfile.TemporaryDirectory(prefix="hol-guard-rust-ingress-") as temp:
        root = Path(temp)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        os.environ["HOL_GUARD_NATIVE"] = "force"
        os.environ["HOL_GUARD_NATIVE_BINARY"] = str(runtime)
        worker = HookWorker(store=GuardStore(guard_home))
        for harness in harnesses:
            allowed = worker.review_http_payload(
                payload={
                    "hook_event_name": "PreToolUse",
                    "request_id": f"{harness}-allow",
                    "tool_input": {"command": "pwd"},
                },
                params={},
                default_harness=harness,
                home_dir=root,
                guard_home=guard_home,
                workspace=root,
            )
            assert allowed["native_authority"] == "rust", harness
            assert allowed["decision"] == "allow", harness
            blocked = worker.review_http_payload(
                payload={
                    "hook_event_name": "PreToolUse",
                    "request_id": f"{harness}-block",
                    "tool_input": {"command": "rm -rf /"},
                },
                params={},
                default_harness=harness,
                home_dir=root,
                guard_home=guard_home,
                workspace=root,
            )
            assert blocked["native_authority"] == "rust", harness
            assert blocked["decision"] == "deny", harness
'''
        script = script.replace("\ndef main() -> int:\n", insertion + "\n\ndef main() -> int:\n", 1)
        script = script.replace(
            "    runtime = Path(os.environ[\"HOL_GUARD_NATIVE_BINARY\"]).resolve(strict=True)\n",
            "    runtime = Path(os.environ[\"HOL_GUARD_NATIVE_BINARY\"]).resolve(strict=True)\n    exercise_daemon_ingress(runtime)\n",
            1,
        )
        integration.write_text(script, encoding="utf-8")

    docs = path("docs/guard/all-harness-hook-review.md")
    text = docs.read_text(encoding="utf-8")
    marker = "## Rust-authoritative PreToolUse\n"
    if marker not in text:
        text += """

## Rust-authoritative PreToolUse

On release/3.0, supported `PreToolUse` command decisions are final decisions
from the bundled, version-matched Rust runtime. Python transports the request,
validates the exact response binding, renders the harness response, and may
coordinate an approval, but it does not parse or classify the command and does
not apply a semantic fallback. Native unavailability, overload, timeout,
malformed output, or containment failure fails closed.

`PostToolUse` output review remains a separate native hook operation. Prompt
and lifecycle observation surfaces are not part of the PreToolUse command
authority contract.
"""
        docs.write_text(text, encoding="utf-8")

    print("Applied batch-1 ingress follow-up")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
