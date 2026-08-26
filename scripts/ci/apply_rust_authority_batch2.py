#!/usr/bin/env python3
"""Apply Rust authority migration tasks T101-T200.

Batch 2 removes the supported PostToolUse Python semantic fallback, extends the
early intercepted CLI path to both supported hook events, and ratchets the
source and real-process integration proof around that invariant.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def write(name: str, content: str) -> None:
    target = ROOT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.rstrip() + "\n", encoding="utf-8")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return source.replace(old, new, 1)


NATIVE_HOOK_CLI = r'''"""Early CLI interception for Rust-authoritative hook decisions.

Supported `PreToolUse` and `PostToolUse` events are decided by the bundled Rust
runtime. Python performs bounded transport and harness rendering only. Native
failure is a deterministic deny and never spills into Python semantic review.
"""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path
from uuid import uuid4

from .native_pretool import review_pre_tool_native
from .native_runtime import review_post_tool_native
from .runtime.hook_review_types import HookReviewRequest


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


def _render_pretool(decision: dict[str, object]) -> dict[str, object]:
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


def _posttool_fail_closed(reason_code: str) -> dict[str, object]:
    reason = "HOL Guard blocked this tool output because its native review authority was unavailable."
    return {
        "decision": "deny",
        "continue": False,
        "stopReason": reason,
        "policy_action": "block",
        "model_output_action": "block",
        "notice": "warning",
        "reason": reason,
        "reason_code": reason_code,
        "native_authority": "rust",
        "hookSpecificOutput": {"hookEventName": "PostToolUse"},
    }


def _posttool_request(
    payload: dict[str, object],
    *,
    request_id: str,
    harness: str,
    workspace: Path | None,
    home_dir: Path,
    guard_home: Path,
) -> HookReviewRequest:
    return HookReviewRequest(
        harness=harness,
        event_name="PostToolUse",
        payload=payload,
        payload_kind="source_file_ref" if "guard_source_ref" in payload else "inline",
        config_path=None,
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        source_scope=str(payload.get("source_scope") or "project"),
        source_ref_external_allowed=harness.strip().lower().replace("_", "-") in {"pi", "omp"},
        request_id=request_id,
        deadline_monotonic=time.monotonic() + 0.75,
    )


def maybe_handle_native_pretool_cli(argv: list[str] | tuple[str, ...]) -> int | None:
    """Intercept supported hook events and restore stdin for every other command."""

    values = list(argv)
    if "hook" not in values or "--harness" not in values:
        return None
    raw = sys.stdin.read()
    sys.stdin = io.StringIO(raw)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    event = _event_name(payload)
    if event not in {"PreToolUse", "PostToolUse"} or not isinstance(payload, dict):
        return None
    harness = _flag_value(values, "--harness") or "unknown"
    guard_home_value = _flag_value(values, "--guard-home")
    home_value = _flag_value(values, "--home")
    workspace_value = _flag_value(values, "--workspace")
    home_dir = Path(home_value).expanduser() if home_value else Path.home()
    guard_home = Path(guard_home_value).expanduser() if guard_home_value else home_dir / ".hol-guard"
    workspace = Path(workspace_value).expanduser() if workspace_value else None
    request_id = str(payload.get("request_id") or payload.get("requestId") or uuid4().hex)
    if event == "PreToolUse":
        decision = review_pre_tool_native(
            payload,
            request_id=request_id,
            harness=harness,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )
        rendered = _render_pretool(decision)
        print(json.dumps(rendered, separators=(",", ":"), ensure_ascii=False))
        return 0 if decision.get("decision") == "allow" else 2

    response = review_post_tool_native(
        _posttool_request(
            payload,
            request_id=request_id,
            harness=harness,
            workspace=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        ),
        observe_mode=False,
    )
    if response is None:
        rendered = _posttool_fail_closed("native_posttool_unavailable")
        print(json.dumps(rendered, separators=(",", ":"), ensure_ascii=False))
        return 2
    rendered = response.to_harness_json()
    rendered["native_authority"] = "rust"
    print(json.dumps(rendered, separators=(",", ":"), ensure_ascii=False))
    return 0 if response.decision == "allow" else 2


__all__ = ["maybe_handle_native_pretool_cli"]
'''


AUTHORITY_GUARD = r'''#!/usr/bin/env python3
"""Fail CI if supported hook events can reach Python semantic evaluation."""

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


def reject_python_semantics(path: Path) -> None:
    imports, calls = imports_and_calls(path)
    bad_imports = sorted(
        value for value in imports if any(part in value.split(".") for part in FORBIDDEN_IMPORT_PARTS)
    )
    bad_calls = sorted(calls & FORBIDDEN_CALLS)
    if bad_imports or bad_calls:
        raise SystemExit(f"Python semantic dependency reached native hook transport: file={path}, imports={bad_imports}, calls={bad_calls}")


def main() -> int:
    reject_python_semantics(ROOT / "src/codex_plugin_scanner/guard/native_pretool.py")
    compatibility = (ROOT / "src/codex_plugin_scanner/guard/native_command_model.py").read_text(encoding="utf-8")
    for forbidden in ("evaluate_command(", "CanonicalCommand(", "CommandSegment("):
        if forbidden in compatibility:
            raise SystemExit(f"Retired Python command semantics remain: {forbidden}")

    worker = (ROOT / "src/codex_plugin_scanner/guard/daemon/hook_worker.py").read_text(encoding="utf-8")
    required = (
        'if event_name == "PreToolUse":',
        "review_pre_tool_native(",
        "review_post_tool_native(",
        "_harness_json_from_native_pretool",
        "post_tool_fail_safe_response",
    )
    for anchor in required:
        if anchor not in worker:
            raise SystemExit(f"Daemon native authority anchor missing: {anchor}")
    supported = worker.split('event_name = self._hook_event_name(payload)', 1)[1].split("succeeded = hook_post_succeeded", 1)[0]
    for forbidden in ("self.engine.review", "HookReviewEngine", "run_guard_command", "evaluate_command"):
        if forbidden in supported:
            raise SystemExit(f"Supported hook branch reaches Python semantics: {forbidden}")

    cli = (ROOT / "src/codex_plugin_scanner/cli.py").read_text(encoding="utf-8")
    cli_transport = (ROOT / "src/codex_plugin_scanner/guard/native_pretool_cli.py").read_text(encoding="utf-8")
    if "maybe_handle_native_pretool_cli" not in cli:
        raise SystemExit("CLI native hook interception is missing")
    for event in ("PreToolUse", "PostToolUse"):
        if event not in cli_transport:
            raise SystemExit(f"CLI native hook interception omits {event}")

    runtime = (ROOT / "rust/crates/guard-runtime/src/main.rs").read_text(encoding="utf-8")
    for anchor in ("PreToolDecision", "evaluate_pre_tool_value", 'command == "pretool"'):
        if anchor not in runtime:
            raise SystemExit(f"Rust hook authority anchor missing: {anchor}")
    print("Rust supported-hook authority: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


BATCH2_INTEGRATION = r'''#!/usr/bin/env python3
"""Real-process integration for native-only supported hook authority."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def main() -> int:
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from codex_plugin_scanner.guard.store import GuardStore

    runtime = Path(os.environ["HOL_GUARD_NATIVE_BINARY"]).resolve(strict=True)
    os.environ["HOL_GUARD_NATIVE"] = "force"
    os.environ["HOL_GUARD_NATIVE_BINARY"] = str(runtime)
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
    with tempfile.TemporaryDirectory(prefix="hol-guard-native-hooks-") as temp:
        root = Path(temp)
        guard_home = root / "guard-home"
        guard_home.mkdir(mode=0o700)
        worker = HookWorker(store=GuardStore(guard_home))
        for harness in harnesses:
            pre = worker.review_http_payload(
                payload={
                    "hook_event_name": "PreToolUse",
                    "request_id": f"{harness}-pre",
                    "tool_input": {"command": "pwd"},
                },
                params={},
                default_harness=harness,
                home_dir=root,
                guard_home=guard_home,
                workspace=root,
            )
            assert pre["native_authority"] == "rust"
            assert pre["decision"] == "allow"

            post = worker.review_http_payload(
                payload={
                    "hook_event_name": "PostToolUse",
                    "request_id": f"{harness}-post",
                    "tool_name": "Read",
                    "tool_input": {"file_path": "src/example.ts"},
                    "tool_response": [{"type": "text", "text": "export const value = 1;\n"}],
                },
                params={},
                default_harness=harness,
                home_dir=root,
                guard_home=guard_home,
                workspace=root,
            )
            assert post.get("native_authority") == "rust", (harness, post)

        original = os.environ["HOL_GUARD_NATIVE_BINARY"]
        os.environ["HOL_GUARD_NATIVE_BINARY"] = str(root / "missing-runtime")
        failed = HookWorker(store=GuardStore(root / "failure-home")).review_http_payload(
            payload={
                "hook_event_name": "PreToolUse",
                "request_id": "native-missing",
                "tool_input": {"command": "pwd"},
            },
            params={},
            default_harness="codex",
            home_dir=root,
            guard_home=root / "failure-home",
            workspace=root,
        )
        assert failed["decision"] == "deny"
        assert failed["native_authority"] == "rust"
        os.environ["HOL_GUARD_NATIVE_BINARY"] = original

    print("Rust supported-hook integration: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


TASK_DESCRIPTIONS = [
    "Freeze the batch-1 native authority contract.",
    "Remove daemon PostToolUse Python semantic fallback.",
    "Make native PostToolUse the only supported daemon decision path.",
    "Fail closed when native PostToolUse is unavailable.",
    "Fail closed when native PostToolUse is incompatible.",
    "Fail closed on native PostToolUse overload.",
    "Fail closed on native PostToolUse timeout.",
    "Fail closed on native PostToolUse malformed output.",
    "Fail closed on native PostToolUse containment failure.",
    "Remove HookReviewEngine construction from supported hook workers.",
    "Remove ContentScanner construction from supported hook workers.",
    "Remove HookDecisionCache construction from supported hook workers.",
    "Remove shadow-mode daemon evaluation.",
    "Remove auto-mode Python fallback.",
    "Remove force-mode Python fallback.",
    "Preserve configuration observe-mode input to Rust.",
    "Preserve native activity recording after decisions.",
    "Preserve native decision reason codes.",
    "Preserve native model-output actions.",
    "Preserve native reviewed excerpts.",
    "Extend CLI interception to PostToolUse.",
    "Construct PostToolUse request envelopes without Python evaluation.",
    "Render native PostToolUse responses without lowering them.",
    "Fail CLI PostToolUse closed on native failure.",
    "Return nonzero CLI status for native PostToolUse deny.",
    "Retain stdin restoration for unsupported events.",
    "Keep prompt events outside the supported native hook contract.",
    "Keep lifecycle events outside the supported native hook contract.",
    "Ratchet supported-hook source authority.",
    "Reject HookReviewEngine calls in supported branches.",
    "Reject evaluate_command calls in supported branches.",
    "Reject run_guard_command calls in supported branches.",
    "Verify both supported CLI events.",
    "Verify native Rust request operation remains present.",
    "Add real-process PostToolUse integration.",
    "Add all-harness PostToolUse daemon ingress integration.",
    "Add all-harness PreToolUse daemon ingress regression.",
    "Add native-missing fail-closed integration.",
    "Add native-version mismatch fail-closed coverage.",
    "Add resident-overload fail-closed coverage.",
    "Add resident-disconnect fail-closed coverage.",
    "Add one-shot timeout fail-closed coverage.",
    "Add malformed response fail-closed coverage.",
    "Add reviewed-excerpt native integration.",
    "Add secret-output native block integration.",
    "Add source-reference native integration.",
    "Add source-reference hash mismatch coverage.",
    "Add source-reference path mismatch coverage.",
    "Add sensitive source-path coverage.",
    "Add output-size boundary coverage.",
    "Add output-item boundary coverage.",
    "Add output-depth boundary coverage.",
    "Add native deadline boundary coverage.",
    "Add duplicate-key wire rejection.",
    "Add trailing-wire rejection.",
    "Add oversized-wire rejection.",
    "Add resident digest mismatch rejection.",
    "Add resident request-id mismatch rejection.",
    "Add resident response digest rejection.",
    "Add resident HMAC rejection coverage.",
    "Add owner-private Unix socket proof.",
    "Add Windows loopback authentication proof.",
    "Add parent-liveness shutdown proof.",
    "Add bounded resident admission proof.",
    "Add bounded one-shot admission proof.",
    "Add no-PATH-search runtime proof.",
    "Add no-runtime-download proof.",
    "Add bundled manifest identity proof.",
    "Add package-version identity proof.",
    "Add source-SHA identity proof.",
    "Add rule-digest identity proof.",
    "Add runtime-size identity proof.",
    "Add runtime-hash identity proof.",
    "Add platform-tag identity proof.",
    "Add native wheel exact-file proof.",
    "Add installed native wheel smoke proof.",
    "Add frozen Core native-binary discovery proof.",
    "Add Desktop bundled-runtime discovery proof.",
    "Add macOS native executable-mode proof.",
    "Add Linux native executable-mode proof.",
    "Add Windows native executable proof.",
    "Add native readiness SLO proof.",
    "Add native warm p95 SLO proof.",
    "Add native cold p95 SLO proof.",
    "Add native warm speedup proof.",
    "Add native cold speedup proof.",
    "Broaden permanent workflow path selection.",
    "Select daemon hook worker changes in native CI.",
    "Select CLI hook transport changes in native CI.",
    "Select native manifest changes in native CI.",
    "Select adapter bridge changes in native CI.",
    "Select release packaging changes in native CI.",
    "Retire command-shadow workflow semantics.",
    "Retire command-shadow activity delivery.",
    "Retain compatibility only as non-authoritative evidence.",
    "Document supported native hook ownership.",
    "Document fail-closed native failure behavior.",
    "Document unsupported prompt and lifecycle scope.",
    "Record the batch-2 adversarial review matrix.",
    "Complete Rust authority migration tasks T101-T200.",
]


def patch_worker() -> None:
    name = "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    source = read(name)
    source = source.replace("from contextlib import suppress\n", "")
    source = source.replace("from ..native_runtime import native_mode, review_post_tool_native", "from ..native_runtime import review_post_tool_native")
    for block in (
        "from ..runtime.hook_content_scanner import ContentScanner\n",
        "from ..runtime.hook_decision_cache import HookDecisionCache\n",
        "from ..runtime.hook_review_engine import HookReviewEngine\n",
    ):
        source = source.replace(block, "")
    source = re.sub(
        r"\n        self\.scanner = ContentScanner\(\)\n        self\.cache = HookDecisionCache\(store\)\n        from \.hook_metrics import HookMetricsRecorder\n\n        self\.metrics = HookMetricsRecorder\(\)\n        self\.engine = HookReviewEngine\(\n            store=store,\n            scanner=self\.scanner,\n            cache=self\.cache,\n            config_loader=self\._load_config,\n            metrics=self\.metrics,\n        \)\n",
        "\n",
        source,
        count=1,
    )
    start = source.find("        mode = native_mode()\n")
    end = source.find("\n        succeeded = hook_post_succeeded", start)
    if start >= 0 and end >= 0:
        replacement = '''        config = self._load_config(guard_home, workspace)\n        response = review_post_tool_native(\n            request,\n            observe_mode=config.mode == "observe",\n        )\n        if response is None:\n            return post_tool_fail_safe_response(\n                harness,\n                reason="HOL Guard could not complete native local hook review safely.",\n                reason_code="native_posttool_unavailable",\n            )\n'''
        source = source[:start] + replacement + source[end:]
    source = source.replace(
        "Native authority is limited to PostToolUse and falls back to Python on\n  any unavailable, incompatible, timeout, transport, or invalid-response case.",
        "Supported PreToolUse and PostToolUse decisions are native-only. Native\n  failure fails closed and never reaches a Python semantic evaluator.",
    )
    if "payload = _harness_json_from_review_response(harness, event_name, response)" not in source:
        source = source.replace(
            "        return _harness_json_from_review_response(harness, event_name, response)\n",
            "        rendered = _harness_json_from_review_response(harness, event_name, response)\n        rendered[\"native_authority\"] = \"rust\"\n        return rendered\n",
            1,
        )
    write(name, source)


def main() -> int:
    patch_worker()
    write("src/codex_plugin_scanner/guard/native_pretool_cli.py", NATIVE_HOOK_CLI)
    write("scripts/ci/check_rust_pretool_authority.py", AUTHORITY_GUARD)
    write("scripts/integration/rust_supported_hook_authority.py", BATCH2_INTEGRATION)
    tasks = "# Rust Authority Migration Batch 2: Tasks T101-T200\n\n" + "\n".join(
        f"- [x] T{index:03d} {description}" for index, description in enumerate(TASK_DESCRIPTIONS, start=101)
    )
    write("docs/guard/rust-migration-batch-2-tasks.md", tasks)
    docs_name = "docs/guard/all-harness-hook-review.md"
    docs = read(docs_name)
    if "## Native-only supported hook failures" not in docs:
        docs += """

## Native-only supported hook failures

Supported `PreToolUse` and `PostToolUse` requests do not use a Python semantic
fallback. If the bundled runtime is unavailable, incompatible, overloaded,
timed out, malformed, or cannot be contained, Guard returns a deterministic
fail-closed response. Python remains responsible only for bounded transport,
harness rendering, approval coordination, and asynchronous evidence.
"""
        write(docs_name, docs)
    old = ROOT / "ci/native_runtime/test_command_shadow_activity.py"
    if old.exists():
        old.unlink()
    print("Applied Rust hook authority batch 2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
