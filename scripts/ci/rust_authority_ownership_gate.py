#!/usr/bin/env python3
"""Enforce HOL Guard's permanent Rust hook/data-plane ownership boundary."""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path
from typing import Final

SCHEMA: Final = "hol-guard-rust-authority-ownership.v1"
MANIFEST = Path("ci/rust-authority-ownership.v1.json")

TEMPORARY_PATHS: Final = (
    Path(".github/workflows/rust-local-toolchain-export.yml"),
    Path(".github/workflows/rust-pretool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-pretool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-authority-batch1-finalize.yml"),
    Path(".github/workflows/rust-authority-batch1-merge-gate.yml"),
    Path(".github/workflows/rust-posttool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-posttool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-posttool-authority-lint-fix.yml"),
    Path(".github/workflows/rust-authority-batch2-merge-gate.yml"),
    Path(".github/workflows/rust-authority-batch2-retry-merge-v2.yml"),
    Path(".github/workflows/rust-authority-batch2-converge-v3.yml"),
    Path(".github/workflows/rust-authority-batch2-converge-v4.yml"),
    Path(".github/workflows/rust-authority-final-orchestrator.yml"),
    Path(".github/workflows/rust-authority-final-lint-fix.yml"),
    Path(".github/workflows/rust-authority-final-merge-gate.yml"),
    Path(".github/workflows/rust-authority-final-retry-merge-v2.yml"),
    Path(".github/workflows/rust-authority-batch3-converge-v3.yml"),
    Path("scripts/ci/bootstrap_rust_pretool_authority.sh"),
    Path("scripts/ci/bootstrap_rust_posttool_authority.sh"),
    Path("scripts/ci/fallback_rust_posttool_authority.py"),
    Path("scripts/ci/converge_rust_posttool_authority_v2.py"),
    Path("scripts/ci/harden_rust_policy_snapshot_v3.py"),
    Path("scripts/ci/select_rust_posttool_authority_candidate_v2.sh"),
    Path("scripts/ci/rust_authority_ownership_gate_v2.py"),
    Path("scripts/ci/rust_authority_ownership_gate_v3.py"),
    Path("scripts/ci/finalize_rust_authority_migration.py"),
    Path("scripts/ci/finalize_rust_authority_migration_v2.py"),
    Path("docs/guard/.batch1-merge-probe"),
    Path("docs/guard/rust-authority-batch-2-bootstrap.md"),
    Path("rust/AUTHORITY_BATCH_1"),
    Path("rust/AUTHORITY_BATCH_1_FINAL"),
    Path("rust/AUTHORITY_BATCH_2"),
    Path("rust/AUTHORITY_BATCH_2_FINAL"),
    Path("rust/AUTHORITY_FINAL"),
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"required authority source is missing: {path}") from exc


def _manifest() -> dict[str, object]:
    value = json.loads(_read(MANIFEST))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise RuntimeError("Rust authority ownership manifest has an invalid schema")
    surfaces = value.get("surfaces")
    if not isinstance(surfaces, dict):
        raise RuntimeError("Rust authority ownership manifest has no surfaces")
    for key in ("pre_tool_use", "post_tool_use"):
        surface = surfaces.get(key)
        if not isinstance(surface, dict):
            raise RuntimeError(f"Rust authority surface is missing: {key}")
        if surface.get("semantic_authority") != "rust" or surface.get("python_semantic_fallback") is not False:
            raise RuntimeError(f"Rust authority surface is not exclusive: {key}")
        if surface.get("native_failure") != "fail_closed":
            raise RuntimeError(f"Rust authority surface is not fail closed: {key}")

    hook_edge = surfaces.get("hook_edge")
    if not isinstance(hook_edge, dict) or hook_edge.get("event_and_action_extraction") != "rust":
        raise RuntimeError("raw hook event/action extraction is not Rust-owned")
    if hook_edge.get("python_semantic_envelope_parsing") is not False:
        raise RuntimeError("Python semantic envelope parsing is still permitted")

    client = surfaces.get("resident_client")
    if not isinstance(client, dict):
        raise RuntimeError("resident client ownership surface is missing")
    for field in ("authentication", "framing", "request_response_digest_validation", "socket_io"):
        if client.get(field) != "rust":
            raise RuntimeError(f"resident client {field} is not Rust-owned")

    io_surface = surfaces.get("decision_critical_io")
    if not isinstance(io_surface, dict) or any(item != "rust" for item in io_surface.values()):
        raise RuntimeError("decision-critical PostToolUse I/O is not exclusively Rust-owned")

    default_contract = value.get("default_runtime_contract")
    if not isinstance(default_contract, dict):
        raise RuntimeError("no-environment production runtime contract is missing")
    if default_contract.get("native_mode_without_environment") != "auto":
        raise RuntimeError("unset native mode is not auto")
    if default_contract.get("hook_fast_path_without_environment") is not True:
        raise RuntimeError("unset hook fast path is not enabled")
    if default_contract.get("path_runtime_search") is not False:
        raise RuntimeError("production runtime contract still permits PATH search")
    if default_contract.get("decision_time_runtime_download") is not False:
        raise RuntimeError("production runtime contract still permits decision-time runtime download")
    return value


def _function_source(path: Path, function_name: str) -> str:
    source = _read(path)
    tree = ast.parse(source, filename=str(path))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
            segment = ast.get_source_segment(source, node)
            if segment is None:
                raise RuntimeError(f"could not inspect function {function_name} in {path}")
            return segment
    raise RuntimeError(f"required function is missing: {path}:{function_name}")


def _hook_worker_gate() -> None:
    path = Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py")
    source = _read(path)
    required = (
        "review_hook_edge_native",
        "native_hook_edge_unavailable",
        "_harness_json_from_native_edge",
    )
    missing = [token for token in required if token not in source]
    if missing:
        raise RuntimeError(f"daemon hook worker is not bound to native hook edge: {missing}")
    forbidden = (
        "HookReviewEngine",
        "ContentScanner",
        "HookDecisionCache",
        "review_pre_tool_native",
        "review_post_tool_native",
        "self.engine.review(",
        "_parse_source_ref(",
        "_parse_output_summary(",
        "_pre_tool_command(",
    )
    present = [token for token in forbidden if token in source]
    if present:
        raise RuntimeError(f"daemon hook worker retains Python semantic/data-plane implementation: {present}")
    review = _function_source(path, "review_http_payload")
    if "HookWorkerUnsupported" in review:
        raise RuntimeError("production daemon hook review can escape native authority")


def _rust_hook_edge_gate() -> None:
    runtime = _read(Path("rust/crates/guard-runtime/src/main.rs"))
    oneshot = _read(Path("rust/crates/guard-runtime/src/oneshot.rs"))
    core = _read(Path("rust/crates/guard-hook-core/src/lib.rs"))
    for required in ('"hook-edge-v2"', "HookEdge(Value)", 'command == "hook-edge"'):
        if required not in runtime:
            raise RuntimeError(f"Rust hook edge runtime contract is missing: {required}")
    for required in (
        "evaluate_hook_edge_value",
        "hook_event_name",
        "extract_pre_tool_command",
        "native_pre_tool_unsupported_review",
        "review_post_tool",
    ):
        if required not in oneshot:
            raise RuntimeError(f"Rust hook edge implementation is missing: {required}")
    for required in ("read_bounded", "scan_text", "extract_payload_output", "review_post_tool"):
        if required not in core:
            raise RuntimeError(f"Rust PostToolUse decision-critical I/O is missing: {required}")


def _resident_client_gate() -> None:
    runtime = _read(Path("rust/crates/guard-runtime/src/main.rs"))
    client = _read(Path("rust/crates/guard-runtime/src/resident_client.rs"))
    for required in (
        '"resident-client-v1"',
        'command == "resident-client"',
        "resident_client::request_unix",
        "resident_client::request_loopback",
    ):
        if required not in runtime:
            raise RuntimeError(f"Rust resident-client runtime contract is missing: {required}")
    for required in (
        "authenticate(",
        "hmac_sha256",
        "REQUEST_MAGIC",
        "RESPONSE_MAGIC",
        "Sha256::digest(payload)",
        "response_id_mismatch",
        "response_digest_mismatch",
    ):
        if required not in client:
            raise RuntimeError(f"Rust resident-client transport is missing: {required}")

    bridge = Path("src/codex_plugin_scanner/guard/native_runtime_resident.py")
    source = _read(bridge)
    class_start = source.find("class _ResidentService:")
    send_start = source.find("    def _send(", class_start)
    send_end = source.find("\n    def _ensure_started(", send_start)
    if send_start < 0 or send_end <= send_start:
        raise RuntimeError("Python resident lifecycle has no bounded _send bridge")
    send = source[send_start:send_end]
    for required in ("resident-client", "run_isolated_hook_process"):
        if required not in send:
            raise RuntimeError(f"Python resident lifecycle does not delegate {required} to Rust")
    for forbidden in (
        "_send_authenticated_unix_request",
        "_send_authenticated_loopback_request",
        "_authenticate_client(",
        "socket.create_connection",
    ):
        if forbidden in send:
            raise RuntimeError(f"production resident client I/O still executes in Python: {forbidden}")


def _cli_gate() -> None:
    hook = _read(Path("src/codex_plugin_scanner/guard/cli/commands_hook.py"))
    if "try_native_or_source_ref_hook" not in hook:
        raise RuntimeError("CLI hook path does not consult native authority")
    path = Path("src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py")
    source = _read(path)
    for forbidden in (
        "_try_source_ref_fast_path",
        "native_mode",
        "HookWorkerUnsupported",
        "HookReviewEngine",
        "evaluate_command(",
    ):
        if forbidden in source:
            raise RuntimeError(f"CLI hook path retains Python semantic fallback: {forbidden}")
    route = _function_source(path, "try_native_or_source_ref_hook")
    if "try_native_hook_authority" not in route or '_emit("hook"' not in route:
        raise RuntimeError("CLI hook route does not terminate at native authority")


def _default_mode_gate() -> None:
    native = _read(Path("src/codex_plugin_scanner/guard/native_runtime.py"))
    config = _read(Path("src/codex_plugin_scanner/guard/config.py"))
    if '_DEFAULT_NATIVE_MODE: NativeMode = "auto"' not in native:
        raise RuntimeError("bundled native authority is not the no-env default")
    if 'os.environ.get(HOOK_FAST_PATH_ENV, "1") == "1"' not in config:
        raise RuntimeError("resident hook path is not enabled when its environment variable is absent")
    candidates_start = native.find("def _runtime_candidates()")
    candidates_end = native.find("\ndef _validate_binary", candidates_start)
    candidates = native[candidates_start:candidates_end]
    if "shutil.which" in candidates or "PATH" in candidates:
        raise RuntimeError("automatic native runtime selection searches PATH")


def _policy_and_identity_gate() -> None:
    cargo = _read(Path("rust/crates/guard-runtime/Cargo.toml"))
    runtime = _read(Path("rust/crates/guard-runtime/src/main.rs"))
    native = _read(Path("src/codex_plugin_scanner/guard/native_runtime.py"))
    release = _read(Path("scripts/verify_native_runtime_release.py"))
    if "guard-policy-snapshot" not in cargo:
        raise RuntimeError("hol-guard-runtime does not link guard-policy-snapshot")
    if "policy_snapshot" not in runtime and "validate_request_policy_snapshot" not in _read(
        Path("rust/crates/guard-runtime/src/oneshot.rs")
    ):
        raise RuntimeError("hol-guard-runtime does not consume policy snapshots")
    for required in (
        "native_manifest_runtime_mismatch",
        "native_manifest_version_mismatch",
        "native_manifest_rule_mismatch",
        "runtime_sha256",
    ):
        if required not in native and required not in release:
            raise RuntimeError(f"bundled runtime identity guard is missing: {required}")


def _workflow_gate() -> None:
    source = _read(Path(".github/workflows/rust-authority-ownership.yml"))
    required_paths = (
        '"rust/**"',
        '"src/codex_plugin_scanner/guard/**"',
        '"ci/native_runtime/**"',
        '"scripts/**"',
        '".github/workflows/**"',
    )
    missing = [value for value in required_paths if value not in source]
    if missing:
        raise RuntimeError(f"authority workflow path coverage is incomplete: {missing}")
    required_commands = (
        "rust_pretool_authority_integration.py",
        "rust_posttool_failclosed_integration.py",
        "test_guard_native_runtime_differential.py",
        "test_guard_native_runtime_mutation_differential.py",
        "bench_guard_native_release_gate.py",
        "test_native_hol_guard_wheel.py",
    )
    missing_commands = [value for value in required_commands if value not in source]
    if missing_commands:
        raise RuntimeError(f"authority workflow integration coverage is incomplete: {missing_commands}")


def _docs_gate() -> None:
    architecture = _read(Path("docs/guard/all-harness-hook-review.md"))
    support = _read(Path("docs/guard/harness-support.md"))
    forbidden = (
        "causing the server to fall through to the legacy CLI path",
        "Python remains authoritative",
    )
    for value in forbidden:
        if value in architecture or value in support:
            raise RuntimeError(f"legacy Python authority documentation remains: {value}")
    if "Rust Authority Boundary" not in architecture or "Rust Authority Boundary" not in support:
        raise RuntimeError("Rust authority boundary is not documented on both harness pages")


def _mode_terminology_gate() -> None:
    relevant = [
        Path("src/codex_plugin_scanner/guard/native_runtime.py"),
        Path("src/codex_plugin_scanner/guard/native_command_model.py"),
        Path("docs/guard/all-harness-hook-review.md"),
        Path("docs/guard/harness-support.md"),
    ]
    strict_mode = re.compile(r"(?i)(native|rust|runtime)[-_ ]strict|strict[-_ ]mode|mode[=: ]+strict")
    found = [str(path) for path in relevant if path.exists() and strict_mode.search(_read(path))]
    if found:
        raise RuntimeError(f"retired strict-mode terminology remains: {found}")


def _hygiene_gate() -> None:
    residue = [str(path) for path in TEMPORARY_PATHS if path.exists()]
    if residue:
        raise RuntimeError(f"temporary Rust migration delivery residue remains: {residue}")


def run(root: Path) -> dict[str, object]:
    original = Path.cwd()
    try:
        if root != original:
            import os

            os.chdir(root)
        manifest = _manifest()
        _hook_worker_gate()
        _rust_hook_edge_gate()
        _resident_client_gate()
        _cli_gate()
        _default_mode_gate()
        _policy_and_identity_gate()
        _workflow_gate()
        _docs_gate()
        _mode_terminology_gate()
        _hygiene_gate()
        return {"schema": SCHEMA, "status": "passed", "manifest": manifest}
    finally:
        if Path.cwd() != original:
            import os

            os.chdir(original)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", type=Path)
    parsed = parser.parse_args()
    payload = run(parsed.root.resolve())
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if parsed.json is not None:
        parsed.json.parent.mkdir(parents=True, exist_ok=True)
        parsed.json.write_text(rendered + "\n", encoding="utf-8")
