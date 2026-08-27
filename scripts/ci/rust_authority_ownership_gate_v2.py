#!/usr/bin/env python3
"""Enforce HOL Guard's permanent Rust runtime authority boundary."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
from pathlib import Path
from typing import Final

SCHEMA: Final = "hol-guard-rust-authority-ownership.v1"
MANIFEST = Path("ci/rust-authority-ownership.v1.json")

TEMPORARY_PATHS: Final = (
    Path(".github/workflows/rust-local-toolchain-export.yml"),
    Path(".github/workflows/rust-pretool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-pretool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-pretool-authority-fallback.yml"),
    Path(".github/workflows/rust-pretool-authority-lint-fix.yml"),
    Path(".github/workflows/rust-pretool-authority-retry-dispatch.yml"),
    Path(".github/workflows/rust-pretool-authority-acceptance.yml"),
    Path(".github/workflows/rust-authority-batch1-finalize.yml"),
    Path(".github/workflows/rust-authority-batch1-merge-gate.yml"),
    Path(".github/workflows/rust-authority-batch1-retry-merge.yml"),
    Path(".github/workflows/rust-authority-batch1-retry-merge-v2.yml"),
    Path(".github/workflows/rust-authority-batch1-converge-v3.yml"),
    Path(".github/workflows/rust-authority-batch1-converge-v4.yml"),
    Path(".github/workflows/rust-posttool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-posttool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-posttool-authority-lint-fix.yml"),
    Path(".github/workflows/rust-posttool-authority-acceptance.yml"),
    Path(".github/workflows/rust-policy-snapshot-generation-fix.yml"),
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
    Path("scripts/ci/select_rust_pretool_authority_candidate.sh"),
    Path("scripts/ci/fallback_rust_pretool_authority.py"),
    Path("scripts/ci/converge_rust_pretool_authority.py"),
    Path("scripts/ci/converge_rust_pretool_authority_v2.py"),
    Path("scripts/ci/bootstrap_rust_posttool_authority.sh"),
    Path("scripts/ci/fallback_rust_posttool_authority.py"),
    Path("scripts/ci/converge_rust_posttool_authority_v2.py"),
    Path("scripts/ci/finalize_rust_authority_migration.py"),
    Path("scripts/ci/finalize_rust_authority_migration_v2.py"),
    Path("docs/guard/.batch1-merge-probe"),
    Path("rust/AUTHORITY_BATCH_1"),
    Path("rust/AUTHORITY_BATCH_1_FINAL"),
    Path("rust/AUTHORITY_BATCH_2"),
    Path("rust/AUTHORITY_BATCH_2_FINAL"),
    Path("rust/AUTHORITY_FINAL"),
)


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"required Rust authority source is missing: {path}") from exc


def manifest() -> dict[str, object]:
    value = json.loads(read(MANIFEST))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise RuntimeError("Rust authority ownership manifest has an invalid schema")
    surfaces = value.get("surfaces")
    if not isinstance(surfaces, dict):
        raise RuntimeError("Rust authority ownership manifest has no surfaces")
    for key in ("pre_tool_use", "post_tool_use"):
        surface = surfaces.get(key)
        if not isinstance(surface, dict):
            raise RuntimeError(f"Rust authority surface is missing: {key}")
        if surface.get("semantic_authority") != "rust":
            raise RuntimeError(f"Rust is not the declared semantic authority: {key}")
        if surface.get("python_semantic_fallback") is not False:
            raise RuntimeError(f"Python semantic fallback is not disabled: {key}")
        if surface.get("native_failure") != "fail_closed":
            raise RuntimeError(f"Native failure is not fail closed: {key}")
    return value


def imports_python_evaluator(path: Path) -> bool:
    tree = ast.parse(read(path), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if not (node.module or "").endswith("command_evaluation"):
            continue
        if any(alias.name == "evaluate_command" for alias in node.names):
            return True
    return False


def pretool_gate() -> None:
    bridge = Path("src/codex_plugin_scanner/guard/native_command_model.py")
    if bridge.exists():
        source = read(bridge)
        forbidden = (
            "Python remains authoritative",
            "from .runtime.command_evaluation import evaluate_command",
            "evaluate_command(",
        )
        residue = [item for item in forbidden if item in source]
        if residue or imports_python_evaluator(bridge):
            raise RuntimeError(f"Python PreToolUse evaluator residue remains: {residue}")

    hook_path = Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py")
    hook = read(hook_path)
    if not re.search(r'event_name\s*==\s*"PreToolUse"|pre_tool', hook):
        raise RuntimeError("daemon ingress has no Rust PreToolUse authority route")
    pretool_region = re.search(
        r'if event_name\s*==\s*"PreToolUse":[\s\S]*?(?=\n\s*if event_name\s*!=\s*"PostToolUse")',
        hook,
    )
    if pretool_region and "self.engine.review(" in pretool_region.group(0):
        raise RuntimeError("PreToolUse can reach the Python HookReviewEngine")
    if "review_pre_tool_native" not in hook and "hol-guard-runtime" not in hook:
        raise RuntimeError("PreToolUse ingress is not bound to the native runtime")

    rust_sources = read(Path("rust/crates/guard-runtime/src/main.rs")) + read(
        Path("rust/crates/guard-command/src/lib.rs")
    )
    for required in ("PreToolUse", "evaluate_pre_tool", "pre-tool"):
        if required not in rust_sources:
            raise RuntimeError(f"Rust PreToolUse authority is missing {required}")


def posttool_gate() -> None:
    hook = read(Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py"))
    if re.search(
        r"if response is None:\s*response = self\.engine\.review\(request\)",
        hook,
    ):
        raise RuntimeError("supported PostToolUse still spills into Python semantic evaluation")
    native = read(Path("src/codex_plugin_scanner/guard/native_runtime.py"))
    if "currently supported Python reference backend remains authoritative" in native:
        raise RuntimeError("native runtime still declares Python PostToolUse authority")
    core = read(Path("rust/crates/guard-hook-core/src/lib.rs"))
    for required in ("review_post_tool", "read_bounded", "scan_text"):
        if required not in core:
            raise RuntimeError(f"Rust PostToolUse core is missing {required}")


def retired_mode_gate() -> None:
    source_paths = (
        Path("src/codex_plugin_scanner/guard/native_runtime.py"),
        Path("src/codex_plugin_scanner/guard/native_command_model.py"),
        Path("src/codex_plugin_scanner/guard/config.py"),
    )
    strict_value = re.compile(r"(?i)(?:native|rust|runtime)[-_ ]strict|[\"']strict[\"']")
    found = [str(path) for path in source_paths if path.exists() and strict_value.search(read(path))]
    if found:
        raise RuntimeError(f"retired strict runtime mode remains in source: {found}")


def policy_and_identity_gate() -> None:
    cargo = read(Path("rust/crates/guard-runtime/Cargo.toml"))
    runtime = read(Path("rust/crates/guard-runtime/src/main.rs"))
    native = read(Path("src/codex_plugin_scanner/guard/native_runtime.py"))
    release = read(Path("scripts/verify_native_runtime_release.py"))
    if "guard-policy-snapshot" not in cargo:
        raise RuntimeError("hol-guard-runtime does not link guard-policy-snapshot")
    for required in (
        "validate_request_policy_snapshot",
        "canonical_config_digest",
        "canonical_policy_digest",
        "policy-snapshot-v1",
        "rule_digest",
    ):
        if required not in runtime:
            raise RuntimeError(f"native policy authority is missing {required}")
    for required in (
        "native_manifest_runtime_mismatch",
        "native_manifest_version_mismatch",
        "native_manifest_rule_mismatch",
        "runtime_sha256",
    ):
        if required not in native and required not in release:
            raise RuntimeError(f"bundled runtime identity guard is missing {required}")


def workflow_gate() -> None:
    source = read(Path(".github/workflows/rust-authority-ownership.yml"))
    required_paths = (
        '"rust/**"',
        '"src/codex_plugin_scanner/guard/**"',
        '"ci/native_runtime/**"',
        '"scripts/**"',
        '"tests/**"',
        '"docs/guard/**"',
        '".github/workflows/**"',
    )
    missing = [item for item in required_paths if item not in source]
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
    missing_commands = [item for item in required_commands if item not in source]
    if missing_commands:
        raise RuntimeError(f"authority workflow integration coverage is incomplete: {missing_commands}")


def docs_gate() -> None:
    architecture = read(Path("docs/guard/all-harness-hook-review.md"))
    support = read(Path("docs/guard/harness-support.md"))
    forbidden = (
        "causing the server to fall through to the legacy CLI path",
        "Python remains authoritative",
    )
    for item in forbidden:
        if item in architecture or item in support:
            raise RuntimeError(f"legacy Python authority documentation remains: {item}")
    if "## Rust Authority Boundary" not in architecture:
        raise RuntimeError("all-harness architecture lacks the Rust authority boundary")
    if "## Rust Authority Boundary" not in support:
        raise RuntimeError("harness support lacks the Rust authority boundary")


def hygiene_gate() -> None:
    residue = [str(path) for path in TEMPORARY_PATHS if path.exists()]
    if residue:
        raise RuntimeError(f"temporary Rust migration delivery residue remains: {residue}")


def run(root: Path) -> dict[str, object]:
    original = Path.cwd()
    try:
        os.chdir(root)
        value = manifest()
        pretool_gate()
        posttool_gate()
        retired_mode_gate()
        policy_and_identity_gate()
        workflow_gate()
        docs_gate()
        hygiene_gate()
        return {"schema": SCHEMA, "status": "passed", "manifest": value}
    finally:
        os.chdir(original)


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
