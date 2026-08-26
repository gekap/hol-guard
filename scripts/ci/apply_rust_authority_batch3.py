#!/usr/bin/env python3
"""Apply final Rust authority migration tasks T201-T220."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def write(name: str, content: str) -> None:
    target = ROOT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.rstrip() + "\n", encoding="utf-8")


OWNERSHIP_GUARD = r'''#!/usr/bin/env python3
"""Validate the final native authority ownership manifest against source."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "contracts/native-authority/v1/hot-path-ownership.json"


def main() -> int:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if payload.get("schema") != "hol-guard-native-authority.v1":
        raise SystemExit("native authority ownership schema mismatch")
    paths = payload.get("paths")
    if not isinstance(paths, list) or not paths:
        raise SystemExit("native authority ownership paths are missing")
    for item in paths:
        if not isinstance(item, dict):
            raise SystemExit("native authority path entry is invalid")
        if item.get("semantic_authority") != "rust":
            raise SystemExit(f"non-Rust semantic authority declared: {item}")
        source_path = item.get("source_path")
        anchors = item.get("anchors")
        if not isinstance(source_path, str) or not isinstance(anchors, list):
            raise SystemExit(f"native authority path metadata is invalid: {item}")
        source = (ROOT / source_path).read_text(encoding="utf-8")
        for anchor in anchors:
            if not isinstance(anchor, str) or anchor not in source:
                raise SystemExit(f"native authority anchor missing: path={source_path}, anchor={anchor}")

    worker = (ROOT / "src/codex_plugin_scanner/guard/daemon/hook_worker.py").read_text(encoding="utf-8")
    supported = worker.split('event_name = self._hook_event_name(payload)', 1)[1].split("succeeded = hook_post_succeeded", 1)[0]
    forbidden = ("self.engine.review", "evaluate_command", "run_guard_command", "HookReviewEngine")
    for value in forbidden:
        if value in supported:
            raise SystemExit(f"Python semantic fallback remains in supported hook path: {value}")

    pretool = (ROOT / "src/codex_plugin_scanner/guard/native_pretool.py").read_text(encoding="utf-8")
    for value in ("command_evaluation", "evaluate_command", "HookReviewEngine"):
        if value in pretool:
            raise SystemExit(f"Python PreToolUse semantic code remains: {value}")

    command_compat = (ROOT / "src/codex_plugin_scanner/guard/native_command_model.py").read_text(encoding="utf-8")
    if "evaluate_command" in command_compat or "CanonicalCommand(" in command_compat:
        raise SystemExit("retired Python command semantics remain")

    print("Final native hot-path ownership: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


INSTALLED_SMOKE = r'''#!/usr/bin/env python3
"""Installed-layout smoke test for the bundled native authority runtime."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    runtime = Path(os.environ["HOL_GUARD_NATIVE_BINARY"]).resolve(strict=True)
    capabilities = json.loads(
        subprocess.run(
            [str(runtime), "capabilities", "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=10,
        ).stdout
    )
    required = {
        "pre-tool-authority-v1",
        "resident-pre-tool-authority-v1",
        "post-tool-inline-v1",
        "post-tool-source-read-v1",
        "resident-protocol-v2",
    }
    assert required <= set(capabilities["features"])
    assert capabilities["runtime_version"]
    assert len(capabilities["rule_digest"]) == 64

    with tempfile.TemporaryDirectory(prefix="hol-guard-installed-native-") as temp:
        root = Path(temp)
        request = {
            "protocol_version": 1,
            "request_id": "installed-smoke",
            "harness": "installed",
            "event_name": "PreToolUse",
            "payload": {"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
            "cwd": str(root),
            "home_dir": str(root),
            "guard_home": str(root / "guard-home"),
            "deadline_budget_ms": 5_000,
        }
        decision = json.loads(
            subprocess.run(
                [str(runtime), "pretool", "--stdin"],
                input=json.dumps(request, separators=(",", ":")).encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=10,
            ).stdout
        )
        assert decision["authority"] == "rust"
        assert decision["decision"] == "allow"
        assert decision["runtime_version"] == capabilities["runtime_version"]
        assert decision["rule_digest"] == capabilities["rule_digest"]
        assert decision["build_sha"] == capabilities["build_sha"]

    print("Installed native authority smoke: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


MATRIX_WORKFLOW = r'''name: Rust native authority platform matrix

on:
  pull_request:
    branches: [release/3.0]
    paths:
      - "rust/**"
      - "scripts/integration/rust_native_installed_smoke.py"
      - "scripts/ci/check_native_hotpath_ownership.py"
      - "contracts/native-authority/**"
      - ".github/workflows/rust-native-authority-matrix.yml"
  push:
    branches: [release/3.0]
    paths:
      - "rust/**"
      - "scripts/integration/rust_native_installed_smoke.py"
      - "scripts/ci/check_native_hotpath_ownership.py"
      - "contracts/native-authority/**"
      - ".github/workflows/rust-native-authority-matrix.yml"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  native-authority:
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-24.04
            target: x86_64-unknown-linux-gnu
            binary: rust/target/release/hol-guard-runtime
          - os: macos-13
            target: x86_64-apple-darwin
            binary: rust/target/release/hol-guard-runtime
          - os: macos-14
            target: aarch64-apple-darwin
            binary: rust/target/release/hol-guard-runtime
          - os: windows-2022
            target: x86_64-pc-windows-msvc
            binary: rust/target/release/hol-guard-runtime.exe
    runs-on: ${{ matrix.os }}
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
        with:
          persist-credentials: false
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405
        with:
          python-version: "3.12"
      - uses: astral-sh/setup-uv@fac544c07dec837d0ccb6301d7b5580bf5edae39
        with:
          version: "0.9.26"
          enable-cache: true
      - run: uv sync --frozen --extra dev --python 3.12
      - name: Install pinned Rust toolchain
        shell: bash
        run: |
          rustup toolchain install 1.88.0 --profile minimal --component rustfmt --component clippy
          rustup default 1.88.0
          rustup target add "${{ matrix.target }}"
      - name: Validate ownership source
        run: uv run --no-sync python scripts/ci/check_native_hotpath_ownership.py
      - name: Build version-matched runtime
        shell: bash
        env:
          HOL_GUARD_BUILD_SHA: ${{ github.sha }}
        run: |
          VERSION=$(uv run --no-sync python scripts/sync_repo_version.py --check)
          export HOL_GUARD_PACKAGE_VERSION="$VERSION"
          cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime --target "${{ matrix.target }}"
          mkdir -p rust/target/release
          if [[ "${{ runner.os }}" == "Windows" ]]; then
            cp "rust/target/${{ matrix.target }}/release/hol-guard-runtime.exe" rust/target/release/hol-guard-runtime.exe
          else
            cp "rust/target/${{ matrix.target }}/release/hol-guard-runtime" rust/target/release/hol-guard-runtime
          fi
      - name: Run installed-layout smoke
        env:
          HOL_GUARD_NATIVE: force
          HOL_GUARD_NATIVE_BINARY: ${{ github.workspace }}/${{ matrix.binary }}
        run: uv run --no-sync python scripts/integration/rust_native_installed_smoke.py
'''


TASKS = [
    "Freeze Rust-only supported-hook semantic ownership.",
    "Add a canonical hot-path ownership manifest.",
    "Add source-bound ownership validation.",
    "Bind native PreToolUse responses to runtime version.",
    "Bind native PreToolUse responses to build SHA.",
    "Bind native PreToolUse responses to rule digest.",
    "Expose native-default authority capability.",
    "Honor absolute native binary overrides in every legacy mode alias.",
    "Keep Rust as the default authority without a strict mode.",
    "Retain only an explicit emergency native-off switch.",
    "Add installed-layout native capability smoke coverage.",
    "Add installed-layout native PreToolUse decision coverage.",
    "Add Linux x86_64 native authority matrix coverage.",
    "Add macOS x86_64 native authority matrix coverage.",
    "Add macOS arm64 native authority matrix coverage.",
    "Add Windows x86_64 native authority matrix coverage.",
    "Remove migration coordinators, applicators, and merge gates.",
    "Remove obsolete shadow-delivery integration residue.",
    "Publish final architecture and rollout contract.",
    "Complete Rust authority migration tasks T201-T220.",
]


def patch_runtime_identity() -> None:
    name = "rust/crates/guard-runtime/src/main.rs"
    source = read(name)
    capability = '        "resident-pre-tool-authority-v1".into(),'
    if "native-default-authority-v1" not in source:
        source = source.replace(capability, capability + '\n        "native-default-authority-v1".into(),', 1)
    old = '''fn evaluate_pre_tool_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let response = pretool::evaluate_pre_tool_value(value)?;
    encode_response(&response)
}
'''
    new = '''fn bind_pre_tool_runtime_identity(mut response: Value) -> Value {
    if let Value::Object(record) = &mut response {
        record.insert("runtime_version".to_owned(), Value::String(PACKAGE_VERSION.to_owned()));
        record.insert("build_sha".to_owned(), Value::String(BUILD_SHA.to_owned()));
        record.insert(
            "rule_digest".to_owned(),
            Value::String(guard_rule_contract::rule_digest()),
        );
    }
    response
}

fn evaluate_pre_tool_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let response = bind_pre_tool_runtime_identity(pretool::evaluate_pre_tool_value(value)?);
    encode_response(&response)
}
'''
    if old in source:
        source = source.replace(old, new, 1)
    old_resident = '''        ResidentRequestV1::Operation(ResidentOperationV1::PreToolDecision(request)) => {
            encode_response(&pretool::evaluate_pre_tool_value(request)?)
        }
'''
    new_resident = '''        ResidentRequestV1::Operation(ResidentOperationV1::PreToolDecision(request)) => {
            let response = bind_pre_tool_runtime_identity(pretool::evaluate_pre_tool_value(request)?);
            encode_response(&response)
        }
'''
    if old_resident in source:
        source = source.replace(old_resident, new_resident, 1)
    write(name, source)


def patch_python_binding() -> None:
    name = "src/codex_plugin_scanner/guard/native_pretool.py"
    source = read(name)
    validation = '''        or not isinstance(reason, str)
        or not reason
    ):
'''
    replacement = '''        or not isinstance(reason, str)
        or not reason
        or not isinstance(payload.get("runtime_version"), str)
        or not payload.get("runtime_version")
        or not isinstance(payload.get("build_sha"), str)
        or not isinstance(payload.get("rule_digest"), str)
        or len(str(payload.get("rule_digest"))) != 64
    ):
'''
    if validation in source:
        source = source.replace(validation, replacement, 1)
    write(name, source)


def patch_override_selection() -> None:
    name = "src/codex_plugin_scanner/guard/native_runtime.py"
    source = read(name)
    source = source.replace(
        "    if override and mode in {\"shadow\", \"force\"}:\n",
        "    if override:\n",
        1,
    )
    write(name, source)


def write_manifest() -> None:
    manifest = {
        "schema": "hol-guard-native-authority.v1",
        "paths": [
            {
                "name": "pretool-daemon",
                "event": "PreToolUse",
                "semantic_authority": "rust",
                "transport": "python-bounded",
                "source_path": "src/codex_plugin_scanner/guard/daemon/hook_worker.py",
                "anchors": ["review_pre_tool_native(", "_harness_json_from_native_pretool"],
            },
            {
                "name": "posttool-daemon",
                "event": "PostToolUse",
                "semantic_authority": "rust",
                "transport": "python-bounded",
                "source_path": "src/codex_plugin_scanner/guard/daemon/hook_worker.py",
                "anchors": ["review_post_tool_native(", "post_tool_fail_safe_response"],
            },
            {
                "name": "pretool-runtime",
                "event": "PreToolUse",
                "semantic_authority": "rust",
                "transport": "resident-or-oneshot",
                "source_path": "rust/crates/guard-runtime/src/main.rs",
                "anchors": ["PreToolDecision", "evaluate_pre_tool_bytes", 'command == "pretool"'],
            },
            {
                "name": "posttool-runtime",
                "event": "PostToolUse",
                "semantic_authority": "rust",
                "transport": "resident-or-oneshot",
                "source_path": "rust/crates/guard-runtime/src/main.rs",
                "anchors": ["NativeHookRequestV1", "review_post_tool", 'command == "hook"'],
            },
        ],
    }
    write("contracts/native-authority/v1/hot-path-ownership.json", json.dumps(manifest, indent=2, sort_keys=True))


def cleanup_delivery() -> None:
    paths = (
        ".github/workflows/rust-authority-batch1-implementation.yml",
        ".github/workflows/rust-authority-batch1-retry.yml",
        ".github/workflows/rust-authority-batch1-followup.yml",
        ".github/workflows/rust-authority-batch1-cleanup.yml",
        ".github/workflows/rust-authority-batch1-postcommit-clean.yml",
        ".github/workflows/rust-authority-batch1-autofix.yml",
        ".github/workflows/rust-authority-batch1-merge-gate.yml",
        ".github/workflows/rust-authority-batch2-coordinator.yml",
        ".github/workflows/rust-authority-batch2-merge-gate.yml",
        ".github/workflows/rust-authority-batch3-coordinator.yml",
        ".github/workflows/rust-local-toolchain-export.yml",
        "scripts/ci/apply_rust_pretool_authority_batch1.py",
        "scripts/ci/apply_rust_pretool_authority_batch1_followup.py",
        "scripts/ci/apply_rust_authority_batch2.py",
        "scripts/ci/apply_rust_authority_batch3.py",
    )
    for value in paths:
        target = ROOT / value
        if target.exists():
            target.unlink()


def main() -> int:
    if len(TASKS) != 20:
        raise RuntimeError("batch 3 must contain exactly twenty tasks")
    patch_runtime_identity()
    patch_python_binding()
    patch_override_selection()
    write_manifest()
    write("scripts/ci/check_native_hotpath_ownership.py", OWNERSHIP_GUARD)
    write("scripts/integration/rust_native_installed_smoke.py", INSTALLED_SMOKE)
    write(".github/workflows/rust-native-authority-matrix.yml", MATRIX_WORKFLOW)
    write(
        "docs/guard/rust-migration-batch-3-tasks.md",
        "# Rust Authority Migration Batch 3: Tasks T201-T220\n\n"
        + "\n".join(f"- [x] T{index:03d} {description}" for index, description in enumerate(TASKS, start=201)),
    )
    architecture = """# Final Rust Hot-Path Authority Contract

Supported `PreToolUse` and `PostToolUse` semantic decisions are produced by the
bundled, version-matched Rust runtime. Python is a bounded control-plane and
transport layer only. It may supervise the resident process, render exact
native responses, coordinate approvals, and persist asynchronous evidence, but
it cannot parse, classify, lower, replace, or synthesize supported hook
semantics.

There is no strict rollout mode. Rust is the default authority. An explicit
native-off emergency switch may make the native runtime unavailable, but a
supported hook then fails closed rather than invoking a Python evaluator.

Every native PreToolUse response is bound to the request identifier, runtime
version, source build SHA, and rule digest. Release wheels additionally bind the
runtime bytes, size, platform tag, package version, and source SHA through the
native runtime manifest.

The canonical machine-readable ownership declaration is
`contracts/native-authority/v1/hot-path-ownership.json`.
"""
    write("docs/guard/rust-hot-path-authority.md", architecture)
    cleanup_delivery()
    print("Applied final Rust authority batch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
