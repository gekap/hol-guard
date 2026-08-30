from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.config import hook_fast_path_enabled
from codex_plugin_scanner.guard.native_runtime import native_mode

ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_no_environment_configuration_selects_native_fast_path(monkeypatch) -> None:
    monkeypatch.delenv("HOL_GUARD_NATIVE", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_BINARY", raising=False)
    monkeypatch.delenv("HOL_GUARD_HOOK_FAST_PATH", raising=False)

    assert native_mode() == "auto"
    assert hook_fast_path_enabled() is True


def test_daemon_hook_worker_has_no_python_semantic_engine() -> None:
    source = _source("src/codex_plugin_scanner/guard/daemon/hook_worker.py")
    assert "review_hook_edge_native" in source
    for forbidden in (
        "HookReviewEngine",
        "ContentScanner",
        "HookDecisionCache",
        "review_pre_tool_native",
        "review_post_tool_native",
        "_parse_source_ref(",
        "_pre_tool_command(",
    ):
        assert forbidden not in source


def test_cli_hook_authority_has_no_source_ref_or_mode_fallback() -> None:
    source = _source("src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py")
    for forbidden in (
        "_try_source_ref_fast_path",
        "native_mode",
        "HookWorkerUnsupported",
    ):
        assert forbidden not in source
    assert "try_native_hook_authority" in source


def test_production_resident_send_delegates_client_protocol_to_rust() -> None:
    source = _source("src/codex_plugin_scanner/guard/native_runtime_resident.py")
    class_start = source.index("class _ResidentService:")
    send_start = source.index("    def _send(", class_start)
    send_end = source.index("\n    def _ensure_started(", send_start)
    send = source[send_start:send_end]

    assert "resident-client" in send
    assert "run_isolated_hook_process" in send
    assert "_send_authenticated_unix_request" not in send
    assert "_send_authenticated_loopback_request" not in send
    assert "socket.create_connection" not in send


def test_ownership_manifest_requires_rust_hook_edge_client_and_io() -> None:
    manifest = json.loads(_source("ci/rust-authority-ownership.v1.json"))
    assert manifest["default_runtime_contract"] == {
        "native_mode_without_environment": "auto",
        "hook_fast_path_without_environment": True,
        "path_runtime_search": False,
        "decision_time_runtime_download": False,
    }
    surfaces = manifest["surfaces"]
    assert surfaces["hook_edge"]["event_and_action_extraction"] == "rust"
    assert surfaces["hook_edge"]["python_semantic_envelope_parsing"] is False
    assert surfaces["resident_client"]["authentication"] == "rust"
    assert surfaces["resident_client"]["framing"] == "rust"
    assert surfaces["resident_client"]["socket_io"] == "rust"
    assert set(surfaces["decision_critical_io"].values()) == {"rust"}


def test_runtime_source_exposes_native_hook_edge_and_resident_client() -> None:
    runtime = _source("rust/crates/guard-runtime/src/main.rs")
    oneshot = _source("rust/crates/guard-runtime/src/oneshot.rs")
    client = _source("rust/crates/guard-runtime/src/resident_client.rs")

    assert '"hook-edge-v2"' in runtime
    assert '"resident-client-v1"' in runtime
    assert 'command == "hook-edge"' in runtime
    assert 'command == "resident-client"' in runtime
    assert "evaluate_hook_edge_value" in oneshot
    assert "native_pre_tool_unsupported_review" in oneshot
    assert "REQUEST_MAGIC" in client
    assert "RESPONSE_MAGIC" in client
