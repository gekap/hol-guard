"""Tests for Rust PostToolUse authority fail-closed daemon behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from codex_plugin_scanner.guard.store import GuardStore


def _post_tool_payload() -> dict[str, object]:
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/foo.ts"},
        "tool_response": [{"type": "text", "text": "export const value = 1;\n"}],
    }


def test_hook_worker_fails_closed_when_forced_posttool_native_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_post_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "force",
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload=_post_tool_payload(),
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_post_tool_unavailable"


def test_hook_worker_fails_closed_when_available_native_posttool_returns_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_post_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="auto",
            available=True,
            compatible=True,
            reason="ok",
        ),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload=_post_tool_payload(),
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "native_post_tool_unavailable"
