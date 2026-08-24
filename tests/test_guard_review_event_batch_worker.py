"""Shared batch-worker assertions used by Review outbox delivery coverage."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_event_wake import register_review_event_outbox_wake_callback
from codex_plugin_scanner.guard.runtime.review_event_batch_worker import take_bounded_batch
from codex_plugin_scanner.guard.runtime.review_event_worker_lifecycle import (
    LiveRequestSyncWorker,
    _restart_dead_review_event_worker,
)
from codex_plugin_scanner.guard.store import GuardStore


def assert_byte_capped_batch() -> None:
    """Exercise the byte cap independently of an event's request shape."""

    bounded, oversized = take_bounded_batch(
        [(1, {"payload": "x" * 256}), (2, {"payload": "y" * 256})],
        maximum_events=50,
        maximum_bytes=300,
    )
    assert bounded.sequences == [1] and bounded.byte_size <= 300 and oversized == []


def test_oversized_leading_event_blocks_later_entries() -> None:
    bounded, oversized = take_bounded_batch(
        [(1, {"payload": "x" * 512}), (2, {"payload": "ok"})],
        maximum_events=50,
        maximum_bytes=300,
    )

    assert bounded.sequences == [] and oversized == [1]


def test_watchdog_restarts_confirmed_dead_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state: dict[str, object] = {}

    class ReplacementThread:
        def __init__(self, **_kwargs: object) -> None:
            self.started = False

        def start(self) -> None:
            self.started = True

        def is_alive(self) -> bool:
            return self.started

    sync = SimpleNamespace(
        _load_sync_state=lambda _store: dict(state),
        _state_int=lambda payload, key: int(payload.get(key, 0)),
        _now=lambda: "2026-08-24T14:00:00+00:00",
        _save_sync_state=lambda _store, payload: state.update(payload),
        threading=SimpleNamespace(Thread=ReplacementThread),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.review_event_worker_lifecycle._sync_module",
        lambda: sync,
    )
    worker = LiveRequestSyncWorker(
        thread=threading.Thread(target=lambda: None),
        stop_event=threading.Event(),
        wake_event=threading.Event(),
    )

    store = GuardStore(tmp_path / "guard")
    assert _restart_dead_review_event_worker(store, worker) is True
    assert worker.thread.is_alive() is True
    assert state["watchdog_restart_count"] == 1


def test_requeue_commit_wakes_delivery_worker(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    request = GuardApprovalRequest(
        request_id="request-1",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Test action",
        artifact_hash="hash-1",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/test/config.toml",
        review_command="hol-guard approvals approve request-1",
        approval_url="http://127.0.0.1/requests/request-1",
        action_identity="request-1",
        queue_group_id="request-1",
        trigger_summary="Review action",
        last_seen_at="2026-08-24T14:00:00+00:00",
    )
    store.add_approval_request(request, "2026-08-24T14:00:00+00:00")
    wakes: list[None] = []
    unregister = register_review_event_outbox_wake_callback(store, lambda: wakes.append(None))

    assert store.requeue_pending_live_requests(changed_at="2026-08-24T14:00:01+00:00") == 1
    unregister()
    assert wakes == [None]
