from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_process_entrypoint as hook_entrypoint_module
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.native_route_receipt import (
    record_native_hook_route,
    reset_native_hook_route,
)


def test_route_receipt_requires_a_current_native_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hook_entrypoint_module, "_native_mode_requires_rust", lambda: True)
    reset_native_hook_route()
    assert hook_entrypoint_module._current_decision_route() == "python_semantic"  # pyright: ignore[reportPrivateUsage]

    record_native_hook_route("native_resident")
    assert hook_entrypoint_module._current_decision_route() == "native_resident"  # pyright: ignore[reportPrivateUsage]

    reset_native_hook_route()
    assert hook_entrypoint_module._current_decision_route() == "python_semantic"  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(hook_entrypoint_module, "_native_mode_requires_rust", lambda: False)
    assert hook_entrypoint_module._current_decision_route() == "python_semantic"  # pyright: ignore[reportPrivateUsage]


def test_route_receipt_waits_for_metrics_lock(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    runner._metrics_lock.acquire()  # pyright: ignore[reportPrivateUsage]
    thread = threading.Thread(
        target=runner._record_route_metric,  # pyright: ignore[reportPrivateUsage]
        args=("native_resident",),
    )
    try:
        thread.start()
        thread.join(timeout=0.05)
        assert thread.is_alive()
    finally:
        runner._metrics_lock.release()  # pyright: ignore[reportPrivateUsage]
        thread.join(timeout=1)

    assert runner.stats()["routes"] == {"native_resident": 1}
