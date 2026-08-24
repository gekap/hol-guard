"""In-process wake notifications for the durable Review outbox."""

from __future__ import annotations

import threading
from collections.abc import Callable

_LOCK = threading.Lock()
_CALLBACKS: dict[int, Callable[[], None]] = {}


def register_review_event_outbox_wake_callback(
    store: object,
    callback: Callable[[], None],
) -> Callable[[], None]:
    """Register one process-local callback and return its safe unsubscriber."""

    key = id(store)
    with _LOCK:
        _CALLBACKS[key] = callback

    def unregister() -> None:
        with _LOCK:
            if _CALLBACKS.get(key) is callback:
                _ = _CALLBACKS.pop(key, None)

    return unregister


def notify_review_event_outbox_wake(store: object) -> None:
    with _LOCK:
        callback = _CALLBACKS.get(id(store))
    if callback is not None:
        callback()
