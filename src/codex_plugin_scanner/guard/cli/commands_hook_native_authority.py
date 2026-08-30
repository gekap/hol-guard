"""Route production hook decisions through the native Rust data plane."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..daemon.hook_worker import HookWorker
from ..store import GuardStore
from .commands_support_interaction import _emit


def try_native_hook_authority(
    *,
    payload: dict[str, object],
    harness: str,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    store: GuardStore,
) -> dict[str, Any]:
    """Return the fail-closed Rust hook result for the raw harness envelope.

    Environment mode settings no longer select a Python semantic evaluator.
    The worker itself returns a deterministic block when the bundled native
    runtime cannot complete the decision safely.
    """

    return HookWorker(store=store).review_http_payload(
        payload=payload,
        params={},
        default_harness=harness,
        home_dir=home_dir,
        guard_home=guard_home,
        workspace=workspace,
    )


def try_native_or_source_ref_hook(
    args: argparse.Namespace,
    *,
    config: GuardConfig | None,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
) -> int | None:
    """Use Rust authority for every production hook reaching this route.

    The historical Python source-ref semantic fallback is intentionally not
    reachable here. Source-reference validation and content I/O are performed
    by the Rust hook core; native failure is rendered fail closed by HookWorker.
    """

    del config
    native_result = try_native_hook_authority(
        payload=payload,
        harness=args.harness,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        workspace=runtime_workspace,
        store=store,
    )
    _emit("hook", native_result, getattr(args, "json", False))
    return 0
