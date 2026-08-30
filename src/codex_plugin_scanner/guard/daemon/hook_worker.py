"""Daemon-resident hook transport for the Rust Guard data plane.

The Python worker authenticates the daemon route, supplies bounded control-plane
metadata, renders the already-produced native decision for each harness, and
persists best-effort activity after PostToolUse. It does not parse/classify a
supported hook action, read content for semantic review, or invoke a Python
semantic fallback.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, final

from ..cli.commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
)
from ..config import load_guard_config
from ..native_hook_edge import review_hook_edge_native

if TYPE_CHECKING:
    from ..store import GuardStore


class CommandActivityWriter(Protocol):
    def submit_command_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> bool: ...


def runtime_hook_event_name(payload: Mapping[str, object]) -> str:
    """Best-effort display/fail-safe event label; Rust owns semantic extraction."""
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "PreToolUse"


class HookWorkerUnsupported(RuntimeError):  # noqa: N818
    """Compatibility exception retained for callers outside the native hook surface."""


@final
class HookWorker:
    """Transport raw hook envelopes to the bundled Rust authority."""

    def __init__(self, *, store: GuardStore, activity_writer: CommandActivityWriter | None = None):
        self.store = store
        self.guard_home = store.guard_home
        self.activity_writer = activity_writer
        from .hook_metrics import HookMetricsRecorder

        self.metrics = HookMetricsRecorder()

    def _load_config(self, guard_home: Path, workspace: Path | None):
        return load_guard_config(guard_home, workspace=workspace)

    def review_http_payload(
        self,
        *,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        default_harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None = None,
    ) -> dict[str, object]:
        """Return a harness response from Rust authority or a fail-closed result."""

        harness = self._runtime_harness(params) or default_harness
        try:
            config = self._load_config(guard_home, workspace)
            native = review_hook_edge_native(
                payload=payload,
                harness=harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
                observe_mode=config.mode == "observe",
                deadline=deadline,
            )
        except Exception:
            native = None
        if native is None:
            event_name = runtime_hook_event_name(payload)
            if event_name == "PostToolUse":
                self._record_post_tool_activity(
                    harness=harness,
                    payload=payload,
                    succeeded=hook_post_succeeded(event_name, payload),
                )
            return post_tool_fail_safe_response(
                harness,
                reason="HOL Guard could not complete the native hook decision safely.",
                reason_code="native_hook_edge_unavailable",
                event_name=event_name,
            )

        event_name = str(native.get("event_name") or runtime_hook_event_name(payload))
        if event_name == "PostToolUse":
            self._record_post_tool_activity(
                harness=harness,
                payload=payload,
                succeeded=hook_post_succeeded(event_name, payload),
            )
        return _harness_json_from_native_edge(harness, native)

    def _record_post_tool_activity(
        self,
        *,
        harness: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> None:
        if self.activity_writer is not None:
            _ = self.activity_writer.submit_command_activity(
                harness=harness,
                event="PostToolUse",
                payload=payload,
                succeeded=succeeded,
            )
            return
        _ = record_post_hook_command_activity_best_effort(
            store=self.store,
            guard_home=self.guard_home,
            harness=harness,
            event="PostToolUse",
            payload=payload,
            succeeded=succeeded,
        )

    def _runtime_harness(self, params: Mapping[str, list[str]]) -> str | None:
        values = params.get("runtime-harness", [])
        if values and isinstance(values[-1], str) and values[-1].strip():
            return values[-1].strip()
        return None


def _canonical_hook_harness(harness: str) -> str:
    return harness.strip().lower().replace("_", "-")


def _pre_tool_harness_response(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    action = str(response.get("minimum_action") or response.get("policy_action") or "block")
    reason = str(response.get("reason") or "HOL Guard requires native review before execution.")
    reason_code = str(response.get("reason_code") or "native_pre_tool_review")
    canonical = _canonical_hook_harness(harness)
    if action == "allow" and response.get("decision") == "allow":
        if canonical in {"pi", "omp"}:
            return {
                "decision": "allow",
                "policy_action": "allow",
                "reason_code": reason_code,
            }
        return {
            "continue": True,
            "policy_action": "allow",
            "reason_code": reason_code,
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
        }

    if canonical in {"pi", "omp"}:
        return {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "reason_code": reason_code,
            "policy_action": action,
        }

    permission_decision = "deny"
    if action == "review" and canonical not in {"codex", "kimi", "grok", "zcode"}:
        permission_decision = "ask"
    return {
        "policy_action": action,
        "reason_code": reason_code,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        },
    }


def _post_tool_harness_response(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    canonical = _canonical_hook_harness(harness)
    payload = {
        key: value
        for key, value in response.items()
        if key
        in {
            "decision",
            "reason",
            "model_output_action",
            "reviewed_output_sha256",
            "reviewed_excerpt",
            "notice",
            "reason_code",
            "policy_action",
            "observed_policy_action",
            "observe_mode",
        }
    }
    if canonical in {"pi", "omp"}:
        return payload
    decision = str(payload.get("decision") or "")
    model_output_action = str(payload.get("model_output_action") or "")
    if decision == "allow" and model_output_action == "allow_original":
        return {
            "policy_action": "allow",
            "reason_code": str(payload.get("reason_code") or "native_post_tool_allow"),
            "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        }
    reason = str(payload.get("reason") or "HOL Guard blocked this tool output because it could not be proven safe.")
    reason_code = str(payload.get("reason_code") or "native_post_tool_block")
    return post_tool_native_block_response(reason=reason, reason_code=reason_code)


def _harness_json_from_native_edge(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    event_name = str(response.get("event_name") or "PreToolUse")
    if event_name == "PreToolUse":
        return _pre_tool_harness_response(harness, response)
    if event_name == "PostToolUse":
        return _post_tool_harness_response(harness, response)
    reason = str(response.get("reason") or "HOL Guard requires review for this native hook event.")
    return post_tool_fail_safe_response(
        harness,
        reason=reason,
        reason_code=str(response.get("reason_code") or "native_hook_event_review_required"),
        event_name=event_name,
    )


def post_tool_native_block_response(
    *,
    reason: str = "HOL Guard blocked this tool output because it could not be proven safe.",
    reason_code: str = "fast_path_block",
) -> dict[str, object]:
    return {
        "decision": "block",
        "reason": reason,
        "continue": False,
        "stopReason": reason,
        "policy_action": "block",
        "risk_summary": reason,
        "model_output_action": "block",
        "notice": "warning",
        "reason_code": reason_code,
    }


def post_tool_fail_safe_response(
    harness: str,
    *,
    reason: str = "HOL Guard could not complete local hook review safely.",
    reason_code: str = "daemon_worker_exception",
    event_name: str = "PostToolUse",
) -> dict[str, object]:
    canonical = _canonical_hook_harness(harness)
    if event_name == "PreToolUse" and canonical not in {"pi", "omp"}:
        return {
            "policy_action": "block",
            "reason_code": reason_code,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            },
        }
    if canonical in {"pi", "omp"}:
        return {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "reason_code": reason_code,
        }
    return post_tool_native_block_response(reason=reason, reason_code=reason_code)


__all__ = [
    "HookWorker",
    "HookWorkerUnsupported",
    "post_tool_fail_safe_response",
    "post_tool_native_block_response",
]
