"""Compatibility application for queued legacy Review policy bundles."""

from __future__ import annotations

from typing import TypeGuard

from ..action_lattice import is_guard_action as _is_guard_action
from ..models import DECISION_SCOPE_VALUES, DecisionScope, PolicyDecision
from ..review_contracts import (
    GuardReviewContractError,
    guard_review_oauth_metadata,
    validate_decision_memory_bundle_target,
    validated_decision_memory_bundle,
)
from ..review_memory_ack import build_decision_memory_ack
from ..store import GuardStore

_GUARD_REVIEW_MEMORY_REGISTRY_SYNC_KEY = "guard_review_memory_registry"
_GUARD_REVIEW_MEMORY_VERSION_SYNC_KEY = "guard_review_memory_policy_version"
_GUARD_REVIEW_MEMORY_ACK_SYNC_KEY = "guard_review_memory_last_ack"


def execute_legacy_policy_sync(
    payload: dict[str, object],
    *,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    bundle_payload = _payload_mapping(payload.get("decisionMemoryBundle") or payload.get("decision_memory_bundle"))
    if not bundle_payload:
        raise ValueError("missing_decision_memory_bundle")
    oauth = guard_review_oauth_metadata(store)
    bundle = validated_decision_memory_bundle(bundle_payload, store=store)
    validate_decision_memory_bundle_target(
        bundle=bundle,
        oauth=oauth,
        last_policy_version=_stored_review_memory_policy_version(store),
    )
    registry = _stored_review_memory_registry(store)
    revocations = bundle.get("revocations")
    for revoked_rule_id in revocations if isinstance(revocations, list) else []:
        revoked_key = _optional_string(revoked_rule_id)
        if revoked_key is not None:
            registry.pop(revoked_key, None)
    rejected_rule_ids: list[str] = []
    applied_rule_count = 0
    rules = bundle.get("memoryRules")
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            raise ValueError("invalid_decision_memory_rule")
        rule_id = _optional_string(rule.get("ruleId"))
        if rule_id is None:
            raise ValueError("invalid_decision_memory_rule")
        try:
            decision = _decision_from_memory_rule(bundle=bundle, rule=rule)
        except GuardReviewContractError:
            rejected_rule_ids.append(rule_id)
            continue
        registry[rule_id] = {
            "decision": decision.to_dict(),
            "ruleId": rule_id,
        }
        applied_rule_count += 1
    store.replace_remote_policies(
        [
            *_existing_non_review_remote_policies(store),
            *[_decision_from_registry_entry(entry) for entry in registry.values()],
        ],
        generated_at,
        remote_write_authorized=True,
    )
    store.set_sync_payload(
        _GUARD_REVIEW_MEMORY_REGISTRY_SYNC_KEY,
        list(registry.values()),
        generated_at,
    )
    ack_status = "accepted" if not rejected_rule_ids else "rejected"
    if ack_status == "accepted":
        store.set_sync_payload(
            _GUARD_REVIEW_MEMORY_VERSION_SYNC_KEY,
            {"policyVersion": _optional_string(bundle.get("policyVersion"))},
            generated_at,
        )
    ack = build_decision_memory_ack(
        bundle=bundle,
        oauth=oauth,
        status=ack_status,
        applied_rule_count=applied_rule_count,
        reason=None if not rejected_rule_ids else "decision_memory_rule_rejected",
        rejected_rule_ids=rejected_rule_ids,
    )
    store.set_sync_payload(_GUARD_REVIEW_MEMORY_ACK_SYNC_KEY, ack, generated_at)
    return _result(
        {
            "action": "policy_sync",
            "bundleHash": _optional_string(bundle.get("bundleHash")),
            "bundleVersion": _optional_string(bundle.get("bundleVersion")),
            "decisionMemoryAck": ack,
            "localRequestId": _optional_string(payload.get("localRequestId")),
            "status": str(ack["status"]),
        },
        generated_at=generated_at,
    )


def _local_policy_scope(scope: str | None) -> DecisionScope:
    """Map Cloud policy scopes onto the narrower local policy model."""
    if scope in {"workspace", "team", "policy", "machine", "project"}:
        return "workspace"
    if scope == "item":
        return "artifact"
    return "artifact"


def _is_decision_scope(value: object) -> TypeGuard[DecisionScope]:
    return isinstance(value, str) and value in DECISION_SCOPE_VALUES


def _payload_mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _stored_review_memory_policy_version(store: GuardStore) -> str | None:
    payload = store.get_sync_payload(_GUARD_REVIEW_MEMORY_VERSION_SYNC_KEY)
    if not isinstance(payload, dict):
        return None
    return _optional_string(payload.get("policyVersion"))


def _stored_review_memory_registry(store: GuardStore) -> dict[str, dict[str, object]]:
    payload = store.get_sync_payload(_GUARD_REVIEW_MEMORY_REGISTRY_SYNC_KEY)
    if not isinstance(payload, list):
        return {}
    registry: dict[str, dict[str, object]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        rule_id = _optional_string(item.get("ruleId"))
        decision = item.get("decision")
        if rule_id is None or not isinstance(decision, dict):
            continue
        registry[rule_id] = {"decision": dict(decision), "ruleId": rule_id}
    return registry


def _existing_non_review_remote_policies(store: GuardStore) -> list[PolicyDecision]:
    decisions: list[PolicyDecision] = []
    for item in store.list_policy_decisions():
        if item.get("source") in {"cloud-signed-memory"}:
            continue
        if item.get("source") != "policy-bundle":
            continue
        scope = _optional_string(item.get("scope"))
        action = _optional_string(item.get("action"))
        harness = _optional_string(item.get("harness"))
        if scope is None or action is None or harness is None:
            continue
        if not _is_decision_scope(scope) or not _is_guard_action(action):
            continue
        decisions.append(
            PolicyDecision(
                harness=harness,
                scope=scope,
                action=action,
                artifact_id=_optional_string(item.get("artifact_id")),
                artifact_hash=_optional_string(item.get("artifact_hash")),
                workspace=_optional_string(item.get("workspace")),
                publisher=_optional_string(item.get("publisher")),
                reason=_optional_string(item.get("reason")),
                owner=_optional_string(item.get("owner")),
                source=str(item.get("source") or "cloud-sync"),
                expires_at=_optional_string(item.get("expires_at")),
            )
        )
    return decisions


def _decision_from_registry_entry(entry: dict[str, object]) -> PolicyDecision:
    decision = entry.get("decision")
    if not isinstance(decision, dict):
        raise ValueError("invalid_decision_memory_registry")
    harness = _optional_string(decision.get("harness"))
    scope = _optional_string(decision.get("scope"))
    action = _optional_string(decision.get("action"))
    if harness is None or scope is None or action is None:
        raise ValueError("invalid_decision_memory_registry")
    if not _is_decision_scope(scope) or not _is_guard_action(action):
        raise ValueError("invalid_decision_memory_registry")
    return PolicyDecision(
        harness=harness,
        scope=scope,
        action=action,
        artifact_id=_optional_string(decision.get("artifact_id")),
        artifact_hash=_optional_string(decision.get("artifact_hash")),
        workspace=_optional_string(decision.get("workspace")),
        publisher=_optional_string(decision.get("publisher")),
        reason=_optional_string(decision.get("reason")),
        owner=_optional_string(decision.get("owner")),
        source=str(decision.get("source") or "cloud-signed-memory"),
        expires_at=_optional_string(decision.get("expires_at")),
    )


def _decision_from_memory_rule(
    *,
    bundle: dict[str, object],
    rule: dict[str, object],
) -> PolicyDecision:
    harness = _optional_string(rule.get("harnessId"))
    artifact_id = _optional_string(rule.get("artifactId"))
    action = _optional_string(rule.get("action"))
    scope_value = _optional_string(rule.get("scope"))
    if harness is None or artifact_id is None or action is None or scope_value is None:
        raise GuardReviewContractError("invalid_decision_memory_rule")
    if not _is_guard_action(action):
        raise GuardReviewContractError("invalid_decision_memory_rule")
    if action == "allow" and scope_value not in {"artifact", "workspace"}:
        raise GuardReviewContractError("decision_memory_allow_scope_unsupported")
    scope = _local_policy_scope(scope_value)
    target = rule.get("target")
    target_payload = target if isinstance(target, dict) else {}
    workspace_ids = target_payload.get("workspaceIds")
    workspace = _optional_string(bundle.get("workspaceId"))
    if scope == "workspace" and isinstance(workspace_ids, list):
        workspace = next(
            (candidate for candidate in (_optional_string(item) for item in workspace_ids) if candidate is not None),
            workspace,
        )
    return PolicyDecision(
        harness=harness,
        scope=scope,
        action=action,
        artifact_id=artifact_id,
        artifact_hash=_optional_string(rule.get("artifactHash")),
        workspace=workspace if scope == "workspace" else None,
        publisher=None,
        reason=_optional_string(rule.get("reason")) or "Guard Cloud signed decision memory sync",
        owner=None,
        source="cloud-signed-memory",
        expires_at=_optional_string(rule.get("expiresAt")),
    )


def _optional_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _result(data: dict[str, object], *, generated_at: str) -> dict[str, object]:
    return {"data": data, "generatedAt": generated_at}


__all__ = ["execute_legacy_policy_sync"]
