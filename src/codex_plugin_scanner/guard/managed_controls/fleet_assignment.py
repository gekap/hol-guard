from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final, Mapping, Sequence

_OPAQUE_ID: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST: Final[re.Pattern[str]] = re.compile(r"^sha256:[0-9a-f]{64}$")
_REQUIRED_CAPABILITIES: Final[tuple[str, ...]] = (
    "guard.fleet-extension-configuration.v1",
    "guard.managed-control-assignment.v1",
    "guard.custom-extension-definition.v2",
    "guard.custom-extension-configuration.v2",
    "guard.catalog-semantic-fingerprint.v2",
    "guard.managed-controls-composite-apply.v2",
)
_MAX_DEVICES: Final[int] = 10_000
_MAX_LABELS: Final[int] = 32


class FleetAssignmentError(ValueError):
    """Bounded, privacy-safe Fleet Assignment validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class FleetAssignmentIntent:
    workspace_id: str
    assignment_id: str
    configuration_id: str
    configuration_version_id: str
    configuration_digest: str
    revision: int
    selector: Mapping[str, Any]
    excluded_device_ids: tuple[str, ...]
    continuous_enrollment: bool
    created_at: str


@dataclass(frozen=True, slots=True)
class FleetTarget:
    target_id: str
    kind: str
    semantic_digest: str
    outcome: str
    extension_id: str | None = None
    custom_extension_id: str | None = None
    definition_version_id: str | None = None
    variant_id: str | None = None
    settings_digest: str | None = None


@dataclass(frozen=True, slots=True)
class CustomBinding:
    custom_extension_id: str
    definition_version_id: str
    variant_id: str
    semantic_digest: str


@dataclass(frozen=True, slots=True)
class DeviceCatalogSnapshot:
    workspace_id: str
    device_id: str
    labels: Mapping[str, str]
    capabilities: tuple[str, ...]
    catalog_digest: str
    catalog_semantic_digest: str
    supported_extension_ids: tuple[str, ...]
    custom_extension_bindings: tuple[CustomBinding, ...]


@dataclass(frozen=True, slots=True)
class AssignmentExclusion:
    device_id: str
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class AssignmentPreview:
    workspace_id: str
    assignment_id: str
    revision: int
    eligible_device_ids: tuple[str, ...]
    exclusions: tuple[AssignmentExclusion, ...]
    selector_digest: str
    preview_digest: str


@dataclass(frozen=True, slots=True)
class DeviceProjection:
    workspace_id: str
    assignment_id: str
    assignment_revision: int
    configuration_id: str
    configuration_version_id: str
    configuration_digest: str
    device_id: str
    catalog_digest: str
    catalog_semantic_digest: str
    targets: tuple[FleetTarget, ...]
    compiled_at: str
    projection_digest: str


def _assert_exact_keys(value: Mapping[str, Any], expected: set[str], *, label: str) -> None:
    unknown = set(value) - expected
    if unknown:
        raise FleetAssignmentError("fec_unknown_field", f"{label} contains an unknown field.")


def _assert_id(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _OPAQUE_ID.fullmatch(value) is None:
        raise FleetAssignmentError("fec_assignment_invalid", f"{label} is invalid.")
    return value


def _assert_digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise FleetAssignmentError("fec_assignment_invalid", f"{label} is invalid.")
    return value


def _assert_timestamp(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise FleetAssignmentError("fec_assignment_invalid", f"{label} is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FleetAssignmentError("fec_assignment_invalid", f"{label} is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise FleetAssignmentError("fec_assignment_invalid", f"{label} is invalid.")
    normalized = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if normalized != value:
        raise FleetAssignmentError("fec_assignment_invalid", f"{label} is invalid.")
    return value


def _unique_ids(values: Any, *, label: str, limit: int = _MAX_DEVICES) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        raise FleetAssignmentError("fec_assignment_invalid", f"{label} is invalid.")
    if len(values) > limit:
        raise FleetAssignmentError("fec_assignment_limit_exceeded", f"{label} exceeds its item limit.")
    output = tuple(sorted(_assert_id(value, label=label) for value in values))
    if len(output) != len(set(output)):
        raise FleetAssignmentError("fec_assignment_invalid", f"{label} contains duplicates.")
    return output


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FleetAssignmentError("fec_assignment_invalid", "Value is not canonical JSON.") from exc


def _digest(domain: str, value: Any) -> str:
    hasher = hashlib.sha256()
    hasher.update(domain.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(_canonical_json(value))
    return f"sha256:{hasher.hexdigest()}"


def _mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FleetAssignmentError("fec_assignment_invalid", f"{label} is invalid.")
    return value


def parse_assignment_intent(value: Mapping[str, Any]) -> FleetAssignmentIntent:
    _assert_exact_keys(
        value,
        {
            "schemaVersion",
            "workspaceId",
            "assignmentId",
            "configurationId",
            "configurationVersionId",
            "configurationDigest",
            "revision",
            "selector",
            "excludedDeviceIds",
            "continuousEnrollment",
            "createdAt",
        },
        label="assignment",
    )
    if value.get("schemaVersion") != "guard.managed-control-assignment.v1":
        raise FleetAssignmentError("fec_assignment_invalid", "schemaVersion is invalid.")
    revision = value.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise FleetAssignmentError("fec_assignment_invalid", "revision is invalid.")
    continuous_enrollment = value.get("continuousEnrollment")
    if not isinstance(continuous_enrollment, bool):
        raise FleetAssignmentError("fec_assignment_invalid", "continuousEnrollment is invalid.")

    selector = _mapping(value.get("selector"), label="selector")
    _assert_exact_keys(selector, {"allDevices", "deviceIds", "matchLabels"}, label="selector")
    selected = sum(
        (
            selector.get("allDevices") is True,
            "deviceIds" in selector,
            "matchLabels" in selector,
        )
    )
    if selected != 1:
        raise FleetAssignmentError(
            "fec_assignment_ambiguous_selector",
            "Exactly one assignment selector is required.",
        )
    normalized_selector: dict[str, Any]
    if selector.get("allDevices") is True:
        normalized_selector = {"allDevices": True}
    elif "deviceIds" in selector:
        device_ids = _unique_ids(selector.get("deviceIds"), label="selector.deviceIds")
        if not device_ids:
            raise FleetAssignmentError("fec_assignment_empty", "Explicit selection is empty.")
        normalized_selector = {"deviceIds": device_ids}
    else:
        labels = _mapping(selector.get("matchLabels"), label="selector.matchLabels")
        if not labels or len(labels) > _MAX_LABELS:
            code = "fec_assignment_empty" if not labels else "fec_assignment_limit_exceeded"
            raise FleetAssignmentError(code, "Label selection is invalid.")
        normalized_labels: dict[str, str] = {}
        for key, raw in sorted(labels.items()):
            if not isinstance(key, str) or not isinstance(raw, str) or not key or not raw:
                raise FleetAssignmentError("fec_assignment_invalid", "Selector labels are invalid.")
            if len(key.encode("utf-8")) > 64 or len(raw.encode("utf-8")) > 128:
                raise FleetAssignmentError("fec_assignment_limit_exceeded", "Selector labels are too large.")
            normalized_labels[key] = raw
        normalized_selector = {"matchLabels": normalized_labels}

    exclusions = _unique_ids(value.get("excludedDeviceIds", ()), label="excludedDeviceIds")
    if "deviceIds" in normalized_selector and set(exclusions) & set(normalized_selector["deviceIds"]):
        raise FleetAssignmentError(
            "fec_assignment_invalid",
            "A device cannot be both explicitly selected and excluded.",
        )
    return FleetAssignmentIntent(
        workspace_id=_assert_id(value.get("workspaceId"), label="workspaceId"),
        assignment_id=_assert_id(value.get("assignmentId"), label="assignmentId"),
        configuration_id=_assert_id(value.get("configurationId"), label="configurationId"),
        configuration_version_id=_assert_id(
            value.get("configurationVersionId"),
            label="configurationVersionId",
        ),
        configuration_digest=_assert_digest(
            value.get("configurationDigest"),
            label="configurationDigest",
        ),
        revision=revision,
        selector=normalized_selector,
        excluded_device_ids=exclusions,
        continuous_enrollment=continuous_enrollment,
        created_at=_assert_timestamp(value.get("createdAt"), label="createdAt"),
    )


def parse_target(value: Mapping[str, Any]) -> FleetTarget:
    _assert_exact_keys(
        value,
        {
            "targetId",
            "kind",
            "extensionId",
            "customExtensionId",
            "definitionVersionId",
            "variantId",
            "semanticDigest",
            "outcome",
            "settingsDigest",
        },
        label="target",
    )
    kind = value.get("kind")
    if kind not in {"extension", "customExtension"}:
        raise FleetAssignmentError("fec_assignment_invalid", "target kind is invalid.")
    outcome = value.get("outcome")
    if outcome not in {"allow", "deny", "review"}:
        raise FleetAssignmentError("fec_assignment_invalid", "target outcome is invalid.")
    extension_id = value.get("extensionId")
    custom_extension_id = value.get("customExtensionId")
    definition_version_id = value.get("definitionVersionId")
    variant_id = value.get("variantId")
    if kind == "extension":
        extension_id = _assert_id(extension_id, label="extensionId")
        if any(candidate is not None for candidate in (custom_extension_id, definition_version_id, variant_id)):
            raise FleetAssignmentError("fec_assignment_invalid", "Extension target identity is ambiguous.")
    else:
        custom_extension_id = _assert_id(custom_extension_id, label="customExtensionId")
        definition_version_id = _assert_id(definition_version_id, label="definitionVersionId")
        variant_id = _assert_id(variant_id, label="variantId")
        if extension_id is not None:
            raise FleetAssignmentError("fec_assignment_invalid", "Custom target identity is ambiguous.")
    settings_digest = value.get("settingsDigest")
    if settings_digest is not None:
        settings_digest = _assert_digest(settings_digest, label="settingsDigest")
    return FleetTarget(
        target_id=_assert_id(value.get("targetId"), label="targetId"),
        kind=kind,
        extension_id=extension_id,
        custom_extension_id=custom_extension_id,
        definition_version_id=definition_version_id,
        variant_id=variant_id,
        semantic_digest=_assert_digest(value.get("semanticDigest"), label="semanticDigest"),
        outcome=outcome,
        settings_digest=settings_digest,
    )


def _selector_matches(selector: Mapping[str, Any], device: DeviceCatalogSnapshot) -> bool:
    if selector.get("allDevices") is True:
        return True
    if "deviceIds" in selector:
        return device.device_id in selector["deviceIds"]
    labels = selector.get("matchLabels", {})
    return all(device.labels.get(key) == value for key, value in labels.items())


def _validate_device(
    intent: FleetAssignmentIntent,
    device: DeviceCatalogSnapshot,
    targets: Sequence[FleetTarget],
    expected_catalog_semantic_digest: str | None,
) -> AssignmentExclusion | None:
    if device.workspace_id != intent.workspace_id:
        raise FleetAssignmentError(
            "fec_assignment_tenant_mismatch",
            "Device workspace binding does not match the assignment.",
        )
    missing = [capability for capability in _REQUIRED_CAPABILITIES if capability not in device.capabilities]
    if missing:
        return AssignmentExclusion(
            device.device_id,
            "capability_missing",
            f"Missing {len(missing)} required reader capabilities.",
        )
    if expected_catalog_semantic_digest is not None and not hmac.compare_digest(
        device.catalog_semantic_digest,
        expected_catalog_semantic_digest,
    ):
        return AssignmentExclusion(
            device.device_id,
            "catalog_mismatch",
            "The device catalog semantic fingerprint does not match the approved intent.",
        )
    for target in targets:
        if target.kind == "extension":
            if target.extension_id not in device.supported_extension_ids:
                return AssignmentExclusion(
                    device.device_id,
                    "semantic_mismatch",
                    "A required built-in Extension is not supported by this device.",
                )
            continue
        binding = next(
            (
                candidate
                for candidate in device.custom_extension_bindings
                if candidate.custom_extension_id == target.custom_extension_id
                and candidate.definition_version_id == target.definition_version_id
                and candidate.variant_id == target.variant_id
            ),
            None,
        )
        if binding is None:
            return AssignmentExclusion(
                device.device_id,
                "custom_binding_missing",
                "The exact reviewed Custom Extension variant is not bound on this device.",
            )
        if not hmac.compare_digest(binding.semantic_digest, target.semantic_digest):
            return AssignmentExclusion(
                device.device_id,
                "semantic_mismatch",
                "The Custom Extension semantic fingerprint has changed.",
            )
    return None


def preview_assignment(
    intent: FleetAssignmentIntent,
    devices: Sequence[DeviceCatalogSnapshot],
    targets: Sequence[FleetTarget],
    *,
    expected_catalog_semantic_digest: str | None = None,
) -> AssignmentPreview:
    seen: set[str] = set()
    eligible: list[str] = []
    exclusions: list[AssignmentExclusion] = []
    explicit_exclusions = set(intent.excluded_device_ids)
    for device in sorted(devices, key=lambda candidate: candidate.device_id):
        _assert_id(device.device_id, label="deviceId")
        if device.device_id in seen:
            raise FleetAssignmentError("fec_assignment_invalid", "Device inventory contains duplicates.")
        seen.add(device.device_id)
        if not _selector_matches(intent.selector, device):
            continue
        if device.device_id in explicit_exclusions:
            exclusions.append(
                AssignmentExclusion(
                    device.device_id,
                    "explicit_exclusion",
                    "The device is explicitly excluded from this assignment.",
                )
            )
            continue
        exclusion = _validate_device(
            intent,
            device,
            targets,
            expected_catalog_semantic_digest,
        )
        if exclusion is None:
            eligible.append(device.device_id)
        else:
            exclusions.append(exclusion)
    selector_digest = _digest(
        "guard.fleet-assignment-selector.v1",
        {
            "selector": intent.selector,
            "excludedDeviceIds": intent.excluded_device_ids,
            "continuousEnrollment": intent.continuous_enrollment,
        },
    )
    body = {
        "workspaceId": intent.workspace_id,
        "assignmentId": intent.assignment_id,
        "revision": intent.revision,
        "eligibleDeviceIds": eligible,
        "exclusions": [
            {"deviceId": item.device_id, "code": item.code, "detail": item.detail}
            for item in exclusions
        ],
        "selectorDigest": selector_digest,
    }
    return AssignmentPreview(
        workspace_id=intent.workspace_id,
        assignment_id=intent.assignment_id,
        revision=intent.revision,
        eligible_device_ids=tuple(eligible),
        exclusions=tuple(exclusions),
        selector_digest=selector_digest,
        preview_digest=_digest("guard.fleet-assignment-preview.v1", body),
    )


def compile_projection(
    intent: FleetAssignmentIntent,
    preview: AssignmentPreview,
    device: DeviceCatalogSnapshot,
    targets: Sequence[FleetTarget],
    *,
    compiled_at: str,
) -> DeviceProjection:
    _assert_timestamp(compiled_at, label="compiledAt")
    if preview.workspace_id != intent.workspace_id or preview.assignment_id != intent.assignment_id:
        raise FleetAssignmentError(
            "fec_assignment_tenant_mismatch",
            "Preview binding does not match the assignment.",
        )
    if preview.revision != intent.revision:
        raise FleetAssignmentError(
            "fec_assignment_stale_revision",
            "Preview revision does not match the assignment.",
        )
    if device.device_id not in preview.eligible_device_ids:
        raise FleetAssignmentError(
            "fec_assignment_device_excluded",
            "The device was not admitted by the assignment preview.",
        )
    ordered_targets = tuple(sorted(targets, key=lambda target: target.target_id))
    target_payload = [
        {
            "targetId": target.target_id,
            "kind": target.kind,
            "extensionId": target.extension_id,
            "customExtensionId": target.custom_extension_id,
            "definitionVersionId": target.definition_version_id,
            "variantId": target.variant_id,
            "semanticDigest": target.semantic_digest,
            "outcome": target.outcome,
            "settingsDigest": target.settings_digest,
        }
        for target in ordered_targets
    ]
    body = {
        "schemaVersion": "guard.fleet-extension-projection.v1",
        "workspaceId": intent.workspace_id,
        "assignmentId": intent.assignment_id,
        "assignmentRevision": intent.revision,
        "configurationId": intent.configuration_id,
        "configurationVersionId": intent.configuration_version_id,
        "configurationDigest": intent.configuration_digest,
        "deviceId": device.device_id,
        "catalogDigest": device.catalog_digest,
        "catalogSemanticDigest": device.catalog_semantic_digest,
        "targets": target_payload,
        "compiledAt": compiled_at,
    }
    return DeviceProjection(
        workspace_id=intent.workspace_id,
        assignment_id=intent.assignment_id,
        assignment_revision=intent.revision,
        configuration_id=intent.configuration_id,
        configuration_version_id=intent.configuration_version_id,
        configuration_digest=intent.configuration_digest,
        device_id=device.device_id,
        catalog_digest=device.catalog_digest,
        catalog_semantic_digest=device.catalog_semantic_digest,
        targets=ordered_targets,
        compiled_at=compiled_at,
        projection_digest=_digest("guard.fleet-extension-projection.v1", body),
    )


def assignment_intent_digest(intent: FleetAssignmentIntent) -> str:
    return _digest(
        "guard.managed-control-assignment.v1",
        {
            "schemaVersion": "guard.managed-control-assignment.v1",
            "workspaceId": intent.workspace_id,
            "assignmentId": intent.assignment_id,
            "configurationId": intent.configuration_id,
            "configurationVersionId": intent.configuration_version_id,
            "configurationDigest": intent.configuration_digest,
            "revision": intent.revision,
            "selector": intent.selector,
            "excludedDeviceIds": intent.excluded_device_ids,
            "continuousEnrollment": intent.continuous_enrollment,
            "createdAt": intent.created_at,
        },
    )
