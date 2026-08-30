from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.fleet_assignment import (
    CustomBinding,
    DeviceCatalogSnapshot,
    FleetAssignmentError,
    assignment_intent_digest,
    compile_projection,
    parse_assignment_intent,
    parse_target,
    preview_assignment,
)

_REQUIRED = (
    "guard.fleet-extension-configuration.v1",
    "guard.managed-control-assignment.v1",
    "guard.custom-extension-definition.v2",
    "guard.custom-extension-configuration.v2",
    "guard.catalog-semantic-fingerprint.v2",
    "guard.managed-controls-composite-apply.v2",
)


def _intent(**overrides: object):
    value: dict[str, object] = {
        "schemaVersion": "guard.managed-control-assignment.v1",
        "workspaceId": "workspace-a",
        "assignmentId": "assignment-a",
        "configurationId": "configuration-a",
        "configurationVersionId": "configuration-version-a",
        "configurationDigest": f"sha256:{'1' * 64}",
        "revision": 1,
        "selector": {"allDevices": True},
        "excludedDeviceIds": [],
        "continuousEnrollment": True,
        "createdAt": "2026-08-30T12:00:00.000Z",
    }
    value.update(overrides)
    return parse_assignment_intent(value)


def _device(**overrides: object) -> DeviceCatalogSnapshot:
    value: dict[str, object] = {
        "workspace_id": "workspace-a",
        "device_id": "device-a",
        "labels": {"environment": "production"},
        "capabilities": _REQUIRED,
        "catalog_digest": f"sha256:{'2' * 64}",
        "catalog_semantic_digest": f"sha256:{'3' * 64}",
        "supported_extension_ids": ("command.shell",),
        "custom_extension_bindings": (
            CustomBinding(
                custom_extension_id="custom-a",
                definition_version_id="definition-v1",
                variant_id="variant-linux",
                semantic_digest=f"sha256:{'4' * 64}",
            ),
        ),
    }
    value.update(overrides)
    return DeviceCatalogSnapshot(**value)  # type: ignore[arg-type]


def _targets():
    return (
        parse_target(
            {
                "targetId": "target-shell",
                "kind": "extension",
                "extensionId": "command.shell",
                "semanticDigest": f"sha256:{'4' * 64}",
                "outcome": "deny",
            }
        ),
        parse_target(
            {
                "targetId": "target-custom",
                "kind": "customExtension",
                "customExtensionId": "custom-a",
                "definitionVersionId": "definition-v1",
                "variantId": "variant-linux",
                "semanticDigest": f"sha256:{'4' * 64}",
                "outcome": "review",
                "settingsDigest": f"sha256:{'5' * 64}",
            }
        ),
    )


def test_selector_is_exact_and_non_empty() -> None:
    with pytest.raises(FleetAssignmentError, match="Exactly one") as captured:
        _intent(selector={})
    assert captured.value.code == "fec_assignment_ambiguous_selector"

    with pytest.raises(FleetAssignmentError) as captured:
        _intent(selector={"allDevices": True, "deviceIds": ["device-a"]})
    assert captured.value.code == "fec_assignment_ambiguous_selector"

    with pytest.raises(FleetAssignmentError) as captured:
        _intent(selector={"deviceIds": []})
    assert captured.value.code == "fec_assignment_empty"


def test_preview_excludes_unsupported_devices_without_downgrade() -> None:
    preview = preview_assignment(
        _intent(),
        (
            _device(capabilities=_REQUIRED[:-1]),
            _device(device_id="device-b", supported_extension_ids=()),
        ),
        _targets(),
    )
    assert preview.eligible_device_ids == ()
    assert [item.code for item in preview.exclusions] == [
        "capability_missing",
        "semantic_mismatch",
    ]


def test_preview_requires_exact_custom_extension_binding() -> None:
    preview = preview_assignment(
        _intent(),
        (_device(custom_extension_bindings=()),),
        _targets(),
    )
    assert preview.exclusions[0].code == "custom_binding_missing"


def test_workspace_substitution_fails_closed() -> None:
    with pytest.raises(FleetAssignmentError) as captured:
        preview_assignment(
            _intent(),
            (_device(workspace_id="workspace-b"),),
            _targets(),
        )
    assert captured.value.code == "fec_assignment_tenant_mismatch"


def test_projection_is_exact_device_bound_and_deterministic() -> None:
    intent = _intent()
    device = _device()
    targets = _targets()
    preview = preview_assignment(intent, (device,), targets)
    projection = compile_projection(
        intent,
        preview,
        device,
        targets,
        compiled_at="2026-08-30T12:01:00.000Z",
    )
    assert projection.device_id == "device-a"
    assert [target.target_id for target in projection.targets] == [
        "target-custom",
        "target-shell",
    ]
    assert projection.projection_digest.startswith("sha256:")


def test_stale_or_excluded_projection_is_rejected() -> None:
    first = _intent()
    device = _device()
    preview = preview_assignment(first, (device,), _targets())
    with pytest.raises(FleetAssignmentError) as captured:
        compile_projection(
            _intent(revision=2),
            preview,
            device,
            _targets(),
            compiled_at="2026-08-30T12:01:00.000Z",
        )
    assert captured.value.code == "fec_assignment_stale_revision"

    with pytest.raises(FleetAssignmentError) as captured:
        compile_projection(
            first,
            preview,
            _device(device_id="device-z"),
            _targets(),
            compiled_at="2026-08-30T12:01:00.000Z",
        )
    assert captured.value.code == "fec_assignment_device_excluded"


def test_assignment_digest_is_order_independent() -> None:
    left = assignment_intent_digest(
        _intent(selector={"deviceIds": ["device-b", "device-a"]})
    )
    right = assignment_intent_digest(
        _intent(selector={"deviceIds": ["device-a", "device-b"]})
    )
    assert left == right


def test_errors_do_not_echo_private_values() -> None:
    with pytest.raises(FleetAssignmentError) as captured:
        parse_assignment_intent(
            {
                "schemaVersion": "guard.managed-control-assignment.v1",
                "workspaceId": "workspace-a",
                "assignmentId": "assignment-a",
                "configurationId": "configuration-a",
                "configurationVersionId": "configuration-version-a",
                "configurationDigest": f"sha256:{'1' * 64}",
                "revision": 1,
                "selector": {"allDevices": True},
                "excludedDeviceIds": [],
                "continuousEnrollment": True,
                "createdAt": "2026-08-30T12:00:00.000Z",
                "rawCommand": "token secret /Users/example/private",
            }
        )
    assert captured.value.code == "fec_unknown_field"
    assert "token secret" not in str(captured.value).lower()
    assert "/users/" not in str(captured.value).lower()
