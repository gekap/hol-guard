from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from importlib.resources import files as resource_files
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.managed_controls.fleet_contracts import (
    ContractKind,
    FleetContractError,
    REQUIRED_FLEET_CAPABILITIES,
    apply_adversarial_fixture,
    canonical_fleet_contract_bytes,
    fleet_contract_digest,
    load_adversarial_fleet_fixtures,
    load_shared_fleet_fixtures,
    negotiate_fleet_capabilities,
    validate_fleet_contract,
    verify_packaged_contract_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = ROOT / "contracts/managed-controls/v2"
PACKAGE_ROOT = resource_files(
    "codex_plugin_scanner.guard.managed_controls.contracts.v2"
)
FIXTURES = load_shared_fleet_fixtures()
ADVERSARIAL = load_adversarial_fleet_fixtures()
KINDS: tuple[ContractKind, ...] = (
    "fleetExtensionConfiguration",
    "assignment",
    "customExtensionDefinition",
    "customExtensionConfiguration",
    "catalogSemantics",
)


@pytest.mark.parametrize("kind", KINDS)
def test_shared_positive_contracts_validate_and_match_frozen_digests(
    kind: ContractKind,
) -> None:
    value = FIXTURES[kind]

    normalized = validate_fleet_contract(kind, value)

    assert normalized["schemaVersion"] == cast(dict[str, object], value)["schemaVersion"]
    assert canonical_fleet_contract_bytes(kind, value) == canonical_fleet_contract_bytes(
        kind, normalized
    )
    assert fleet_contract_digest(kind, value) == cast(dict[str, str], FIXTURES["digests"])[kind]


@pytest.mark.parametrize(
    "case",
    cast(list[dict[str, object]], ADVERSARIAL["cases"]),
    ids=lambda case: cast(dict[str, object], case)["id"],
)
def test_shared_adversarial_contracts_fail_with_stable_reason(
    case: dict[str, object],
) -> None:
    kind = cast(ContractKind, case["contract"])
    candidate = apply_adversarial_fixture(FIXTURES[kind], case)

    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract(kind, candidate)

    assert caught.value.code == case["expectedError"]
    assert "/Users/" not in str(caught.value)
    assert "token secret" not in str(caught.value).lower()


def test_manifest_pins_every_shared_root_and_packaged_resource_byte() -> None:
    manifest = json.loads((CONTRACT_ROOT / "manifest.json").read_text(encoding="utf-8"))
    declared = [entry["path"] for entry in manifest["files"]]
    actual = sorted(
        path.name
        for path in CONTRACT_ROOT.iterdir()
        if path.is_file() and path.suffix == ".json" and path.name != "manifest.json"
    )
    assert sorted(declared) == actual
    assert len(declared) == len(set(declared))
    assert verify_packaged_contract_manifest() == tuple(declared)

    for entry in manifest["files"]:
        root_bytes = (CONTRACT_ROOT / entry["path"]).read_bytes()
        package_bytes = PACKAGE_ROOT.joinpath(entry["path"]).read_bytes()
        assert root_bytes == package_bytes
        assert len(root_bytes) == entry["bytes"]
        assert hashlib.sha256(root_bytes).hexdigest() == entry["sha256"]


def test_canonicalization_is_independent_of_object_and_collection_order() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["customExtensionDefinition"]))
    commands = cast(list[dict[str, object]], value["commands"])
    variants = cast(list[dict[str, object]], value["variants"])
    commands.reverse()
    variants.reverse()
    cast(list[str], variants[0]["platforms"]).reverse()
    reordered = {key: value[key] for key in reversed(tuple(value))}

    assert canonical_fleet_contract_bytes(
        "customExtensionDefinition", reordered
    ) == canonical_fleet_contract_bytes(
        "customExtensionDefinition", FIXTURES["customExtensionDefinition"]
    )


def test_capability_negotiation_excludes_semantically_incomplete_readers() -> None:
    supported, missing = negotiate_fleet_capabilities(sorted(REQUIRED_FLEET_CAPABILITIES))
    assert supported is True
    assert missing == ()

    supported, missing = negotiate_fleet_capabilities(
        sorted(
            REQUIRED_FLEET_CAPABILITIES
            - {"guard.managed-controls-composite-apply.v2"}
        )
    )
    assert supported is False
    assert missing == ("guard.managed-controls-composite-apply.v2",)


@pytest.mark.parametrize("advertised", [["valid.capability", ["not-a-string"]], {"bad": True}, "bad"])
def test_malformed_capabilities_are_bounded(advertised: object) -> None:
    with pytest.raises(FleetContractError) as caught:
        negotiate_fleet_capabilities(advertised)
    assert caught.value.code == "fec_invalid_identifier"


def test_managed_restrictive_authority_cannot_enable_or_permit() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    entries = cast(list[dict[str, object]], value["entries"])
    entries[0]["availability"] = "enabled"

    with pytest.raises(FleetContractError, match="cannot weaken") as caught:
        validate_fleet_contract("fleetExtensionConfiguration", value)

    assert caught.value.code == "fec_managed_weaken_forbidden"


def test_managed_restrictive_authority_cannot_target_custom_extensions() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    entries = cast(list[dict[str, object]], value["entries"])
    entries[0] = {
        "authorityMode": "managed-restrictive",
        "availability": "disabled",
        "contextualOutcome": "block",
        "entryId": "entry.custom.block",
        "source": "explicit",
        "target": {
            "definitionId": "ced_01j5example00000001",
            "kind": "custom-extension",
        },
    }

    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", value)

    assert caught.value.code == "fec_managed_weaken_forbidden"


def test_utf8_limits_are_bytes_not_python_characters() -> None:
    at_limit = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    at_limit["description"] = "é" * 512
    validate_fleet_contract("fleetExtensionConfiguration", at_limit)

    over_limit = deepcopy(at_limit)
    over_limit["description"] = "é" * 513
    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", over_limit)
    assert caught.value.code == "fec_limit_exceeded"


def test_nested_unknown_fields_are_classified_without_echoing_values() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    entries = cast(list[dict[str, object]], value["entries"])
    target = cast(dict[str, object], entries[0]["target"])
    target["sourcePath"] = "/Users/private/secret-tool"

    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", value)

    assert caught.value.code == "fec_unknown_field"
    assert "secret-tool" not in str(caught.value)


def test_noncanonical_timestamp_has_its_stable_reason() -> None:
    value = deepcopy(cast(dict[str, object], FIXTURES["fleetExtensionConfiguration"]))
    value["createdAt"] = "2026-08-27T12:00:00+00:00"
    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("fleetExtensionConfiguration", value)
    assert caught.value.code == "fec_invalid_timestamp"
