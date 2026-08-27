from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls.fleet_contracts import (
    FleetContractError,
    REQUIRED_FLEET_CAPABILITIES,
    apply_adversarial_fixture,
    canonical_fleet_contract_bytes,
    fleet_contract_digest,
    negotiate_fleet_capabilities,
    validate_fleet_contract,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = json.loads((ROOT / "contracts/managed-controls/v2/fixtures.json").read_text())
ADVERSARIAL = json.loads((ROOT / "contracts/managed-controls/v2/adversarial-fixtures.json").read_text())
KINDS = (
    "fleetExtensionConfiguration",
    "assignment",
    "customExtensionDefinition",
    "customExtensionConfiguration",
    "catalogSemantics",
)


@pytest.mark.parametrize("kind", KINDS)
def test_shared_positive_contracts_validate_and_match_frozen_digests(kind: str) -> None:
    value = FIXTURES[kind]

    normalized = validate_fleet_contract(kind, value)

    assert normalized["schemaVersion"] == value["schemaVersion"]
    assert canonical_fleet_contract_bytes(kind, value) == canonical_fleet_contract_bytes(kind, normalized)
    assert fleet_contract_digest(kind, value) == FIXTURES["digests"][kind]


@pytest.mark.parametrize("case", ADVERSARIAL["cases"], ids=lambda case: case["id"])
def test_shared_adversarial_contracts_fail_with_stable_reason(case: dict[str, object]) -> None:
    kind = case["contract"]
    candidate = apply_adversarial_fixture(FIXTURES[kind], case)

    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract(kind, candidate)

    assert caught.value.code == case["expectedError"]
    assert "/Users/" not in str(caught.value)
    assert "token" not in str(caught.value).lower()


def test_canonicalization_is_independent_of_object_and_collection_order() -> None:
    value = deepcopy(FIXTURES["customExtensionDefinition"])
    value["commands"] = list(reversed(value["commands"]))
    value["variants"] = list(reversed(value["variants"]))
    value["variants"][0]["platforms"] = list(reversed(value["variants"][0]["platforms"]))
    reordered = {key: value[key] for key in reversed(tuple(value))}

    assert canonical_fleet_contract_bytes("customExtensionDefinition", reordered) == canonical_fleet_contract_bytes(
        "customExtensionDefinition", FIXTURES["customExtensionDefinition"]
    )


def test_capability_negotiation_excludes_semantically_incomplete_readers() -> None:
    supported, missing = negotiate_fleet_capabilities(sorted(REQUIRED_FLEET_CAPABILITIES))
    assert supported is True
    assert missing == ()

    supported, missing = negotiate_fleet_capabilities(
        sorted(REQUIRED_FLEET_CAPABILITIES - {"guard.managed-controls-composite-apply.v2"})
    )
    assert supported is False
    assert missing == ("guard.managed-controls-composite-apply.v2",)


def test_managed_restrictive_authority_cannot_enable_or_permit() -> None:
    value = deepcopy(FIXTURES["fleetExtensionConfiguration"])
    value["entries"][0]["availability"] = "enabled"

    with pytest.raises(FleetContractError, match="cannot weaken") as caught:
        validate_fleet_contract("fleetExtensionConfiguration", value)

    assert caught.value.code == "fec_managed_weaken_forbidden"


def test_unknown_private_fields_fail_closed_without_echoing_values() -> None:
    value = deepcopy(FIXTURES["customExtensionDefinition"])
    value["sourcePath"] = "/Users/private/secret-tool"

    with pytest.raises(FleetContractError) as caught:
        validate_fleet_contract("customExtensionDefinition", value)

    assert caught.value.code == "fec_unknown_field"
    assert "secret-tool" not in str(caught.value)
