from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.managed_controls.fleet_contracts import (
    FLEET_CONTRACT_CAPABILITIES,
    FleetContractError,
    enabled_fleet_contract_capabilities,
    parse_fleet_contract,
    runtime_supports_fleet_contract,
    supports_fleet_extension_configuration,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATHS = (
    "contracts/managed-controls/v1/fleet-extension-configuration.fixtures.json",
    "contracts/managed-controls/v1/managed-control-assignment.fixtures.json",
    "contracts/managed-controls/v2/custom-extension-definition.fixtures.json",
    "contracts/managed-controls/v2/custom-extension-configuration.fixtures.json",
    "contracts/managed-controls/v2/catalog-semantic-fingerprints.fixtures.json",
)


def _fixture(relative_path: str) -> dict[str, object]:
    return cast(dict[str, object], json.loads((ROOT / relative_path).read_text(encoding="utf-8")))


def _apply_mutation(source: object, mutation: dict[str, object]) -> object:
    result = copy.deepcopy(source)
    path = cast(list[str | int], mutation.get("path", []))
    cursor = result
    for segment in path:
        cursor = cursor[segment]  # type: ignore[index]
    if "mutation" in mutation:
        cast(dict[str, object], cursor).update(cast(dict[str, object], mutation["mutation"]))
        return result
    if not path:
        raise AssertionError("Fixture replacement requires a path")
    parent = result
    for segment in path[:-1]:
        parent = parent[segment]  # type: ignore[index]
    parent[path[-1]] = mutation.get("value")  # type: ignore[index]
    return result


@pytest.mark.parametrize("relative_path", FIXTURE_PATHS)
def test_shared_fixture_canonical_bytes_and_digest(relative_path: str) -> None:
    fixture = _fixture(relative_path)
    parsed = parse_fleet_contract(fixture["valid"])
    assert parsed.canonical_json == fixture["canonicalJson"]
    assert parsed.digest == fixture["expectedDigest"]


@pytest.mark.parametrize("relative_path", FIXTURE_PATHS)
def test_shared_fixture_adversarial_mutations(relative_path: str) -> None:
    fixture = _fixture(relative_path)
    valid = fixture["valid"]
    mutations = cast(list[dict[str, object]], fixture["invalidMutations"])
    for mutation in mutations:
        with pytest.raises(FleetContractError) as captured:
            parse_fleet_contract(_apply_mutation(valid, mutation))
        assert captured.value.code == mutation["errorCode"], mutation["name"]


def test_runtime_requires_every_semantic_contract_family() -> None:
    assert supports_fleet_extension_configuration(FLEET_CONTRACT_CAPABILITIES)
    assert not supports_fleet_extension_configuration(FLEET_CONTRACT_CAPABILITIES[:-1])


def test_runtime_requires_exact_contract_capability() -> None:
    contract = parse_fleet_contract(_fixture(FIXTURE_PATHS[0])["valid"])
    assert runtime_supports_fleet_contract(contract, ("fleet-extension-configuration.v1",))
    assert not runtime_supports_fleet_contract(contract, ())


def test_experimental_capability_advertisement_is_explicit() -> None:
    assert enabled_fleet_contract_capabilities({}) == ()
    assert enabled_fleet_contract_capabilities(
        {
            "HOL_GUARD_FLEET_EXTENSION_CONFIGURATION_V1": "true",
            "HOL_GUARD_CUSTOM_EXTENSION_CONFIGURATION_V2": "1",
        }
    ) == (
        "fleet-extension-configuration.v1",
        "custom-extension-configuration.v2",
    )
