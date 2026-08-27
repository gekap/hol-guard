"""Strict shared contracts for fleet Extension configuration and assignment."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Final, Literal, TypeAlias, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

ContractKind: TypeAlias = Literal[
    "fleetExtensionConfiguration",
    "assignment",
    "customExtensionDefinition",
    "customExtensionConfiguration",
    "catalogSemantics",
]

CONTRACT_SCHEMAS: Final[dict[ContractKind, str]] = {
    "fleetExtensionConfiguration": "guard.fleet-extension-configuration.v1",
    "assignment": "guard.managed-control-assignment.v1",
    "customExtensionDefinition": "guard.custom-extension-definition.v2",
    "customExtensionConfiguration": "guard.custom-extension-configuration.v2",
    "catalogSemantics": "guard.catalog-semantic-fingerprint.v2",
}
CONTRACT_DOMAINS: Final[dict[ContractKind, bytes]] = {
    kind: f"hol.guard.{schema.removeprefix('guard.')}\0".encode()
    for kind, schema in CONTRACT_SCHEMAS.items()
}
REQUIRED_FLEET_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        *CONTRACT_SCHEMAS.values(),
        "guard.managed-controls-composite-apply.v2",
        "guard.managed-controls-signed-delivery.v2",
    }
)
_SCHEMA_FILES: Final[dict[ContractKind, str]] = {
    "fleetExtensionConfiguration": "fleet-extension-configuration.schema.json",
    "assignment": "managed-control-assignment.schema.json",
    "customExtensionDefinition": "custom-extension-definition.schema.json",
    "customExtensionConfiguration": "custom-extension-configuration.schema.json",
    "catalogSemantics": "catalog-semantic-fingerprint.schema.json",
}
_ROOT = Path(__file__).resolve().parents[4]
_CONTRACT_ROOT = _ROOT / "contracts/managed-controls/v2"
_CAPABILITY = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_MAX_PAYLOAD_BYTES = 524_288


class FleetContractError(ValueError):
    """Stable, bounded rejection that never contains private payload values."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message[:512])
        self.code = code


_MESSAGES: Final[dict[str, str]] = {
    "fec_invalid_json": "The fleet configuration payload is not valid JSON.",
    "fec_unknown_field": "The fleet configuration contains an unsupported field.",
    "fec_missing_field": "The fleet configuration is missing a required field.",
    "fec_limit_exceeded": "The fleet configuration exceeds a supported limit.",
    "fec_invalid_identifier": "A fleet configuration identifier is invalid.",
    "fec_duplicate_entry": "The fleet configuration contains a duplicate logical entry.",
    "fec_conflicting_entry": "The fleet configuration contains conflicting authority.",
    "fec_managed_weaken_forbidden": "Managed restrictive authority cannot weaken protection.",
    "fec_unsupported_capability": "The device does not support required fleet configuration semantics.",
    "fec_assignment_empty": "The managed assignment selector has no eligible targets.",
}


def _fail(code: str) -> None:
    raise FleetContractError(code, _MESSAGES.get(code, "The fleet configuration is invalid."))


def _load_schema(kind: ContractKind) -> dict[str, object]:
    return cast(dict[str, object], json.loads((_CONTRACT_ROOT / _SCHEMA_FILES[kind]).read_text()))


def _schema_error(error: ValidationError) -> str:
    if error.validator == "additionalProperties":
        return "fec_unknown_field"
    if error.validator == "required":
        return "fec_missing_field"
    if error.validator in {"maxItems", "minItems", "maxLength", "minLength", "maximum", "minimum"}:
        return "fec_limit_exceeded"
    if error.validator in {"pattern", "format"}:
        return "fec_invalid_identifier"
    if error.validator == "const" and list(error.absolute_path) == ["schemaVersion"]:
        return "fec_unsupported_capability"
    return "fec_invalid_json"


def _target_key(target: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        cast(str, target["kind"]),
        cast(str, target.get("extensionId") or target.get("definitionId") or ""),
        cast(str, target.get("permissionId") or target.get("commandId") or ""),
    )


def _unique(values: Sequence[object]) -> None:
    encoded = [json.dumps(value, sort_keys=True, separators=(",", ":")) for value in values]
    if len(encoded) != len(set(encoded)):
        _fail("fec_duplicate_entry")


def _validate_fleet(value: dict[str, object]) -> None:
    entries = cast(list[dict[str, object]], value["entries"])
    _unique([entry["entryId"] for entry in entries])
    _unique([_target_key(cast(dict[str, object], entry["target"])) for entry in entries])
    for entry in entries:
        if entry["authorityMode"] != "managed-restrictive":
            continue
        if entry["availability"] == "enabled" or entry["contextualOutcome"] in {
            "permit",
            "review",
            "observe",
        }:
            _fail("fec_managed_weaken_forbidden")


def _validate_assignment(value: dict[str, object]) -> None:
    selector = cast(dict[str, object], value["selector"])
    field_by_mode: dict[str, str | None] = {
        "all-active-devices": None,
        "selected-members": "memberIds",
        "selected-devices": "deviceIds",
        "supported-agents": "agentIds",
        "directory-query": "directoryQueryId",
        "device-tags": "deviceTags",
    }
    populated = [key for key in selector if key != "mode"]
    expected = field_by_mode[cast(str, selector["mode"])]
    if expected is None and populated:
        _fail("fec_conflicting_entry")
    if expected is not None and populated != [expected]:
        _fail("fec_conflicting_entry")
    if expected is not None:
        selected = selector[expected]
        if selected in (None, "", []) or isinstance(selected, list) and len(selected) != len(set(selected)):
            _fail("fec_assignment_empty")
    if value["continuousEnrollment"] is not True:
        _fail("fec_conflicting_entry")
    exclusions = cast(list[dict[str, object]], value["exclusions"])
    _unique([(item["kind"], item["targetId"]) for item in exclusions])


def _validate_custom_definition(value: dict[str, object]) -> None:
    commands = cast(list[dict[str, object]], value["commands"])
    variants = cast(list[dict[str, object]], value["variants"])
    _unique([item["commandId"] for item in commands])
    _unique([item["variantId"] for item in variants])
    for item in variants:
        platforms = cast(list[str], item["platforms"])
        _unique(platforms)
        if item["reviewState"] == "trusted" and not item.get("reviewedAt") or (
            item["reviewState"] == "trusted" and not item.get("reviewedBy")
        ):
            _fail("fec_missing_field")


def _validate_custom_configuration(value: dict[str, object]) -> None:
    commands = cast(list[dict[str, object]], value["commands"])
    _unique([item["commandId"] for item in commands])
    _unique(cast(list[object], value["allowedVariantIds"]))


def _validate_catalog(value: dict[str, object]) -> None:
    extensions = cast(list[dict[str, object]], value["extensions"])
    _unique([item["extensionId"] for item in extensions])
    _unique(cast(list[object], value["capabilities"]))
    for extension in extensions:
        permissions = cast(list[dict[str, object]], extension["permissions"])
        _unique([item["permissionId"] for item in permissions])


_SEMANTIC_VALIDATORS = {
    "fleetExtensionConfiguration": _validate_fleet,
    "assignment": _validate_assignment,
    "customExtensionDefinition": _validate_custom_definition,
    "customExtensionConfiguration": _validate_custom_configuration,
    "catalogSemantics": _validate_catalog,
}


def validate_fleet_contract(kind: ContractKind, value: object) -> dict[str, object]:
    """Validate and normalize one bounded shared contract."""

    try:
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
    except (TypeError, ValueError):
        _fail("fec_invalid_json")
    if len(encoded) > _MAX_PAYLOAD_BYTES:
        _fail("fec_limit_exceeded")
    validator = Draft202012Validator(_load_schema(kind), format_checker=FormatChecker())
    error = next(validator.iter_errors(value), None)
    if error is not None:
        _fail(_schema_error(error))
    normalized = deepcopy(cast(dict[str, object], value))
    if kind == "fleetExtensionConfiguration":
        for entry in cast(list[dict[str, object]], normalized["entries"]):
            entry.setdefault("source", "explicit")
        normalized.setdefault("previousVersionDigest", None)
    elif kind == "customExtensionConfiguration":
        normalized.setdefault("bindingMode", "exact-approved-variant")
    _SEMANTIC_VALIDATORS[kind](normalized)
    return normalized


def _sort_contract(kind: ContractKind, value: dict[str, object]) -> dict[str, object]:
    normalized = deepcopy(value)
    if kind == "fleetExtensionConfiguration":
        entries = cast(list[dict[str, object]], normalized["entries"])
        entries.sort(key=lambda item: (_target_key(cast(dict[str, object], item["target"])), item["entryId"]))
    elif kind == "assignment":
        selector = cast(dict[str, object], normalized["selector"])
        for key in ("memberIds", "deviceIds", "agentIds", "deviceTags"):
            if isinstance(selector.get(key), list):
                selector[key] = sorted(cast(list[str], selector[key]))
        exclusions = cast(list[dict[str, object]], normalized["exclusions"])
        exclusions.sort(key=lambda item: (item["kind"], item["targetId"]))
    elif kind == "customExtensionDefinition":
        cast(list[dict[str, object]], normalized["commands"]).sort(key=lambda item: item["commandId"])
        variants = cast(list[dict[str, object]], normalized["variants"])
        for variant in variants:
            variant["platforms"] = sorted(cast(list[str], variant["platforms"]))
        variants.sort(key=lambda item: item["variantId"])
    elif kind == "customExtensionConfiguration":
        cast(list[dict[str, object]], normalized["commands"]).sort(key=lambda item: item["commandId"])
        normalized["allowedVariantIds"] = sorted(cast(list[str], normalized["allowedVariantIds"]))
    else:
        extensions = cast(list[dict[str, object]], normalized["extensions"])
        for extension in extensions:
            cast(list[dict[str, object]], extension["permissions"]).sort(key=lambda item: item["permissionId"])
        extensions.sort(key=lambda item: item["extensionId"])
        normalized["capabilities"] = sorted(cast(list[str], normalized["capabilities"]))
    return normalized


def canonical_fleet_contract_bytes(kind: ContractKind, value: object) -> bytes:
    """Return deterministic canonical bytes for signing and digesting."""

    normalized = _sort_contract(kind, validate_fleet_contract(kind, value))
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def fleet_contract_digest(kind: ContractKind, value: object) -> str:
    digest = hashlib.sha256(CONTRACT_DOMAINS[kind] + canonical_fleet_contract_bytes(kind, value)).hexdigest()
    return f"sha256:{digest}"


def negotiate_fleet_capabilities(advertised: Sequence[str]) -> tuple[bool, tuple[str, ...]]:
    values = set(advertised)
    if any(not isinstance(value, str) or _CAPABILITY.fullmatch(value) is None for value in values):
        _fail("fec_unsupported_capability")
    missing = tuple(sorted(REQUIRED_FLEET_CAPABILITIES - values))
    return not missing, missing


def load_shared_fleet_fixtures() -> dict[str, object]:
    return cast(dict[str, object], json.loads((_CONTRACT_ROOT / "fixtures.json").read_text()))


def apply_adversarial_fixture(base: object, case: Mapping[str, object]) -> object:
    value = deepcopy(base)
    if not isinstance(value, dict):
        return value
    patch = case.get("patch")
    if isinstance(patch, Mapping):
        value.update(patch)
    replacement = case.get("replace")
    if isinstance(replacement, Mapping):
        value.update(replacement)
    duplicate_path = case.get("duplicatePath")
    if duplicate_path == "entries[0]":
        cast(list[object], value["entries"]).append(deepcopy(cast(list[object], value["entries"])[0]))
    elif duplicate_path == "extensions[0]":
        cast(list[object], value["extensions"]).append(deepcopy(cast(list[object], value["extensions"])[0]))
    return value
