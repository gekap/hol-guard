# Fleet Extension Configuration v2 contract reference

Shared contract files under `contracts/managed-controls/v2` are byte-identical in Core and Cloud.

## Canonical JSON

Canonical bytes are UTF-8 JSON with recursively sorted object keys, no insignificant whitespace, no non-finite numbers, and contract-specific deterministic array ordering. Parsers reject unknown fields, over-limit input, duplicate logical entries, conflicting entries, unsafe managed broadening, and unsupported schemas. Digests are `sha256:<lowercase hex>` over an ASCII domain label followed by canonical bytes:

- `hol.guard.fleet-extension-configuration.v1\0`
- `hol.guard.managed-control-assignment.v1\0`
- `hol.guard.custom-extension-definition.v2\0`
- `hol.guard.custom-extension-configuration.v2\0`
- `hol.guard.catalog-semantic-fingerprint.v2\0`

## Capability negotiation

All capabilities in `capabilities.json` are required for v2 fleet delivery. Readers ship first. Writers never downgrade by dropping authority-bearing fields. An unsupported target is excluded and surfaced; it does not receive a weaker projection.

## Stable identifiers

Cloud-generated IDs are bounded, lowercase, opaque, and workspace-scoped. Built-in Extension and permission IDs retain their existing canonical `command.*` namespaces. Custom IDs use `ced_`, `cev_`, `cei_`, and `cec_` namespaces and cannot collide with built-ins.

## Sensitive data boundary

The contracts have no field for a raw path, command line, source file, working directory, environment value, token, secret, or raw local identity. Unknown fields fail closed.

## Migration

Existing v1 Managed Controls and Custom Extension continuity remain readable during the compatibility window. They never become workspace portable trust automatically. Promotion to a v2 definition requires administrator review and creates a new immutable workspace object.
