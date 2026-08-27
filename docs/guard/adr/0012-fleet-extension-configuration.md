# ADR 0012: Fleet Extension Configuration and dynamic assignment

Status: Accepted  
Applies to: HOL Guard 3.0 Core and HOL Guard Cloud 3.0

## Decision

Fleet Extension Configuration is an Extension-first section of the existing Managed Controls Control Set. A published immutable configuration version expresses built-in Extension availability, contextual outcomes, permission settings, and portable Custom Extension settings. A separate durable assignment selects current and future eligible workspace targets. Cloud compiles one catalog-bound, device-bound composite projection; Core verifies and atomically activates it with local authority.

## Canonical nouns

- **Fleet Extension Configuration**: immutable versioned intent.
- **Managed Control Assignment**: durable current-and-future selector plus exclusions.
- **Portable Custom Extension Definition**: workspace-owned reviewed semantic identity with approved variants.
- **Custom Extension Configuration**: default and stable command settings for one definition.
- **Catalog Semantic Fingerprint**: digest of behaviorally relevant Extension or permission meaning.
- **Desired / resolved / delivered / verified / applied / effective**: distinct lifecycle stages.
- **Stale / drifted / incompatible / failed / excluded**: distinct non-converged states.

The UI may say **Allow** and **Deny**. Contracts use **permit**, **review**, **block**, **observe**, **enabled**, and **disabled**. Availability is not contextual policy. Contextual block is not Managed Block. Managed restrictive authority can only preserve or strengthen protection.

## Authority and precedence

1. Hard local safety invariants and required Extension floors.
2. Managed restrictive disable or block.
3. Local user tightening.
4. Workspace shared defaults.
5. Personal shared defaults.
6. Built-in defaults.

A more restrictive applicable contribution wins. Managed restrictive authority cannot permit, enable, or suppress required Package Firewall delegation. Local users may tighten but cannot weaken a managed or required floor.

## Assignment

Assignments are durable selectors, not rollout cohorts. `all-active-devices`, selected members and all owned devices, supported agents, directory queries, and device tags continuously reconcile. Explicit selected-device assignments remain exact but still re-evaluate device eligibility. New eligible devices converge without republishing. Suspended members, revoked devices, ambiguous ownership, unsupported capabilities, semantic mismatch, and explicit exclusions fail closed and remain visible.

## Custom Extension identity and privacy

Cloud stores a per-workspace opaque definition ID, stable command IDs, semantic fingerprints, and reviewed variant evidence digests. Exact executable paths, raw command lines, source, environment values, tokens, secrets, and globally correlatable local identifiers never cross the boundary. Core binds an approved variant to the exact local identity and is the enforcement authority.

## Offline, expiry, offboarding, and transfer

Core retains the exact last-known-good composite state while offline. Expiry makes state stale and blocks new broadening, but does not silently erase a restrictive floor. Unassignment, offboarding, revocation, and workspace transfer use signed monotonic tombstones. A device leaving a workspace releases workspace-shared defaults only after verified tombstone processing; managed restrictions use the configured bounded grace or break-glass path and remain auditable.

## Plan packaging

Fleet authoring and continuous assignment require Team or Enterprise. Local protection, local configuration, and local tightening remain available without Cloud. Entitlement loss freezes new fleet mutations and follows the documented authority-release process; it never disables local protection.

## Versioning and downgrade

Writers emit a contract only after the reader capability is advertised. Unsupported devices are excluded with `fec_unsupported_capability`; no fallback may remove an Extension target, Custom Extension command setting, managed floor, semantic fingerprint, or composite-apply requirement. v1 and v2 contracts coexist by explicit schema version and domain-separated digest.
