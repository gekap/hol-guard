# ADR 0010: Default hook review to bundled Rust data plane

Status: accepted for `main`.

## Decision

HOL Guard 3.x selects native `auto` behavior when `HOL_GUARD_NATIVE` is not set, and the daemon hook fast path is enabled when `HOL_GUARD_HOOK_FAST_PATH` is not set. Published native wheels and Desktop Core sidecars use the verified, version-matched bundled Rust runtime as the exclusive semantic authority for supported `PreToolUse` and `PostToolUse` review.

The native boundary now begins at the raw hook envelope. Rust extracts the hook event and supported action, performs command classification, PostTool output extraction, source-reference validation, secure source reads, hashing/equivalence checks, and secret scanning. Structurally valid `PreToolUse` actions that are not yet modeled for automatic allow remain inside the Rust authority boundary and return conservative native review instead of escaping to a Python evaluator.

Resident client authentication, request/response framing, digest validation, and local socket/loopback I/O are also implemented by the bundled Rust runtime. Python remains a bounded control plane for daemon route authentication, resident lifecycle supervision, policy-snapshot transport, harness response rendering, approval presentation/continuation surfaces, and asynchronous non-authoritative evidence persistence. Those responsibilities cannot semantically reinterpret a supported hook or lower a native action floor.

## Security boundary

Automatic runtime selection is limited to the runtime bundled inside the installed `hol-guard` wheel or signed Desktop Core artifact. The runtime must pass executable ownership and permission checks plus manifest bindings for package version, protocol, source/build SHA, rule digest, byte digest, and size. Production `auto` does not search `PATH`, honor an arbitrary runtime override, download decision-time code, or call a network service.

Secret-bearing output remains blocked by the Rust path. Native unavailability, incompatibility, overload, timeout, malformed output, containment failure, client-authentication failure, framing failure, or digest mismatch fails closed rather than becoming an allow or a Python rescan.

## Compatibility settings

`HOL_GUARD_NATIVE=off` and `shadow` no longer restore Python semantic authority on the production hook route. If those settings make the bundled native authority unavailable, the production hook result remains fail closed. `force` remains available for developer validation and explicit runtime overrides. Invalid or empty mode values resolve to the product default instead of silently disabling Rust.

The Python reference evaluator and legacy transport helpers may remain temporarily for differential tests and non-production compatibility verification, but they are excluded from the ordinary production hook call graph by the permanent Rust authority ownership gate.

## Evidence

The permanent ownership contract in `ci/rust-authority-ownership.v1.json` requires:

- no-environment native `auto` selection and enabled hook fast path;
- Rust semantic authority for supported PreToolUse and PostToolUse;
- Rust raw hook-edge extraction;
- Rust PostTool decision-critical content/file I/O;
- Rust resident-client authentication, framing, digest validation, and socket I/O;
- no production Python source-reference or semantic fallback;
- fail-closed native failure behavior.

CI builds and lints the complete Rust workspace, runs real-binary PreToolUse/PostToolUse adversarial integration, resident differential and mutation integration, performance gates, and installed native-wheel execution proof. Stable native-wheel and Desktop packaging tests must continue to validate the bundled runtime without requiring native or fast-path environment-variable configuration.