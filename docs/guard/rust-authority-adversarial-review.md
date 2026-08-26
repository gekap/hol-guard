# Rust PreToolUse Authority Adversarial Review

This review is performed against the compiled, version-matched native runtime and the production daemon ingress.

## Required attack classes

- malformed, duplicate-key, trailing, deeply nested, and oversized JSON
- missing, duplicated, mismatched, and replayed request identifiers
- resident overload, timeout, disconnect, partial frame, and digest mismatch
- native binary absence, version mismatch, rule mismatch, and invalid manifest
- shell quoting, command substitution, redirection, pipelines, wrappers, PATH overrides, and nested interpreters
- destructive filesystem, disk, process, network, package, container, cloud, and credential commands
- sensitive path spelling, separator, home-relative, traversal, and case variants
- all supported harness names through the daemon PreToolUse ingress
- direct CLI fallback with native success and native failure

## Review invariants

- no supported PreToolUse request reaches a Python parser, classifier, evaluator, or policy floor
- no native failure spills into Python semantic evaluation
- any unrecognized or uncertain command is denied pending review
- hard safety floors cannot be lowered by transport or rendering code
- every allow has an exact native request binding and `authority = rust`
- malformed or unbound responses are rejected and fail closed
- the bundled runtime is version, build, rule, size, and digest bound
- generated integration evidence contains no command or file contents beyond synthetic fixtures
