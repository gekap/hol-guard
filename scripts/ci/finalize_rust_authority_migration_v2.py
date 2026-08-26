#!/usr/bin/env python3
"""Finalize Rust authority documentation and remove all migration-only residue."""

from __future__ import annotations

from pathlib import Path

TEMPORARY_PATHS = (
    ".github/workflows/rust-local-toolchain-export.yml",
    ".github/workflows/rust-pretool-authority-bootstrap.yml",
    ".github/workflows/rust-pretool-authority-orchestrator.yml",
    ".github/workflows/rust-pretool-authority-fallback.yml",
    ".github/workflows/rust-pretool-authority-lint-fix.yml",
    ".github/workflows/rust-pretool-authority-retry-dispatch.yml",
    ".github/workflows/rust-pretool-authority-acceptance.yml",
    ".github/workflows/rust-authority-batch1-finalize.yml",
    ".github/workflows/rust-authority-batch1-merge-gate.yml",
    ".github/workflows/rust-authority-batch1-retry-merge.yml",
    ".github/workflows/rust-authority-batch1-retry-merge-v2.yml",
    ".github/workflows/rust-authority-batch1-converge-v3.yml",
    ".github/workflows/rust-authority-batch1-converge-v4.yml",
    ".github/workflows/rust-posttool-authority-bootstrap.yml",
    ".github/workflows/rust-posttool-authority-orchestrator.yml",
    ".github/workflows/rust-posttool-authority-lint-fix.yml",
    ".github/workflows/rust-posttool-authority-acceptance.yml",
    ".github/workflows/rust-policy-snapshot-generation-fix.yml",
    ".github/workflows/rust-authority-batch2-merge-gate.yml",
    ".github/workflows/rust-authority-batch2-retry-merge-v2.yml",
    ".github/workflows/rust-authority-batch2-converge-v3.yml",
    ".github/workflows/rust-authority-batch2-converge-v4.yml",
    ".github/workflows/rust-authority-final-orchestrator.yml",
    ".github/workflows/rust-authority-final-lint-fix.yml",
    ".github/workflows/rust-authority-final-merge-gate.yml",
    ".github/workflows/rust-authority-final-retry-merge-v2.yml",
    ".github/workflows/rust-authority-batch3-converge-v3.yml",
    "scripts/ci/bootstrap_rust_pretool_authority.sh",
    "scripts/ci/select_rust_pretool_authority_candidate.sh",
    "scripts/ci/fallback_rust_pretool_authority.py",
    "scripts/ci/converge_rust_pretool_authority.py",
    "scripts/ci/converge_rust_pretool_authority_v2.py",
    "scripts/ci/bootstrap_rust_posttool_authority.sh",
    "scripts/ci/fallback_rust_posttool_authority.py",
    "scripts/ci/converge_rust_posttool_authority_v2.py",
    "scripts/ci/finalize_rust_authority_migration.py",
    "scripts/ci/finalize_rust_authority_migration_v2.py",
    "docs/guard/.batch1-merge-probe",
    "rust/AUTHORITY_BATCH_1",
    "rust/AUTHORITY_BATCH_1_FINAL",
    "rust/AUTHORITY_BATCH_2",
    "rust/AUTHORITY_BATCH_2_FINAL",
    "rust/AUTHORITY_FINAL",
)

ARCHITECTURE_SECTION = """
## Rust Authority Boundary

Supported `PreToolUse` and `PostToolUse` security semantics are owned by the
version-matched bundled Rust runtime. No supported path converts native
unavailability, incompatibility, overload, timeout, malformed output, policy
snapshot failure, or containment failure into Python semantic evaluation.
Those conditions fail closed.

Python is outside the semantic authority boundary. It may authenticate and
transport a request, render an already-produced native result for a harness,
coordinate approval continuation, and persist bounded asynchronous evidence.
It may not parse or classify a supported `PreToolUse` command, lower a native
action floor, rescan supported `PostToolUse` output as an authoritative
fallback, or synthesize an allow after native failure.

The permanent ownership contract is recorded in
`ci/rust-authority-ownership.v1.json` and enforced by
`.github/workflows/rust-authority-ownership.yml` across the complete Guard
runtime, adapter, daemon, policy, store, packaging, script, test, documentation,
and workflow tree.
""".strip()

SUPPORT_SECTION = """
## Rust Authority Boundary

Every supported harness routes command and output security semantics through
the bundled, version-matched Rust runtime. Supported `PreToolUse` command
classification and supported `PostToolUse` output review have no Python
semantic fallback. Native identity, protocol, rule-digest, policy-snapshot,
overload, timeout, transport, malformed-response, and containment failures fail
closed.

Python is limited to authenticated transport, harness-specific rendering,
approval coordination, dashboard control-plane work, and bounded
non-authoritative evidence persistence. The repository-wide ownership gate
prevents Python command evaluation or output-scanning fallback from being
reintroduced.
""".strip()


def replace_section(path: Path, heading: str, body: str) -> None:
    source = path.read_text(encoding="utf-8")
    if heading in source:
        before, rest = source.split(heading, 1)
        next_heading = rest.find("\n## ")
        after = "" if next_heading == -1 else rest[next_heading:]
        source = before.rstrip() + "\n\n" + body + ("\n" + after.lstrip() if after else "\n")
    else:
        source = source.rstrip() + "\n\n" + body + "\n"
    path.write_text(source, encoding="utf-8")


def remove_legacy_architecture(source: str) -> str:
    heading = "### Legacy Path (Non-PostToolUse Events)"
    start = source.find(heading)
    if start == -1:
        return source
    end = source.find("\n## ", start)
    if end == -1:
        end = len(source)
    return source[:start].rstrip() + "\n\n" + source[end:].lstrip()


def main() -> int:
    architecture = Path("docs/guard/all-harness-hook-review.md")
    architecture.write_text(
        remove_legacy_architecture(architecture.read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    replace_section(architecture, "## Rust Authority Boundary", ARCHITECTURE_SECTION)
    replace_section(Path("docs/guard/harness-support.md"), "## Rust Authority Boundary", SUPPORT_SECTION)

    for raw in TEMPORARY_PATHS:
        Path(raw).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
