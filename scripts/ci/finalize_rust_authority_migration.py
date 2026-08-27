#!/usr/bin/env python3
"""Finalize documentation and remove temporary Rust migration delivery residue."""

from __future__ import annotations

from pathlib import Path


TEMPORARY_PATHS = (
    ".github/workflows/rust-local-toolchain-export.yml",
    ".github/workflows/rust-pretool-authority-bootstrap.yml",
    ".github/workflows/rust-pretool-authority-orchestrator.yml",
    ".github/workflows/rust-authority-batch1-finalize.yml",
    ".github/workflows/rust-authority-batch1-merge-gate.yml",
    ".github/workflows/rust-posttool-authority-bootstrap.yml",
    ".github/workflows/rust-posttool-authority-orchestrator.yml",
    ".github/workflows/rust-authority-batch2-merge-gate.yml",
    "scripts/ci/bootstrap_rust_pretool_authority.sh",
    "scripts/ci/bootstrap_rust_posttool_authority.sh",
    "scripts/ci/fallback_rust_posttool_authority.py",
    "docs/guard/.batch1-merge-probe",
    "rust/AUTHORITY_BATCH_1",
    "rust/AUTHORITY_BATCH_1_FINAL",
    "rust/AUTHORITY_BATCH_2",
    "rust/AUTHORITY_BATCH_2_FINAL",
)

ARCHITECTURE_SECTION = """
## Rust Authority Boundary

Supported `PreToolUse` and `PostToolUse` semantic decisions are owned by the
version-matched bundled Rust runtime. There is no strict mode and no supported
path that converts native unavailability, incompatibility, overload, timeout,
malformed output, or containment failure into Python semantic evaluation.
Those conditions fail closed.

Python remains outside the semantic authority boundary. It may authenticate and
transport a request, render the already-produced native result for a harness,
coordinate approval continuation, and persist bounded asynchronous evidence.
It may not parse or classify a supported `PreToolUse` command, lower a native
action floor, rescan supported `PostToolUse` output as an authoritative
fallback, or synthesize an allow after native failure.

The permanent ownership contract is recorded in
`ci/rust-authority-ownership.v1.json` and enforced by
`.github/workflows/rust-authority-ownership.yml` across the complete Guard
runtime, adapter, daemon, policy, store, packaging, script, and workflow tree.
""".strip()

SUPPORT_SECTION = """
## Rust Authority Boundary

Every supported harness routes security semantics through the bundled,
version-matched Rust runtime. `PreToolUse` command decisions and supported
`PostToolUse` output review do not use a Python semantic fallback. Native
identity, protocol, rule-digest, policy-snapshot, overload, timeout, transport,
and response failures fail closed.

Python is limited to authenticated transport, harness-specific rendering,
approval coordination, dashboard control-plane work, and bounded
non-authoritative evidence persistence. The repository-wide ownership gate
prevents Python command evaluation or output-scanning fallback from being
reintroduced.
""".strip()


def _replace_legacy_architecture(source: str) -> str:
    start = source.find("### Legacy Path (Non-PostToolUse Events)")
    if start == -1:
        return source
    end = source.find("\n## ", start)
    if end == -1:
        end = len(source)
    return source[:start].rstrip() + "\n\n" + source[end:].lstrip()


def _replace_section(path: Path, heading: str, body: str) -> None:
    source = path.read_text(encoding="utf-8")
    if heading in source:
        before, rest = source.split(heading, 1)
        next_heading = rest.find("\n## ")
        after = "" if next_heading == -1 else rest[next_heading:]
        source = before.rstrip() + "\n\n" + body + ("\n" + after.lstrip() if after else "\n")
    else:
        source = source.rstrip() + "\n\n" + body + "\n"
    path.write_text(source, encoding="utf-8")


def main() -> int:
    architecture = Path("docs/guard/all-harness-hook-review.md")
    source = _replace_legacy_architecture(architecture.read_text(encoding="utf-8"))
    architecture.write_text(source, encoding="utf-8")
    _replace_section(architecture, "## Rust Authority Boundary", ARCHITECTURE_SECTION)
    _replace_section(Path("docs/guard/harness-support.md"), "## Rust Authority Boundary", SUPPORT_SECTION)

    for raw in TEMPORARY_PATHS:
        Path(raw).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
