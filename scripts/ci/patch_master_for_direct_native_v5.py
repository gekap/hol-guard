#!/usr/bin/env python3
"""Apply direct-native convergence with executable-path ownership checks."""

from __future__ import annotations

from pathlib import Path

from patch_master_for_direct_native_v4 import main as patch_required_gate_controller

PATH = Path("scripts/ci/rust_authority_master_orchestrator.py")


def main() -> int:
    patch_required_gate_controller()
    source = PATH.read_text(encoding="utf-8")
    old = '''    source_gate = seed(worktree, "scripts/ci/rust_pretool_no_python_gate.py")
'''
    new = '''    source_gate = seed(
        worktree,
        "scripts/ci/rust_pretool_no_python_gate_v2.py",
        "scripts/ci/rust_pretool_no_python_gate.py",
    )
'''
    if old not in source and "rust_pretool_no_python_gate_v2.py" not in source:
        raise RuntimeError("batch 1 source gate seed marker is missing")
    source = source.replace(old, new, 1)
    PATH.write_text(source, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
