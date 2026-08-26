#!/usr/bin/env python3
"""Apply reconciled direct-native convergence with Python runtime retirement."""

from __future__ import annotations

from pathlib import Path

from patch_master_for_direct_native_v6 import main as patch_robust_direct_native

PATH = Path("scripts/ci/rust_authority_master_orchestrator.py")


def main() -> int:
    patch_robust_direct_native()
    source = PATH.read_text(encoding="utf-8")
    source = source.replace(
        '''    selector = seed(worktree, "scripts/ci/select_rust_pretool_authority_candidate_v2.sh")
''',
        '''    selector = seed(worktree, "scripts/ci/select_rust_pretool_authority_candidate_v3.sh")
    cleanup = seed(worktree, "scripts/ci/remove_python_pretool_runtime.py")
''',
        1,
    )
    source = source.replace(
        '''        (selector, "scripts/ci/select_rust_pretool_authority_candidate_v2.sh"),
        (integration, "scripts/ci/rust_pretool_authority_integration.py"),
''',
        '''        (selector, "scripts/ci/select_rust_pretool_authority_candidate_v3.sh"),
        (cleanup, "scripts/ci/remove_python_pretool_runtime.py"),
        (integration, "scripts/ci/rust_pretool_authority_integration.py"),
''',
        1,
    )
    source = source.replace(
        '''    selector.unlink(missing_ok=True)
    sha = git_commit_push(worktree, branch, "feat(rust): make PreToolUse direct-native")
''',
        '''    selector.unlink(missing_ok=True)
    cleanup.unlink(missing_ok=True)
    sha = git_commit_push(worktree, branch, "feat(rust): make PreToolUse direct-native")
''',
        1,
    )
    if "select_rust_pretool_authority_candidate_v3.sh" not in source:
        raise RuntimeError("master controller did not adopt candidate reconciliation v3")
    PATH.write_text(source, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
