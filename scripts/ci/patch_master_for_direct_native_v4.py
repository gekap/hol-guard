#!/usr/bin/env python3
"""Apply direct-native convergence and robust required-gate waiting."""

from __future__ import annotations

from pathlib import Path

from patch_master_for_direct_native_v3 import main as patch_wire_traced_direct_native

PATH = Path("scripts/ci/rust_authority_master_orchestrator.py")


def function_span(source: str, name: str) -> tuple[int, int]:
    start = source.find(f"def {name}(")
    if start < 0:
        raise RuntimeError(f"missing function {name}")
    end = source.find("\ndef ", start + 4)
    if end < 0:
        end = len(source)
    return start, end


WAIT_CI = r'''
def wait_ci(sha: str, timeout_seconds: int = 4200) -> None:
    deadline = time.monotonic() + timeout_seconds
    required = {"CI", "Security Gates", "CodeQL Analysis"}
    while True:
        value = gh_json(["api", f"repos/{REPO}/actions/runs?head_sha={sha}&per_page=100"])
        runs = [run for run in value.get("workflow_runs", []) if run.get("name") in required]
        successful = {
            str(workflow.get("name"))
            for workflow in runs
            if workflow.get("status") == "completed" and workflow.get("conclusion") == "success"
        }
        failed = [
            (str(workflow.get("name")), str(workflow.get("conclusion")))
            for workflow in runs
            if workflow.get("status") == "completed"
            and workflow.get("conclusion") not in {"success", "skipped", "neutral", "cancelled"}
        ]
        pending = {
            str(workflow.get("name"))
            for workflow in runs
            if workflow.get("status") != "completed"
        }
        if failed:
            raise RuntimeError(f"required CI/CD failed for {sha}: {failed}")
        if required <= successful and not (required & pending):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"timed out waiting for required CI/CD on {sha}; "
                f"missing={sorted(required-successful)} pending={sorted(pending)}"
            )
        time.sleep(20)
'''


def main() -> int:
    patch_wire_traced_direct_native()
    source = PATH.read_text(encoding="utf-8")
    start, end = function_span(source, "wait_ci")
    source = source[:start] + WAIT_CI.rstrip() + "\n\n" + source[end:].lstrip("\n")
    PATH.write_text(source, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
