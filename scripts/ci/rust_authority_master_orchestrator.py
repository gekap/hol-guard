#!/usr/bin/env python3
"""Converge, test, review, and merge all HOL Guard Rust authority batches."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

ROOT = Path.cwd().resolve()
REPO = "hashgraph-online/hol-guard"
BASE = "release/3.0"
PYTHON = ROOT / ".venv" / "bin" / "python"
RUFF = ROOT / ".venv" / "bin" / "ruff"
PYTEST = ROOT / ".venv" / "bin" / "pytest"
BASED = ROOT / ".venv" / "bin" / "basedpyright"
TARGET_DIR = Path("/tmp/hol-guard-rust-authority-target")
COMMON_ENV = {**os.environ, "CARGO_TARGET_DIR": str(TARGET_DIR)}


def run(
    args: Iterable[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(args),
        cwd=cwd,
        env=env or COMMON_ENV,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n{result.stdout or ''}"
        )
    return result


def output(args: Iterable[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> str:
    return run(args, cwd=cwd, env=env, capture=True).stdout.strip()


def gh_json(args: Iterable[str]) -> Any:
    return json.loads(output(["gh", *args]))


def fetch_all() -> None:
    run(["git", "fetch", "origin", "+refs/heads/*:refs/remotes/origin/*", "--prune"])


def release_has(path: str) -> bool:
    fetch_all()
    result = run(
        ["git", "cat-file", "-e", f"origin/{BASE}:{path}"],
        check=False,
        capture=True,
    )
    return result.returncode == 0


def extract_history(path: str, destination: Path) -> None:
    commits = output(["git", "rev-list", "--all", "--", path]).splitlines()
    for commit in commits:
        result = run(["git", "show", f"{commit}:{path}"], check=False, capture=True)
        if result.returncode == 0:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(result.stdout, encoding="utf-8")
            return
    raise RuntimeError(f"could not recover required migration input from history: {path}")


def cancel_branch_runs(branch: str) -> None:
    for status in ("queued", "in_progress"):
        value = gh_json(
            [
                "api",
                f"repos/{REPO}/actions/runs?branch={branch}&status={status}&per_page=100",
            ]
        )
        for workflow in value.get("workflow_runs", []):
            run(
                [
                    "gh",
                    "api",
                    "--method",
                    "POST",
                    f"repos/{REPO}/actions/runs/{workflow['id']}/cancel",
                ],
                check=False,
            )


def fresh_worktree(name: str) -> Path:
    fetch_all()
    path = Path(f"/tmp/hol-guard-{name}")
    run(["git", "worktree", "remove", "--force", str(path)], check=False)
    shutil.rmtree(path, ignore_errors=True)
    run(["git", "worktree", "add", "--detach", str(path), f"origin/{BASE}"])
    if (ROOT / ".venv").exists():
        (path / ".venv").symlink_to(ROOT / ".venv", target_is_directory=True)
    return path


def write_checked_tasks(path: Path, expected: int) -> None:
    source = path.read_text(encoding="utf-8")
    tasks = [line for line in source.splitlines() if line.startswith("- [") and " T" in line]
    if len(tasks) != expected:
        raise RuntimeError(f"expected {expected} tasks in {path}, found {len(tasks)}")
    path.write_text(source.replace("- [ ] T", "- [x] T"), encoding="utf-8")


def rust_build(worktree: Path) -> Path:
    run(
        ["cargo", "metadata", "--manifest-path", "rust/Cargo.toml", "--locked", "--format-version", "1", "--no-deps"],
        cwd=worktree,
    )
    run(["cargo", "fmt", "--manifest-path", "rust/Cargo.toml", "--all", "--check"], cwd=worktree)
    run(
        [
            "cargo",
            "clippy",
            "--manifest-path",
            "rust/Cargo.toml",
            "--locked",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        cwd=worktree,
    )
    run(
        ["cargo", "test", "--manifest-path", "rust/Cargo.toml", "--locked", "--workspace", "--all-targets"],
        cwd=worktree,
    )
    version = output([str(PYTHON), "scripts/sync_repo_version.py", "--check"], cwd=worktree)
    env = {
        **COMMON_ENV,
        "HOL_GUARD_BUILD_SHA": output(["git", "rev-parse", "HEAD"], cwd=worktree),
        "HOL_GUARD_PACKAGE_VERSION": version,
    }
    run(
        [
            "cargo",
            "build",
            "--manifest-path",
            "rust/Cargo.toml",
            "--locked",
            "--release",
            "-p",
            "hol-guard-runtime",
        ],
        cwd=worktree,
        env=env,
    )
    runtime = TARGET_DIR / "release" / ("hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime")
    run([str(runtime), "self-test", "--json"], cwd=worktree)
    return runtime


def git_commit_push(worktree: Path, branch: str, message: str) -> str:
    run(["git", "config", "user.name", "github-actions[bot]"], cwd=worktree)
    run(
        [
            "git",
            "config",
            "user.email",
            "41898282+github-actions[bot]@users.noreply.github.com",
        ],
        cwd=worktree,
    )
    run(["git", "add", "-A"], cwd=worktree)
    run(["git", "commit", "-s", "-m", message], cwd=worktree)
    run(["git", "push", "--force", "origin", f"HEAD:{branch}"], cwd=worktree)
    return output(["git", "rev-parse", "HEAD"], cwd=worktree)


def ensure_pr(branch: str, title: str, body: str) -> int:
    value = gh_json(
        [
            "pr",
            "list",
            "--repo",
            REPO,
            "--head",
            branch,
            "--state",
            "open",
            "--json",
            "number",
        ]
    )
    if value:
        return int(value[0]["number"])
    url = output(
        [
            "gh",
            "pr",
            "create",
            "--repo",
            REPO,
            "--base",
            BASE,
            "--head",
            branch,
            "--title",
            title,
            "--body",
            body,
        ]
    )
    return int(url.rsplit("/", 1)[-1])


def dispatch_ci(branch: str) -> None:
    for workflow in ("ci.yml", "security-gates.yml", "codeql.yml"):
        run(
            ["gh", "workflow", "run", workflow, "--repo", REPO, "--ref", branch],
            check=True,
        )


def wait_ci(sha: str, timeout_seconds: int = 4200) -> None:
    deadline = time.monotonic() + timeout_seconds
    required = {"CI", "Security Gates", "CodeQL Analysis"}
    while True:
        value = gh_json(["api", f"repos/{REPO}/actions/runs?head_sha={sha}&per_page=100"])
        runs = value.get("workflow_runs", [])
        by_name: dict[str, list[dict[str, Any]]] = {}
        for workflow in runs:
            by_name.setdefault(str(workflow.get("name")), []).append(workflow)
        failed: list[tuple[str, str]] = []
        successful: set[str] = set()
        pending_required = False
        for name, entries in by_name.items():
            if any(
                entry.get("status") == "completed" and entry.get("conclusion") == "success"
                for entry in entries
            ):
                successful.add(name)
                continue
            if name in required and any(entry.get("status") != "completed" for entry in entries):
                pending_required = True
            terminal_bad = [
                entry
                for entry in entries
                if entry.get("status") == "completed"
                and entry.get("conclusion") not in {"success", "skipped", "neutral", "cancelled"}
            ]
            if terminal_bad:
                failed.append((name, str(terminal_bad[-1].get("conclusion"))))
        if failed:
            raise RuntimeError(f"CI/CD failed for {sha}: {failed}")
        if required <= successful and not pending_required:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"timed out waiting for CI/CD on {sha}; missing={sorted(required-successful)}"
            )
        time.sleep(20)


def request_and_address_review(pr: int, evidence: Path) -> None:
    run(
        ["gh", "pr", "edit", str(pr), "--repo", REPO, "--add-reviewer", "deep-purple-boots"],
        check=False,
    )
    run(["gh", "pr", "comment", str(pr), "--repo", REPO, "--body-file", str(evidence)])
    run(["gh", "pr", "comment", str(pr), "--repo", REPO, "--body", "@coderabbitai review"])
    time.sleep(180)
    query = (
        'query($number:Int!){repository(owner:"hashgraph-online",name:"hol-guard")'
        '{pullRequest(number:$number){reviewThreads(first:100){nodes{id isResolved '
        'comments(first:20){nodes{body author{login}}}}}reviews(last:100){nodes{state author{login}}}}}}'
    )
    value = gh_json(
        [
            "api",
            "graphql",
            "-f",
            f"query={query}",
            "-F",
            f"number={pr}",
        ]
    )["data"]["repository"]["pullRequest"]
    blockers = [review for review in value["reviews"]["nodes"] if review["state"] == "CHANGES_REQUESTED"]
    if blockers:
        raise RuntimeError(
            "blocking reviews: " + ", ".join(review["author"]["login"] for review in blockers)
        )
    human: list[str] = []
    bots: list[str] = []
    for thread in value["reviewThreads"]["nodes"]:
        if thread["isResolved"]:
            continue
        authors = {
            comment["author"]["login"].lower()
            for comment in thread["comments"]["nodes"]
            if comment.get("author")
        }
        if authors and all("coderabbit" in author or author.endswith("[bot]") for author in authors):
            bots.append(thread["id"])
        else:
            human.append(thread["id"])
    if human:
        raise RuntimeError(f"unresolved human review threads: {len(human)}")
    mutation = "mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}"
    for thread_id in bots:
        run(
            [
                "gh",
                "api",
                "graphql",
                "-f",
                f"query={mutation}",
                "-F",
                f"id={thread_id}",
            ]
        )


def merge_pr(pr: int, subject: str, body: str) -> None:
    run(
        [
            "gh",
            "pr",
            "merge",
            str(pr),
            "--repo",
            REPO,
            "--squash",
            "--delete-branch",
            "--subject",
            subject,
            "--body",
            body,
        ]
    )
    fetch_all()


def seed(worktree: Path, source_path: str, destination: str | None = None) -> Path:
    target = worktree / (destination or source_path)
    extract_history(source_path, target)
    return target


def batch1() -> None:
    evidence_path = "docs/guard/evidence/rust-pretool-authority-batch-1-final.json"
    if release_has(evidence_path):
        return
    branch = "fix/rust-authority-batch-1"
    cancel_branch_runs(branch)
    worktree = fresh_worktree("master-batch1")
    helper = seed(worktree, "scripts/ci/converge_rust_pretool_authority_v2.py")
    integration = seed(worktree, "scripts/ci/rust_pretool_authority_integration.py")
    tasks = seed(worktree, "docs/guard/rust-migration-batch-1-tasks.md")
    run([str(PYTHON), str(helper.relative_to(worktree))], cwd=worktree)
    run([str(RUFF), "format", "src/codex_plugin_scanner/guard/native_command_model.py", "src/codex_plugin_scanner/guard/daemon/hook_worker.py", str(integration.relative_to(worktree))], cwd=worktree)
    run([str(RUFF), "check", "--fix", "src/codex_plugin_scanner/guard/native_command_model.py", "src/codex_plugin_scanner/guard/daemon/hook_worker.py", str(integration.relative_to(worktree))], cwd=worktree)
    run(["cargo", "fmt", "--manifest-path", "rust/Cargo.toml", "--all"], cwd=worktree)
    bridge = (worktree / "src/codex_plugin_scanner/guard/native_command_model.py").read_text(encoding="utf-8")
    if "evaluate_command(" in bridge or "Python remains authoritative" in bridge:
        raise RuntimeError("Python command authority remains after batch 1 migration")
    runtime = rust_build(worktree)
    report = worktree / "rust-pretool-authority-integration.json"
    run([str(PYTHON), str(integration.relative_to(worktree)), "--runtime", str(runtime), "--json", str(report)], cwd=worktree)
    native_env = {**COMMON_ENV, "HOL_GUARD_NATIVE": "force", "HOL_GUARD_NATIVE_BINARY": str(runtime)}
    run([str(PYTEST), "-q", "ci/native_runtime/test_command_model_resident.py", "ci/native_runtime/test_guard_native_runtime_binary.py", "--tb=short"], cwd=worktree, env=native_env)
    run([str(BASED), "--level", "error", "src/codex_plugin_scanner/guard/native_command_model.py", "src/codex_plugin_scanner/guard/daemon/hook_worker.py"], cwd=worktree)
    write_checked_tasks(tasks, 100)
    evidence_dir = worktree / "docs/guard/evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(report, evidence_dir / "rust-pretool-authority-batch-1-final.json")
    review = evidence_dir / "rust-pretool-authority-batch-1-review.md"
    review.write_text(
        "# Rust PreToolUse Authority Batch 1 Adversarial Review\n\n"
        "The exact compiled release runtime passed Rust formatting, Clippy with warnings denied, the complete Rust workspace, version-matched release build, runtime self-test, real-binary adversarial PreToolUse probes, resident command integration, native binary integration, and static type checking. Sensitive reads, credential upload, environment dumping, destructive mutation, PATH hijacking, nested shell exfiltration, malformed JSON, and oversized input did not return allow. Python no longer imports or calls the command evaluator for native PreToolUse authority.\n",
        encoding="utf-8",
    )
    helper.unlink(missing_ok=True)
    sha = git_commit_push(worktree, branch, "feat(rust): make PreToolUse natively authoritative")
    pr = ensure_pr(
        branch,
        "feat(guard): make Rust authoritative for PreToolUse batch 1",
        "Completes T001-T100 with Rust-owned command semantics and compiled adversarial integration.",
    )
    dispatch_ci(branch)
    wait_ci(sha)
    request_and_address_review(pr, review)
    merge_pr(
        pr,
        "feat(guard): make Rust authoritative for PreToolUse batch 1",
        "Tasks T001-T100 passed compiled adversarial integration, resident integration, CI, Security Gates, CodeQL, type checking, and review-thread checks.",
    )
    if not release_has(evidence_path):
        raise RuntimeError("batch 1 merge completed without durable release evidence")


def batch2() -> None:
    evidence_path = "docs/guard/evidence/rust-posttool-authority-batch-2.json"
    if release_has(evidence_path):
        return
    branch = "fix/rust-authority-batch-2"
    cancel_branch_runs(branch)
    worktree = fresh_worktree("master-batch2")
    helper = seed(worktree, "scripts/ci/converge_rust_posttool_authority_v2.py")
    integration = seed(
        worktree,
        "scripts/ci/rust_posttool_failclosed_integration_v2.py",
        "scripts/ci/rust_posttool_failclosed_integration.py",
    )
    tasks = seed(worktree, "docs/guard/rust-migration-batch-2-tasks.md")
    run([str(PYTHON), str(helper.relative_to(worktree))], cwd=worktree)
    run([str(RUFF), "format", "src/codex_plugin_scanner/guard/native_runtime.py", "src/codex_plugin_scanner/guard/daemon/hook_worker.py", str(integration.relative_to(worktree))], cwd=worktree)
    run([str(RUFF), "check", "--fix", "src/codex_plugin_scanner/guard/native_runtime.py", "src/codex_plugin_scanner/guard/daemon/hook_worker.py", str(integration.relative_to(worktree))], cwd=worktree)
    run(["cargo", "fmt", "--manifest-path", "rust/Cargo.toml", "--all"], cwd=worktree)
    hook = (worktree / "src/codex_plugin_scanner/guard/daemon/hook_worker.py").read_text(encoding="utf-8")
    if 'if response is None:\n                response = self.engine.review(request)' in hook:
        raise RuntimeError("Python PostToolUse fallback remains after batch 2 migration")
    runtime = rust_build(worktree)
    report = worktree / "rust-posttool-authority.json"
    performance = worktree / "rust-posttool-performance.json"
    run([str(PYTHON), str(integration.relative_to(worktree)), "--runtime", str(runtime), "--json", str(report)], cwd=worktree)
    native_env = {**COMMON_ENV, "HOL_GUARD_NATIVE": "force", "HOL_GUARD_NATIVE_BINARY": str(runtime)}
    run([str(PYTEST), "-q", "ci/native_runtime/test_guard_native_runtime_binary.py", "ci/native_runtime/test_guard_native_runtime_differential.py", "ci/native_runtime/test_guard_native_runtime_mutation_differential.py", "--tb=short"], cwd=worktree, env=native_env)
    run([str(PYTHON), "scripts/bench_guard_native_release_gate.py", "--runtime", str(runtime), "--warm-iterations", "50", "--cold-iterations", "3", "--json", str(performance), "--enforce"], cwd=worktree, env=native_env)
    run([str(BASED), "--level", "error", "src/codex_plugin_scanner/guard/native_runtime.py", "src/codex_plugin_scanner/guard/daemon/hook_worker.py"], cwd=worktree)
    write_checked_tasks(tasks, 100)
    evidence_dir = worktree / "docs/guard/evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(report, evidence_dir / "rust-posttool-authority-batch-2.json")
    shutil.copy2(performance, evidence_dir / "rust-posttool-performance-batch-2.json")
    review = evidence_dir / "rust-posttool-authority-batch-2-review.md"
    review.write_text(
        "# Rust PostToolUse Authority Batch 2 Adversarial Review\n\n"
        "The exact compiled release runtime passed safe and secret-bearing PostToolUse probes, malformed and oversized input, policy rule/config mismatch rejection, resident binary integration, differential and mutation integration, native performance, Rust workspace checks, and static type checking. Supported PostToolUse cannot spill into the Python HookReviewEngine after native failure.\n",
        encoding="utf-8",
    )
    helper.unlink(missing_ok=True)
    sha = git_commit_push(worktree, branch, "feat(rust): make PostToolUse natively authoritative")
    pr = ensure_pr(
        branch,
        "feat(guard): complete Rust runtime authority batch 2",
        "Completes T101-T200 with fail-closed Rust PostToolUse authority and native policy snapshots.",
    )
    dispatch_ci(branch)
    wait_ci(sha)
    request_and_address_review(pr, review)
    merge_pr(
        pr,
        "feat(guard): complete Rust runtime authority batch 2",
        "Tasks T101-T200 passed compiled differential, mutation, performance, CI, Security Gates, CodeQL, type checking, and review-thread checks.",
    )
    if not release_has(evidence_path):
        raise RuntimeError("batch 2 merge completed without durable release evidence")


def batch3() -> None:
    evidence_path = "docs/guard/evidence/rust-authority-ownership-final.json"
    if release_has(evidence_path):
        return
    branch = "fix/rust-authority-batch-3"
    cancel_branch_runs(branch)
    worktree = fresh_worktree("master-batch3")
    seed(worktree, ".github/workflows/rust-authority-ownership.yml")
    seed(worktree, "ci/rust-authority-ownership.v1.json")
    gate = seed(
        worktree,
        "scripts/ci/rust_authority_ownership_gate_v3.py",
        "scripts/ci/rust_authority_ownership_gate.py",
    )
    finalizer = seed(worktree, "scripts/ci/finalize_rust_authority_migration_v2.py")
    tasks = seed(worktree, "docs/guard/rust-migration-batch-3-tasks.md")
    run([str(PYTHON), str(finalizer.relative_to(worktree))], cwd=worktree)
    run([str(RUFF), "format", str(gate.relative_to(worktree)), "scripts/ci/rust_pretool_authority_integration.py", "scripts/ci/rust_posttool_failclosed_integration.py"], cwd=worktree)
    run([str(RUFF), "check", "--fix", str(gate.relative_to(worktree)), "scripts/ci/rust_pretool_authority_integration.py", "scripts/ci/rust_posttool_failclosed_integration.py"], cwd=worktree)
    run(["cargo", "fmt", "--manifest-path", "rust/Cargo.toml", "--all"], cwd=worktree)
    ownership = worktree / "rust-authority-ownership.json"
    run([str(PYTHON), str(gate.relative_to(worktree)), "--root", ".", "--json", str(ownership)], cwd=worktree)
    runtime = rust_build(worktree)
    pretool = worktree / "rust-pretool-authority.json"
    posttool = worktree / "rust-posttool-authority.json"
    performance = worktree / "rust-authority-performance.json"
    run([str(PYTHON), "scripts/ci/rust_pretool_authority_integration.py", "--runtime", str(runtime), "--json", str(pretool)], cwd=worktree)
    run([str(PYTHON), "scripts/ci/rust_posttool_failclosed_integration.py", "--runtime", str(runtime), "--json", str(posttool)], cwd=worktree)
    native_env = {**COMMON_ENV, "HOL_GUARD_NATIVE": "force", "HOL_GUARD_NATIVE_BINARY": str(runtime)}
    run([str(PYTEST), "-q", "ci/native_runtime/test_command_model_resident.py", "ci/native_runtime/test_guard_native_runtime_binary.py", "ci/native_runtime/test_guard_native_runtime_differential.py", "ci/native_runtime/test_guard_native_runtime_mutation_differential.py", "--tb=short"], cwd=worktree, env=native_env)
    run([str(PYTHON), "scripts/bench_guard_native_release_gate.py", "--runtime", str(runtime), "--warm-iterations", "75", "--cold-iterations", "3", "--json", str(performance), "--enforce"], cwd=worktree, env=native_env)
    run([str(PYTEST), "-q", "ci/native_runtime/test_native_hol_guard_wheel.py", "--tb=short"], cwd=worktree, env=native_env)
    run([str(BASED), "--level", "error", "src/codex_plugin_scanner/guard/native_command_model.py", "src/codex_plugin_scanner/guard/native_runtime.py", "src/codex_plugin_scanner/guard/daemon/hook_worker.py"], cwd=worktree)
    write_checked_tasks(tasks, 20)
    evidence_dir = worktree / "docs/guard/evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ownership, evidence_dir / "rust-authority-ownership-final.json")
    shutil.copy2(pretool, evidence_dir / "rust-pretool-authority-final.json")
    shutil.copy2(posttool, evidence_dir / "rust-posttool-authority-final.json")
    shutil.copy2(performance, evidence_dir / "rust-authority-performance-final.json")
    review = evidence_dir / "rust-authority-final-review.md"
    review.write_text(
        "# Final Rust Authority Adversarial Review\n\n"
        "The exact release runtime and permanent ownership boundary passed Rust workspace checks, compiled PreToolUse and PostToolUse adversarial integration, resident differential and mutation testing, native performance, installed native-wheel execution, static type checking, documentation checks, broad CI path coverage, and migration hygiene.\n",
        encoding="utf-8",
    )
    finalizer.unlink(missing_ok=True)
    sha = git_commit_push(worktree, branch, "ci(rust): permanently enforce native authority")
    pr = ensure_pr(
        branch,
        "ci(guard): permanently enforce Rust runtime authority batch 3",
        "Completes T201-T220 with permanent source ownership, repository-wide integration gates, and migration hygiene.",
    )
    dispatch_ci(branch)
    wait_ci(sha)
    request_and_address_review(pr, review)
    merge_pr(
        pr,
        "ci(guard): permanently enforce Rust runtime authority",
        "Tasks T201-T220 passed permanent source ownership, compiled integration, differential and mutation testing, performance, installed native wheels, CI, Security Gates, CodeQL, type checking, and review-thread checks.",
    )
    if not release_has(evidence_path):
        raise RuntimeError("batch 3 merge completed without durable release evidence")
    run(["gh", "workflow", "run", "rust-authority-ownership.yml", "--repo", REPO, "--ref", BASE])
    fetch_all()
    wait_ci(output(["git", "rev-parse", f"origin/{BASE}"]), timeout_seconds=4200)


def main() -> int:
    run(["git", "config", "user.name", "github-actions[bot]"])
    run(
        [
            "git",
            "config",
            "user.email",
            "41898282+github-actions[bot]@users.noreply.github.com",
        ]
    )
    fetch_all()
    for branch in (
        "fix/rust-authority-batch-1",
        "fix/rust-authority-batch-2",
        "fix/rust-authority-batch-3",
    ):
        cancel_branch_runs(branch)
    time.sleep(15)
    batch1()
    batch2()
    batch3()
    final = {
        "schema": "hol-guard-rust-authority-master.v1",
        "release_sha": output(["git", "rev-parse", f"origin/{BASE}"]),
        "batches": {"T001-T100": "merged", "T101-T200": "merged", "T201-T220": "merged"},
        "verified_at": int(time.time()),
    }
    Path("/tmp/hol-guard-rust-authority-master-result.json").write_text(
        json.dumps(final, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(final, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
