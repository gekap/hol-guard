#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path.cwd().resolve()
LIMIT = 40000


def trim(text: str, limit: int = LIMIT) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + f"\n... <truncated {len(text)-limit} chars> ...\n" + text[-half:]


def rooted(value: str | Path) -> Path:
    path = Path(value)
    resolved = (ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    if resolved != ROOT and ROOT not in resolved.parents:
        raise ValueError(f"outside repository: {value}")
    return resolved


def run(command: str | list[str], timeout: int = 1800, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, shell=isinstance(command, str), executable="/bin/bash" if isinstance(command, str) else None, input=stdin, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env={**os.environ, "CI": "1", "PYTHONUNBUFFERED": "1"})


def definition(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "function", "function": {"name": name, "description": description, "parameters": {"type": "object", "properties": properties, "required": required, "additionalProperties": False}}}


TOOLS = [
    definition("list_files", "List files matching a glob.", {"glob": {"type": "string"}, "limit": {"type": "integer"}}, ["glob"]),
    definition("read_file", "Read a UTF-8 file with optional one-indexed line bounds.", {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, ["path"]),
    definition("search", "Search repository text with ripgrep.", {"pattern": {"type": "string"}, "glob": {"type": "string"}, "limit": {"type": "integer"}}, ["pattern"]),
    definition("write_file", "Create or replace a UTF-8 file.", {"path": {"type": "string"}, "content": {"type": "string"}}, ["path", "content"]),
    definition("delete_path", "Delete a repository file.", {"path": {"type": "string"}}, ["path"]),
    definition("apply_patch", "Apply a unified Git patch.", {"patch": {"type": "string"}}, ["patch"]),
    definition("run_command", "Run an allowlisted local inspection, formatter, build, or test command. GitHub, network, publication, and destructive operations are forbidden.", {"command": {"type": "string"}, "timeout": {"type": "integer"}}, ["command"]),
    definition("git_diff", "Show git status and current diff.", {"path": {"type": "string"}}, []),
]


def list_files(args: dict[str, Any]) -> str:
    excluded = {".git", ".venv", "node_modules", "target", "dist", "build", ".next"}
    values: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in excluded for part in rel.parts):
            continue
        if fnmatch.fnmatch(rel.as_posix(), str(args["glob"])):
            values.append(rel.as_posix())
            if len(values) >= min(int(args.get("limit", 500)), 1000):
                break
    return "\n".join(sorted(values)) or "<no files>"


def read_file(args: dict[str, Any]) -> str:
    path = rooted(args["path"])
    if not path.is_file():
        raise FileNotFoundError(path.relative_to(ROOT))
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, int(args.get("start_line", 1)))
    end = min(len(lines), int(args.get("end_line", len(lines))))
    return trim("\n".join(f"{number}: {lines[number-1]}" for number in range(start, end + 1)))


def search(args: dict[str, Any]) -> str:
    argv = ["rg", "--line-number", "--no-heading", "--color", "never", "--glob", "!.git/**", "--glob", "!.venv/**", "--glob", "!node_modules/**", "--glob", "!target/**"]
    if args.get("glob"):
        argv.extend(["--glob", str(args["glob"])])
    argv.extend([str(args["pattern"]), "."])
    result = run(argv, timeout=120)
    return trim("\n".join(result.stdout.splitlines()[: min(int(args.get("limit", 500)), 1000)]) or "<no matches>")


def write_file(args: dict[str, Any]) -> str:
    path = rooted(args["path"])
    if ".git" in path.relative_to(ROOT).parts:
        raise ValueError("cannot write .git")
    content = str(args["content"])
    if len(content.encode()) > 2_000_000:
        raise ValueError("write exceeds 2 MB")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"wrote {path.relative_to(ROOT)}"


def delete_path(args: dict[str, Any]) -> str:
    path = rooted(args["path"])
    if path.exists():
        path.unlink() if path.is_file() else path.rmdir()
    return f"deleted {path.relative_to(ROOT)}"


def apply_patch(args: dict[str, Any]) -> str:
    result = run(["git", "apply", "--3way", "--whitespace=fix", "-"], timeout=240, stdin=str(args["patch"]))
    if result.returncode:
        raise RuntimeError(trim(result.stdout, 12000))
    return result.stdout or "patch applied"


FORBIDDEN = (
    r"\bgit\s+(push|commit|tag|merge|rebase|reset|checkout|switch)\b", r"\bgh\s+", r"\bcurl\s+", r"\bwget\s+", r"\bssh\s+", r"\bsudo\s+", r"\b(npm|pnpm|yarn|bun|uv|pip|cargo)\s+publish\b", r"\brm\s+-rf\s+/",
)
ALLOWED = (
    "git status", "git diff", "git grep", "git log", "git show", "git ls-files", "rg ", "find ", "cat ", "head ", "tail ", "wc ",
    "python ", "python3 ", ".venv/bin/python ", ".venv/bin/pytest", ".venv/bin/ruff", "uv run ", "uv sync", "uv lock", "pytest", "ruff ",
    "bun install", "bun run ", "bun test", "bunx ", "npm run ", "npm test", "pnpm run ", "pnpm test", "cargo test", "cargo check", "cargo clippy",
)


def run_command(args: dict[str, Any]) -> str:
    command = str(args["command"]).strip()
    if any(re.search(pattern, command, re.I) for pattern in FORBIDDEN):
        raise ValueError("forbidden command")
    segments = [part.strip() for part in re.split(r"&&|;|\n", command) if part.strip()]
    if not segments or any(not part.startswith(ALLOWED) for part in segments):
        raise ValueError(f"outside allowlist: {command}")
    result = run(command, timeout=min(max(int(args.get("timeout", 1200)), 1), 1800))
    return f"exit={result.returncode}\n{trim(result.stdout)}"


def git_diff(args: dict[str, Any]) -> str:
    suffix = ""
    if args.get("path"):
        rooted(str(args["path"]))
        suffix = " -- " + shlex.quote(str(args["path"]))
    return trim(run(f"git status --short && git diff --stat{suffix} && git diff{suffix}", timeout=180).stdout or "<clean>")


HANDLERS: dict[str, Callable[[dict[str, Any]], str]] = {"list_files": list_files, "read_file": read_file, "search": search, "write_file": write_file, "delete_path": delete_path, "apply_patch": apply_patch, "run_command": run_command, "git_diff": git_diff}


def execute(name: str, raw: str) -> str:
    try:
        return trim(HANDLERS[name](json.loads(raw or "{}")))
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {type(exc).__name__}: {trim(str(exc), 10000)}"


def candidates() -> list[tuple[str, str, list[str]]]:
    values: list[tuple[str, str, list[str]]] = []
    if os.environ.get("OPENAI_API_KEY", "").strip():
        values.append(("https://api.openai.com/v1/chat/completions", os.environ["OPENAI_API_KEY"], [os.environ.get("OPENAI_MODEL", ""), "gpt-5.2-codex", "gpt-5.1-codex", "gpt-5", "gpt-4.1"]))
    if os.environ.get("GITHUB_TOKEN", "").strip():
        values.append(("https://models.github.ai/inference/chat/completions", os.environ["GITHUB_TOKEN"], [os.environ.get("GITHUB_MODELS_MODEL", ""), "openai/gpt-5.2-codex", "openai/gpt-5.1-codex", "openai/gpt-5", "openai/gpt-4.1", "xai/grok-code-fast-1"]))
    return values


def post(url: str, token: str, model: str, payload: dict[str, Any]) -> dict[str, Any]:
    req = Request(url, data=json.dumps({"model": model, **payload}).encode(), method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "post-merge-review-agent/1"})
    try:
        with urlopen(req, timeout=360) as response:
            return json.loads(response.read().decode())
    except HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}: {trim(exc.read().decode(errors='replace'), 5000)}") from exc
    except URLError as exc:
        raise RuntimeError(str(exc)) from exc


def choose() -> tuple[str, str, str]:
    failures: list[str] = []
    for url, token, models in candidates():
        for model in dict.fromkeys(filter(None, models)):
            try:
                response = post(url, token, model, {"messages": [{"role": "user", "content": "Reply READY."}], "max_tokens": 16, "temperature": 0})
                if response.get("choices"):
                    return url, token, model
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{model}: {exc}")
    raise RuntimeError("no model available:\n" + "\n".join(failures[-20:]))


def call(url: str, token: str, model: str, messages: list[dict[str, Any]]) -> dict[str, Any]:
    for attempt in range(7):
        try:
            return post(url, token, model, {"messages": messages, "tools": TOOLS, "tool_choice": "auto", "temperature": 0.1, "max_tokens": 16000})["choices"][0]["message"]
        except Exception as exc:  # noqa: BLE001
            if attempt == 6 or not any(code in str(exc) for code in ("429", "500", "502", "503", "504", "timed out")):
                raise
            time.sleep(min(30 * (attempt + 1), 150))
    raise RuntimeError("model retries exhausted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt-file", type=Path, required=True)
    parser.add_argument("--max-turns", type=int, default=220)
    args = parser.parse_args()
    prompt = args.prompt_file.read_text(encoding="utf-8", errors="replace")[:150000]
    url, token, model = choose()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": "You are a principal engineer performing a post-merge remediation. Work in the repository using tools. Fix every supplied finding in production code and tests. Do not weaken tests, security, authorization, privacy, retention, fail-closed behavior, accessibility, or quality gates. Never create GitHub issues, use network tools, publish packages, or perform GitHub mutations. Remove temporary automation before delivery. Run focused tests and show a coherent final diff."},
        {"role": "user", "content": prompt},
    ]
    for turn in range(args.max_turns):
        if len(messages) > 90:
            messages = messages[:2] + [{"role": "user", "content": "History compacted. Reinspect files and rerun tests."}] + messages[-70:]
        message = call(url, token, model, messages)
        messages.append(message)
        calls = message.get("tool_calls") or []
        if calls:
            for item in calls:
                function = item.get("function") or {}
                name = str(function.get("name", ""))
                messages.append({"role": "tool", "tool_call_id": item.get("id", f"call-{turn}-{name}"), "content": execute(name, str(function.get("arguments", "{}"))) if name in HANDLERS else f"ERROR: unknown tool {name}"})
            continue
        content = str(message.get("content") or "")
        if re.search(r"\b(cannot|unable|blocked|incomplete|remaining)\b", content, re.I):
            messages.append({"role": "user", "content": "Continue using tools until every finding is fixed and tests pass."})
            continue
        return 0
    raise RuntimeError("agent exceeded maximum turns")


if __name__ == "__main__":
    raise SystemExit(main())
