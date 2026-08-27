#!/usr/bin/env python3
"""Autonomous, repository-scoped implementation agent for the Everyday Mode program.

This script is intentionally limited to the checked-out repository. It uses an
OpenAI-compatible inference endpoint, exposes bounded file/test tools, and never
performs GitHub mutations itself.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path.cwd().resolve()
MAX_TOOL_OUTPUT = 40_000
MAX_FILE_BYTES = 300_000
TASK_RE = re.compile(r"(?m)^.*?\b(EVM-(\d{3}))\b.*$")


@dataclass(frozen=True)
class Endpoint:
    url: str
    token: str
    models: tuple[str, ...]
    api_kind: str = "openai"


def _inside_root(path: Path) -> Path:
    resolved = (ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    if resolved != ROOT and ROOT not in resolved.parents:
        raise ValueError(f"path escapes repository: {path}")
    return resolved


def _trim(value: str, limit: int = MAX_TOOL_OUTPUT) -> str:
    if len(value) <= limit:
        return value
    half = limit // 2
    return value[:half] + f"\n... <truncated {len(value) - limit} chars> ...\n" + value[-half:]


def _run(argv: list[str], *, timeout: int = 1800, check: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    if check and result.returncode != 0:
        raise RuntimeError(_trim(result.stdout))
    return result


def parse_tasks(todo_path: Path) -> dict[int, str]:
    text = todo_path.read_text(encoding="utf-8")
    matches = list(TASK_RE.finditer(text))
    tasks: dict[int, str] = {}
    for index, match in enumerate(matches):
        number = int(match.group(2))
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        section = text[start:end].strip()
        if number not in tasks or len(section) > len(tasks[number]):
            tasks[number] = section
    missing = [number for number in range(1, 741) if number not in tasks]
    if missing:
        raise RuntimeError(f"authoritative TODO is incomplete; missing IDs: {missing[:25]}")
    return tasks


def discover_specs() -> tuple[Path, Path]:
    candidates = [
        ROOT / "docs/everyday-mode/HOL_GUARD_EVERYDAY_MODE_PRD.md",
        ROOT / "HOL_GUARD_EVERYDAY_MODE_PRD.md",
    ]
    prd = next((path for path in candidates if path.exists() and path.stat().st_size > 1000), None)
    candidates = [
        ROOT / "docs/everyday-mode/HOL_GUARD_EVERYDAY_MODE_TODO.md",
        ROOT / "HOL_GUARD_EVERYDAY_MODE_TODO.md",
    ]
    todo = next((path for path in candidates if path.exists() and path.stat().st_size > 10_000), None)
    if prd is None or todo is None:
        raise RuntimeError("validated Everyday Mode PRD/TODO files are not present")
    return prd, todo


def endpoint_candidates() -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if openai_key:
        endpoints.append(
            Endpoint(
                "https://api.openai.com/v1/chat/completions",
                openai_key,
                tuple(
                    filter(
                        None,
                        (
                            os.environ.get("OPENAI_MODEL", "").strip(),
                            "gpt-5.2-codex",
                            "gpt-5.1-codex",
                            "gpt-5",
                            "gpt-4.1",
                        ),
                    )
                ),
            )
        )
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if github_token:
        endpoints.append(
            Endpoint(
                "https://models.github.ai/inference/chat/completions",
                github_token,
                tuple(
                    filter(
                        None,
                        (
                            os.environ.get("GITHUB_MODELS_MODEL", "").strip(),
                            "openai/gpt-5.2-codex",
                            "openai/gpt-5.1-codex",
                            "openai/gpt-5",
                            "openai/gpt-4.1",
                            "xai/grok-code-fast-1",
                            "anthropic/claude-sonnet-4.5",
                        ),
                    )
                ),
            )
        )
    if not endpoints:
        raise RuntimeError("no supported inference credential is available")
    return endpoints


def post_json(endpoint: Endpoint, model: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps({"model": model, **payload}).encode("utf-8")
    request = Request(
        endpoint.url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {endpoint.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "hol-guard-everyday-mode-agent/1",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    try:
        with urlopen(request, timeout=300) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {_trim(detail, 4000)}") from exc
    except URLError as exc:
        raise RuntimeError(f"inference request failed: {exc}") from exc


TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "List repository files matching a glob. Excludes .git and generated dependency directories.",
            "parameters": {
                "type": "object",
                "properties": {"glob": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 500}},
                "required": ["glob"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a UTF-8 repository file, optionally by one-indexed line range.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Search repository text with ripgrep and return bounded matches.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "glob": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                },
                "required": ["pattern"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Create or replace a UTF-8 repository file. Parent directories are created.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "apply_patch",
            "description": "Apply a unified git patch to the working tree. Use repository-relative paths.",
            "parameters": {
                "type": "object",
                "properties": {"patch": {"type": "string"}},
                "required": ["patch"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a bounded, allowlisted repository inspection, formatter, build, or test command.",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}, "timeout": {"type": "integer", "minimum": 1, "maximum": 1800}},
                "required": ["command"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_diff",
            "description": "Show the current git diff and status, optionally limited to a path.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "additionalProperties": False,
            },
        },
    },
]


def tool_list_files(arguments: dict[str, Any]) -> str:
    pattern = arguments["glob"]
    limit = min(int(arguments.get("limit", 200)), 500)
    excluded = {".git", ".venv", "node_modules", "dist", "build", ".next", "target"}
    values: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in excluded for part in path.relative_to(ROOT).parts):
            continue
        relative = path.relative_to(ROOT).as_posix()
        if fnmatch.fnmatch(relative, pattern):
            values.append(relative)
            if len(values) >= limit:
                break
    return "\n".join(sorted(values))


def tool_read_file(arguments: dict[str, Any]) -> str:
    path = _inside_root(Path(arguments["path"]))
    if not path.is_file():
        raise FileNotFoundError(path.relative_to(ROOT))
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file is too large for one read ({path.stat().st_size} bytes); provide a line range")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(int(arguments.get("start_line", 1)), 1)
    end = min(int(arguments.get("end_line", len(lines))), len(lines))
    if end < start:
        return ""
    return "\n".join(f"{index}: {lines[index - 1]}" for index in range(start, end + 1))


def tool_search(arguments: dict[str, Any]) -> str:
    pattern = arguments["pattern"]
    limit = min(int(arguments.get("limit", 200)), 500)
    argv = ["rg", "--line-number", "--no-heading", "--color", "never", "--glob", "!.git/**", "--glob", "!node_modules/**", "--glob", "!.venv/**"]
    if arguments.get("glob"):
        argv += ["--glob", arguments["glob"]]
    argv += [pattern, "."]
    result = _run(argv, timeout=120)
    lines = result.stdout.splitlines()[:limit]
    return "\n".join(lines) if lines else "<no matches>"


def tool_write_file(arguments: dict[str, Any]) -> str:
    path = _inside_root(Path(arguments["path"]))
    if ".git" in path.relative_to(ROOT).parts:
        raise ValueError("cannot write .git")
    content = arguments["content"]
    if len(content.encode("utf-8")) > 1_000_000:
        raise ValueError("single write exceeds 1 MB")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"wrote {path.relative_to(ROOT)} ({len(content)} chars)"


def tool_apply_patch(arguments: dict[str, Any]) -> str:
    patch = arguments["patch"]
    if len(patch.encode("utf-8")) > 2_000_000:
        raise ValueError("patch exceeds 2 MB")
    process = subprocess.run(
        ["git", "apply", "--3way", "--whitespace=fix", "-"],
        cwd=ROOT,
        input=patch,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    if process.returncode != 0:
        raise RuntimeError(_trim(process.stdout))
    return _trim(process.stdout or "patch applied")


ALLOWED_COMMAND_PREFIXES = (
    "git status",
    "git diff",
    "git grep",
    "rg ",
    "find ",
    "python ",
    "python3 ",
    ".venv/bin/python ",
    ".venv/bin/pytest ",
    ".venv/bin/ruff ",
    "uv ",
    "bun ",
    "bunx ",
    "npm test",
    "npm run ",
    "cargo test",
    "cargo check",
    "go test",
)
FORBIDDEN_TOKENS = ("git push", "gh ", "curl ", "wget ", "sudo ", "rm -rf /", "mkfs", ">/dev/", "ssh ")


def tool_run_command(arguments: dict[str, Any]) -> str:
    command = arguments["command"].strip()
    if any(token in command for token in FORBIDDEN_TOKENS):
        raise ValueError("command contains a forbidden token")
    segments = [segment.strip() for segment in re.split(r"&&|;", command) if segment.strip()]
    if not segments or any(not segment.startswith(ALLOWED_COMMAND_PREFIXES) for segment in segments):
        raise ValueError(f"command is outside the allowlist: {command}")
    timeout = min(int(arguments.get("timeout", 900)), 1800)
    result = _run(["bash", "-lc", command], timeout=timeout)
    return f"exit={result.returncode}\n{_trim(result.stdout)}"


def tool_git_diff(arguments: dict[str, Any]) -> str:
    path = arguments.get("path")
    argv = ["git", "diff", "--stat", "&&", "git", "status", "--short", "&&", "git", "diff", "--"]
    if path:
        _inside_root(Path(path))
        argv.append(path)
    return tool_run_command({"command": " ".join(shlex.quote(part) for part in argv), "timeout": 180})


TOOL_HANDLERS = {
    "list_files": tool_list_files,
    "read_file": tool_read_file,
    "search": tool_search,
    "write_file": tool_write_file,
    "apply_patch": tool_apply_patch,
    "run_command": tool_run_command,
    "git_diff": tool_git_diff,
}


def execute_tool(name: str, raw_arguments: str) -> str:
    try:
        arguments = json.loads(raw_arguments or "{}")
        handler = TOOL_HANDLERS[name]
        return _trim(handler(arguments))
    except Exception as exc:  # noqa: BLE001 - report bounded tool errors to the agent
        return f"ERROR: {type(exc).__name__}: {_trim(str(exc), 8000)}"


def choose_endpoint() -> tuple[Endpoint, str]:
    probe = {
        "messages": [{"role": "user", "content": "Reply with exactly READY."}],
        "max_tokens": 16,
        "temperature": 0,
    }
    failures: list[str] = []
    for endpoint in endpoint_candidates():
        for model in endpoint.models:
            for attempt in range(2):
                try:
                    response = post_json(endpoint, model, probe)
                    if response.get("choices"):
                        return endpoint, model
                    failures.append(f"{model}: response had no choices")
                    break
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"{model}: {exc}")
                    if "429" in str(exc) and attempt == 0:
                        time.sleep(30)
                        continue
                    break
    raise RuntimeError("no inference model was available:\n" + "\n".join(failures[-12:]))


def call_agent(endpoint: Endpoint, model: str, messages: list[dict[str, Any]]) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(6):
        try:
            response = post_json(
                endpoint,
                model,
                {
                    "messages": messages,
                    "tools": TOOLS,
                    "tool_choice": "auto",
                    "temperature": 0.1,
                    "max_tokens": 16_000,
                },
            )
            return response["choices"][0]["message"]
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if "429" not in str(exc) and "5" not in str(exc)[:8]:
                raise
            time.sleep(min(30 * (attempt + 1), 180))
    raise RuntimeError(f"inference failed after retries: {last_error}")


def run_session(
    endpoint: Endpoint,
    model: str,
    *,
    prd_text: str,
    task_text: str,
    start: int,
    end: int,
    review_text: str,
    max_turns: int,
) -> None:
    system = """You are the principal engineer completing HOL Guard Everyday Mode on release/3.2.
Work directly through the supplied repository tools. Implement production behavior, not placeholders or task-marker comments. Reuse correct existing architecture. Preserve fail-closed security semantics, local-first privacy, backwards-compatible wire contracts, deterministic migrations, and accessible dashboard behavior. Do not weaken tests, quality gates, authorization, policy floors, or redaction. Refactor instead of expanding already-oversized modules where feasible. Every completed task needs concrete implementation and tests. Update docs/everyday-mode/completion-ledger.json with one record per EVM ID in this assigned range containing status=verified, files, tests, and a concise evidence statement. Never create GitHub issues. Never claim completion until tests and the diff support it."""
    user = f"""Implement and verify EVM-{start:03d} through EVM-{end:03d} end to end.

AUTHORITATIVE PRD (complete product constraints):
{prd_text}

AUTHORITATIVE TODO SECTIONS FOR THIS RANGE:
{task_text}

OPEN REVIEW THREADS OR PRIOR REVIEW FINDINGS:
{review_text or '<none supplied>'}

Start by auditing existing implementation and the ledger. Use repository tools to inspect, edit, format, and test. Continue until every assigned ID is genuinely implemented and verified. Finish by showing git_diff and running the narrowest meaningful tests plus any affected build/type checks."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    idle_finishes = 0
    for _turn in range(max_turns):
        message = call_agent(endpoint, model, messages)
        tool_calls = message.get("tool_calls") or []
        messages.append(message)
        if tool_calls:
            idle_finishes = 0
            for call in tool_calls:
                function = call.get("function", {})
                name = function.get("name", "")
                result = execute_tool(name, function.get("arguments", "{}")) if name in TOOL_HANDLERS else f"ERROR: unknown tool {name}"
                messages.append({"role": "tool", "tool_call_id": call.get("id", name), "content": result})
            continue
        content = (message.get("content") or "").strip()
        diff = _run(["git", "status", "--porcelain"], timeout=60).stdout.strip()
        if diff and not re.search(r"\b(cannot|unable|blocked|incomplete|remaining|not implemented)\b", content, re.I):
            return
        idle_finishes += 1
        if idle_finishes >= 3:
            raise RuntimeError(f"agent stopped without a verified working-tree change: {_trim(content, 8000)}")
        messages.append(
            {
                "role": "user",
                "content": "Do not stop at a report. Continue using the tools to implement the assigned range, add tests and ledger evidence, and verify the diff.",
            }
        )
    raise RuntimeError(f"agent exceeded {max_turns} turns for EVM-{start:03d}..EVM-{end:03d}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("--review-file", type=Path)
    parser.add_argument("--max-turns", type=int, default=100)
    args = parser.parse_args()
    if not (1 <= args.start <= args.end <= 740):
        parser.error("range must be within 1..740")

    prd_path, todo_path = discover_specs()
    tasks = parse_tasks(todo_path)
    task_text = "\n\n".join(tasks[number] for number in range(args.start, args.end + 1))
    prd_text = prd_path.read_text(encoding="utf-8")
    if len(prd_text) > 120_000:
        prd_text = prd_text[:120_000]
    review_text = ""
    if args.review_file and args.review_file.exists():
        review_text = args.review_file.read_text(encoding="utf-8", errors="replace")[:80_000]

    endpoint, model = choose_endpoint()
    print(f"Using {endpoint.url} model {model}", flush=True)
    run_session(
        endpoint,
        model,
        prd_text=prd_text,
        task_text=task_text,
        start=args.start,
        end=args.end,
        review_text=review_text,
        max_turns=args.max_turns,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
