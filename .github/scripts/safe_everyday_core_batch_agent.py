#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path.cwd().resolve()
MAX_OUTPUT = 32000
EXCLUDED = {".git", ".venv", "node_modules", "target", "dist", "build"}
ALLOWED_PREFIXES = (
    "src/codex_plugin_scanner/guard/",
    "dashboard/src/",
    "tests/",
    "docs/guard/",
    "schemas/",
)
COMMAND_RESULTS: dict[str, int] = {}
ACTIVE_START = 1
ACTIVE_END = 740


def trim(value: str) -> str:
    if len(value) <= MAX_OUTPUT:
        return value
    return value[:16000] + "\n...truncated...\n" + value[-16000:]


def repo_path(value: str) -> Path:
    path = (ROOT / value).resolve()
    if path != ROOT and ROOT not in path.parents:
        raise ValueError("path escapes repository")
    return path


def writable_path(value: str) -> Path:
    normalized = value.replace("\\", "/").lstrip("./")
    if not normalized.startswith(ALLOWED_PREFIXES):
        raise ValueError(f"write outside Everyday Mode product roots: {value}")
    if normalized.startswith(".github/") or normalized.endswith(("pyproject.toml", "package.json", "bun.lock", "uv.lock")):
        raise ValueError("workflow, manifest, lock, and quality authority is immutable")
    return repo_path(normalized)


def scrubbed_env() -> dict[str, str]:
    keep = {"PATH", "HOME", "USER", "SHELL", "TMPDIR", "CI", "BUN_INSTALL", "UV_CACHE_DIR"}
    result = {key: value for key, value in os.environ.items() if key in keep}
    result["CI"] = "1"
    return result


def run(argv: list[str], timeout: int = 1800) -> tuple[int, str]:
    completed = subprocess.run(
        argv,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        env=scrubbed_env(),
    )
    return completed.returncode, trim(completed.stdout)


def parse_tasks(path: Path) -> dict[int, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    pattern = re.compile(r"(?m)^.*?\bEVM-(\d{3})\b.*$")
    matches = list(pattern.finditer(text))
    by_number: dict[int, list[str]] = {}
    for index, match in enumerate(matches):
        number = int(match.group(1))
        if not 1 <= number <= 740:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        section = text[match.start():end].strip()
        by_number.setdefault(number, []).append(section)
    tasks = {number: max(values, key=len) for number, values in by_number.items()}
    missing = sorted(set(range(1, 741)) - set(tasks))
    if missing:
        raise RuntimeError(f"authoritative TODO is missing IDs: {missing[:40]}")
    return tasks


def list_files(args: dict[str, Any]) -> str:
    pattern = str(args.get("glob", "**/*"))
    limit = min(int(args.get("limit", 400)), 1000)
    values: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED for part in relative.parts):
            continue
        value = relative.as_posix()
        if fnmatch.fnmatch(value, pattern):
            values.append(value)
            if len(values) >= limit:
                break
    return "\n".join(sorted(values)) or "<none>"


def read_file(args: dict[str, Any]) -> str:
    path = repo_path(str(args["path"]))
    if not path.is_file():
        raise FileNotFoundError(path)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, int(args.get("start_line", 1)))
    end = min(len(lines), int(args.get("end_line", min(len(lines), start + 399))))
    return trim("\n".join(f"{index}: {lines[index - 1]}" for index in range(start, end + 1)))


def search(args: dict[str, Any]) -> str:
    argv = ["rg", "--line-number", "--no-heading", "--color", "never"]
    if args.get("glob"):
        argv += ["--glob", str(args["glob"])]
    argv += [str(args["pattern"]), "."]
    code, output = run(argv, 120)
    if code not in (0, 1):
        raise RuntimeError(output)
    return output or "<no matches>"


def write_file(args: dict[str, Any]) -> str:
    path = writable_path(str(args["path"]))
    content = str(args["content"])
    if len(content.encode()) > 1000000:
        raise ValueError("single write too large")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"wrote {path.relative_to(ROOT)}"


def delete_file(args: dict[str, Any]) -> str:
    path = writable_path(str(args["path"]))
    if path.is_file():
        path.unlink()
    return f"deleted {path.relative_to(ROOT)}"


VALIDATIONS: dict[str, list[str]] = {
    "ruff": ["uv", "run", "--no-sync", "ruff", "check", "src/codex_plugin_scanner/guard", "tests/test_guard_presentation_mode.py", "tests/test_guard_action_explanation_contract.py", "tests/test_guard_codex_browser_authority.py"],
    "pytest_core": ["uv", "run", "--no-sync", "pytest", "-q", "tests/test_guard_presentation_mode.py", "tests/test_guard_action_explanation_contract.py", "tests/test_guard_codex_browser_authority.py", "tests/test_guard_settings_api.py", "tests/test_guard_desktop_contract.py"],
    "decision_diff": ["uv", "run", "--no-sync", "python", "tests/guard_command_decision_diff.py", "--check"],
    "dashboard_test": ["bash", "-lc", "cd dashboard && bun run test"],
    "dashboard_build": ["bash", "-lc", "cd dashboard && bun run build"],
    "git_diff": ["git", "diff", "--stat"],
}


def run_validation(args: dict[str, Any]) -> str:
    name = str(args["name"])
    if name not in VALIDATIONS:
        raise ValueError(f"unknown validation: {name}")
    code, output = run(VALIDATIONS[name])
    COMMAND_RESULTS[name] = code
    return f"exit={code}\n{output}"


def ledger_path() -> Path:
    path = ROOT / "docs/guard/everyday-mode/completion-ledger.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def load_ledger() -> dict[str, Any]:
    path = ledger_path()
    if not path.exists():
        return {"schema_version": 1, "target": "release/3.2", "tasks": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {"schema_version": 1, "target": "release/3.2", "tasks": data}
    data.setdefault("tasks", [])
    return data


def record_task_evidence(args: dict[str, Any]) -> str:
    ledger = load_ledger()
    rows = {str(row.get("id")): row for row in ledger["tasks"] if isinstance(row, dict)}
    accepted: list[str] = []
    for entry in args["entries"]:
        task_id = str(entry["id"])
        match = re.fullmatch(r"EVM-(\d{3})", task_id)
        if not match:
            raise ValueError(f"invalid task ID: {task_id}")
        number = int(match.group(1))
        if not ACTIVE_START <= number <= ACTIVE_END:
            raise ValueError(f"task outside active batch: {task_id}")
        files = [str(value) for value in entry["files"]]
        if not files or any(not repo_path(value).exists() for value in files):
            raise ValueError(f"task references missing implementation files: {task_id}")
        tests = [str(value) for value in entry["tests"]]
        if not tests or any(COMMAND_RESULTS.get(value) != 0 for value in tests):
            raise ValueError(f"task references validations that did not pass in this session: {task_id}")
        evidence = str(entry["evidence"]).strip()
        if len(evidence) < 24:
            raise ValueError(f"evidence is too short: {task_id}")
        rows[task_id] = {"id": task_id, "status": "verified", "files": files, "tests": tests, "evidence": evidence}
        accepted.append(task_id)
    ledger["tasks"] = [rows[key] for key in sorted(rows)]
    ledger_path().write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
    return "recorded " + ", ".join(accepted)


TOOLS = [
    {"type":"function","function":{"name":"list_files","description":"List repository files.","parameters":{"type":"object","properties":{"glob":{"type":"string"},"limit":{"type":"integer"}},"required":["glob"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"read_file","description":"Read a repository file by line range.","parameters":{"type":"object","properties":{"path":{"type":"string"},"start_line":{"type":"integer"},"end_line":{"type":"integer"}},"required":["path"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"search","description":"Search repository text.","parameters":{"type":"object","properties":{"pattern":{"type":"string"},"glob":{"type":"string"}},"required":["pattern"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"write_file","description":"Write only Everyday Mode Core, dashboard, test, schema, or documentation files.","parameters":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"delete_file","description":"Delete only Everyday Mode product files.","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"run_validation","description":"Run a predefined credential-free validation.","parameters":{"type":"object","properties":{"name":{"type":"string","enum":sorted(VALIDATIONS)}},"required":["name"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"record_task_evidence","description":"Record verified evidence for assigned EVM tasks. Files must exist and named validations must have passed in this session.","parameters":{"type":"object","properties":{"entries":{"type":"array","minItems":1,"maxItems":30,"items":{"type":"object","properties":{"id":{"type":"string","pattern":"^EVM-[0-9]{3}$"},"files":{"type":"array","minItems":1,"items":{"type":"string"}},"tests":{"type":"array","minItems":1,"items":{"type":"string"}},"evidence":{"type":"string","minLength":24}},"required":["id","files","tests","evidence"],"additionalProperties":False}}},"required":["entries"],"additionalProperties":False}}},
]
HANDLERS = {"list_files": list_files, "read_file": read_file, "search": search, "write_file": write_file, "delete_file": delete_file, "run_validation": run_validation, "record_task_evidence": record_task_evidence}


def request_model(messages: list[dict[str, Any]]) -> dict[str, Any]:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError("GITHUB_TOKEN unavailable")
    candidates = [os.environ.get("GITHUB_MODELS_MODEL", ""), "openai/gpt-5", "openai/gpt-4.1", "xai/grok-code-fast-1"]
    errors: list[str] = []
    for model in dict.fromkeys(value for value in candidates if value):
        payload = json.dumps({"model": model, "messages": messages, "tools": TOOLS, "tool_choice": "auto", "temperature": 0.1, "max_tokens": 14000}).encode()
        request = Request("https://models.github.ai/inference/chat/completions", data=payload, method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "hol-everyday-core-batch-agent"})
        try:
            with urlopen(request, timeout=300) as response:
                return json.load(response)["choices"][0]["message"]
        except HTTPError as exc:
            errors.append(f"{model}: HTTP {exc.code} {exc.read().decode(errors='replace')[:1200]}")
            if exc.code == 429:
                time.sleep(30)
        except Exception as exc:
            errors.append(f"{model}: {exc}")
    raise RuntimeError("No model available: " + " | ".join(errors))


def verified_ids(start: int, end: int) -> set[str]:
    return {
        str(row.get("id"))
        for row in load_ledger()["tasks"]
        if isinstance(row, dict)
        and row.get("status") == "verified"
        and re.fullmatch(r"EVM-\d{3}", str(row.get("id", "")))
        and start <= int(str(row["id"])[4:]) <= end
    }


def main() -> int:
    global ACTIVE_START, ACTIVE_END
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("--max-turns", type=int, default=160)
    args = parser.parse_args()
    if not 1 <= args.start <= args.end <= 740:
        parser.error("range must be within 1..740")
    ACTIVE_START, ACTIVE_END = args.start, args.end

    prd = Path("docs/guard/everyday-mode/HOL_GUARD_EVERYDAY_MODE_PRD.md")
    todo = Path("docs/guard/everyday-mode/HOL_GUARD_EVERYDAY_MODE_TODO.md")
    if not prd.is_file() or prd.stat().st_size < 1000 or not todo.is_file() or todo.stat().st_size < 10000:
        raise RuntimeError("authoritative PRD/TODO files are unavailable")
    tasks = parse_tasks(todo)
    task_text = "\n\n".join(tasks[number] for number in range(args.start, args.end + 1))
    prd_text = prd.read_text(encoding="utf-8", errors="replace")
    headings = "\n".join(line for line in prd_text.splitlines() if line.lstrip().startswith("#"))
    prd_context = trim("\n".join(prd_text.splitlines()[:220]) + "\n\nPRD OUTLINE\n" + headings)

    system = """You are the principal engineer completing HOL Guard Core Everyday Mode on release/3.2. Implement every assigned EVM task through real production code, tests, schemas, migrations, accessible dashboard behavior, documentation, or verifiable contract evidence as appropriate. Never use placeholders, task-marker comments, or weakened tests. Presentation mode changes wording and detail only; it never changes policy, enforcement, approval eligibility, authorization, retention, receipts, entitlements, extension authority, or fail-closed behavior. Core alone owns semantic explanations. Preserve deterministic migrations, strict schemas, revision/CAS semantics, redaction, Python/TypeScript parity, limited-confidence handling, local-first privacy, and backwards compatibility. Do not modify workflows, manifests, lockfiles, or quality floors. Use record_task_evidence only after cited files exist and cited validations passed during this session. Do not stop until every assigned task has verified evidence."""
    user = f"""Complete EVM-{args.start:03d} through EVM-{args.end:03d} end to end.

Authoritative PRD context:
{prd_context}

Authoritative TODO sections:
{trim(task_text)}

Audit the current implementation and completion ledger first. Reuse correct architecture. Implement missing behavior and tests, run the predefined validations, record evidence for every assigned EVM ID, inspect the diff, and continue until the entire range is verified."""
    messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    expected = {f"EVM-{number:03d}" for number in range(args.start, args.end + 1)}
    for turn in range(args.max_turns):
        reply = request_model(messages)
        messages.append(reply)
        calls = reply.get("tool_calls") or []
        if calls:
            for call in calls:
                function = call.get("function") or {}
                name = function.get("name", "")
                try:
                    result = HANDLERS[name](json.loads(function.get("arguments") or "{}")) if name in HANDLERS else f"ERROR: unknown tool {name}"
                except Exception as exc:
                    result = f"ERROR: {type(exc).__name__}: {exc}"
                messages.append({"role": "tool", "tool_call_id": call.get("id", f"call-{turn}"), "content": trim(result)})
            continue
        missing = sorted(expected - verified_ids(args.start, args.end))
        if not missing:
            return 0
        messages.append({"role": "user", "content": "Continue using tools. These assigned tasks still lack tool-verified evidence: " + ", ".join(missing[:50]) + (" ..." if len(missing) > 50 else "")})
    missing = sorted(expected - verified_ids(args.start, args.end))
    raise RuntimeError(f"agent turn limit reached; unverified tasks: {missing[:60]}")


if __name__ == "__main__":
    raise SystemExit(main())
