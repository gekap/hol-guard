#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path.cwd().resolve()
ALLOWED_PREFIXES = (
    "src/codex_plugin_scanner/guard/",
    "dashboard/src/",
    "tests/",
    "docs/guard/",
    "schemas/",
)
EXCLUDED = {".git", ".venv", "node_modules", "target", "dist", "build"}
MAX_OUTPUT = 32000


def trim(value: str) -> str:
    return value if len(value) <= MAX_OUTPUT else value[:16000] + "\n...truncated...\n" + value[-16000:]


def clean(value: str) -> Path:
    path = (ROOT / value).resolve()
    if path != ROOT and ROOT not in path.parents:
        raise ValueError("path escapes repository")
    return path


def writable(value: str) -> Path:
    normalized = value.replace("\\", "/").lstrip("./")
    if not normalized.startswith(ALLOWED_PREFIXES):
        raise ValueError(f"write outside Everyday product roots: {value}")
    if normalized.startswith(".github/") or normalized.endswith(("pyproject.toml", "package.json", "bun.lock", "uv.lock")):
        raise ValueError("workflow, manifest, and lock authority is immutable")
    return clean(normalized)


def env() -> dict[str, str]:
    keep = {"PATH", "HOME", "USER", "SHELL", "TMPDIR", "CI", "BUN_INSTALL", "UV_CACHE_DIR"}
    result = {key: value for key, value in os.environ.items() if key in keep}
    result["CI"] = "1"
    return result


def run(argv: list[str], timeout: int = 1800) -> tuple[int, str]:
    done = subprocess.run(argv, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env())
    return done.returncode, trim(done.stdout)


def list_files(args: dict[str, Any]) -> str:
    pattern = str(args.get("glob", "**/*"))
    limit = min(int(args.get("limit", 400)), 1000)
    values: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDED for part in rel.parts):
            continue
        value = rel.as_posix()
        if fnmatch.fnmatch(value, pattern):
            values.append(value)
            if len(values) >= limit:
                break
    return "\n".join(sorted(values)) or "<none>"


def read_file(args: dict[str, Any]) -> str:
    path = clean(str(args["path"]))
    if not path.is_file():
        raise FileNotFoundError(path)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, int(args.get("start_line", 1)))
    end = min(len(lines), int(args.get("end_line", min(len(lines), start + 399))))
    return trim("\n".join(f"{i}: {lines[i-1]}" for i in range(start, end + 1)))


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
    path = writable(str(args["path"]))
    content = str(args["content"])
    if len(content.encode()) > 1000000:
        raise ValueError("single write too large")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"wrote {path.relative_to(ROOT)}"


def delete_file(args: dict[str, Any]) -> str:
    path = writable(str(args["path"]))
    if path.is_file():
        path.unlink()
    return f"deleted {path.relative_to(ROOT)}"


VALIDATIONS = {
    "ruff": ["uv", "run", "--no-sync", "ruff", "check", "src/codex_plugin_scanner/guard", "tests/test_guard_presentation_mode.py", "tests/test_guard_action_explanation_contract.py", "tests/test_guard_codex_browser_authority.py"],
    "pytest": ["uv", "run", "--no-sync", "pytest", "-q", "tests/test_guard_presentation_mode.py", "tests/test_guard_action_explanation_contract.py", "tests/test_guard_codex_browser_authority.py", "tests/test_guard_settings_api.py", "tests/test_guard_desktop_contract.py"],
    "decision_diff": ["uv", "run", "--no-sync", "python", "tests/guard_command_decision_diff.py", "--check"],
    "dashboard_test": ["bun", "run", "--cwd", "dashboard", "test"],
    "dashboard_build": ["bun", "run", "--cwd", "dashboard", "build"],
    "git_diff": ["git", "diff", "--stat"],
}


def validation(args: dict[str, Any]) -> str:
    name = str(args["name"])
    if name not in VALIDATIONS:
        raise ValueError(f"unknown validation {name}")
    code, output = run(VALIDATIONS[name])
    return f"exit={code}\n{output}"


TOOLS = [
    {"type":"function","function":{"name":"list_files","description":"List repository files.","parameters":{"type":"object","properties":{"glob":{"type":"string"},"limit":{"type":"integer"}},"required":["glob"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"read_file","description":"Read a repository file by line range.","parameters":{"type":"object","properties":{"path":{"type":"string"},"start_line":{"type":"integer"},"end_line":{"type":"integer"}},"required":["path"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"search","description":"Search repository text.","parameters":{"type":"object","properties":{"pattern":{"type":"string"},"glob":{"type":"string"}},"required":["pattern"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"write_file","description":"Write only Everyday Mode Core, dashboard, test, schema, or documentation paths.","parameters":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"delete_file","description":"Delete only Everyday Mode product paths.","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":False}}},
    {"type":"function","function":{"name":"run_validation","description":"Run a predefined credential-free validation.","parameters":{"type":"object","properties":{"name":{"type":"string","enum":sorted(VALIDATIONS)}},"required":["name"],"additionalProperties":False}}},
]
HANDLERS = {"list_files":list_files,"read_file":read_file,"search":search,"write_file":write_file,"delete_file":delete_file,"run_validation":validation}


def model(messages: list[dict[str, Any]]) -> dict[str, Any]:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError("GITHUB_TOKEN unavailable")
    candidates = [os.environ.get("GITHUB_MODELS_MODEL", ""), "openai/gpt-5", "openai/gpt-4.1", "xai/grok-code-fast-1"]
    errors: list[str] = []
    for name in dict.fromkeys(x for x in candidates if x):
        body = json.dumps({"model":name,"messages":messages,"tools":TOOLS,"tool_choice":"auto","temperature":0.1,"max_tokens":14000}).encode()
        request = Request("https://models.github.ai/inference/chat/completions", data=body, method="POST", headers={"Authorization":f"Bearer {token}","Content-Type":"application/json","User-Agent":"hol-everyday-core-agent"})
        try:
            with urlopen(request, timeout=300) as response:
                return json.load(response)["choices"][0]["message"]
        except HTTPError as exc:
            errors.append(f"{name}: HTTP {exc.code} {exc.read().decode(errors='replace')[:1200]}")
            if exc.code == 429:
                time.sleep(30)
        except Exception as exc:
            errors.append(f"{name}: {exc}")
    raise RuntimeError("No model available: " + " | ".join(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=Path)
    parser.add_argument("--max-turns", type=int, default=160)
    args = parser.parse_args()
    findings = args.findings.read_text(errors="replace")[:70000] if args.findings and args.findings.exists() else ""
    system = """You are the principal engineer completing HOL Guard Core Everyday Mode on release/3.2. Work directly through repository tools. Implement production behavior and regression tests, not placeholders. Presentation mode changes wording and detail only; it never changes policy, enforcement, approval eligibility, authorization, retention, receipts, entitlements, extension authority, or fail-closed behavior. Core alone owns semantic action explanations. Preserve strict schemas, deterministic migrations, explicit revision/CAS handling, redacted Cloud projection, Python/TypeScript parity, unknown-action limited confidence, accessibility, and backwards compatibility. Do not modify workflows, manifests, lockfiles, or quality floors. Continue until all relevant validations pass."""
    user = f"""Repair and complete the current Everyday Mode Core implementation.

Required outcomes:
- persisted everyday/technical preference, explicit-choice semantics, migration/schema versioning, and conflict-safe revision writes;
- strict guard.action-explanation.v1 parser/emitter with deterministic semantic catalog and no side effects or model calls;
- safe summaries, reasons, consequences, confidence, next steps, technical retention/authorization boundaries, and redacted Cloud projection;
- dashboard controls and rendering that consume Core contracts without shell parsing;
- parity between Python and TypeScript resolution, one canonical schema, explicit unsupported/limited-confidence behavior, copy/vocabulary contracts, and regression tests;
- preserve every security/enforcement boundary and current release/3.2 behavior.

Validation failures or review findings supplied as inert data:
{findings or '<none>'}

Inspect the current diff and existing architecture, fix every issue, run predefined validations, and do not stop at a report."""
    messages = [{"role":"system","content":system},{"role":"user","content":user}]
    for turn in range(args.max_turns):
        reply = model(messages)
        messages.append(reply)
        calls = reply.get("tool_calls") or []
        if calls:
            for call in calls:
                fn = call.get("function") or {}
                name = fn.get("name", "")
                try:
                    result = HANDLERS[name](json.loads(fn.get("arguments") or "{}")) if name in HANDLERS else f"ERROR: unknown tool {name}"
                except Exception as exc:
                    result = f"ERROR: {type(exc).__name__}: {exc}"
                messages.append({"role":"tool","tool_call_id":call.get("id",f"call-{turn}"),"content":trim(result)})
            continue
        text = str(reply.get("content") or "")
        changed = subprocess.check_output(["git","status","--porcelain"], cwd=ROOT, text=True).strip()
        if changed and "complete" in text.lower():
            return 0
        messages.append({"role":"user","content":"Continue fixing implementation and tests. Do not stop at a status report; use the tools until validations pass."})
    raise RuntimeError("agent turn limit reached")


if __name__ == "__main__":
    raise SystemExit(main())
