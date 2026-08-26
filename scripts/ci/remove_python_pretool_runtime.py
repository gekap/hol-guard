#!/usr/bin/env python3
"""Remove obsolete Python live PreToolUse compatibility code after native cutover."""

from __future__ import annotations

import re
from pathlib import Path


def function_span(source: str, name: str) -> tuple[int, int] | None:
    match = re.search(rf"(?m)^def {re.escape(name)}\(", source)
    if match is None:
        return None
    start = match.start()
    next_match = re.search(r"(?m)^(?:async )?def |^class |^__all__\s*=", source[match.end() :])
    end = len(source) if next_match is None else match.end() + next_match.start()
    return start, end


def remove_functions(source: str, names: tuple[str, ...]) -> str:
    while True:
        spans = [span for name in names if (span := function_span(source, name)) is not None]
        if not spans:
            return source
        start, end = min(spans, key=lambda item: item[0])
        source = source[:start].rstrip() + "\n\n" + source[end:].lstrip("\n")


def clean_native_command_model() -> None:
    path = Path("src/codex_plugin_scanner/guard/native_command_model.py")
    if not path.exists():
        return
    source = path.read_text(encoding="utf-8")
    source = remove_functions(
        source,
        (
            "_decode_pre_tool",
            "review_pre_tool_native",
            "native_pre_tool_native",
        ),
    )
    source = re.sub(
        r"(?m)^from \.runtime\.command_evaluation import evaluate_command\n",
        "",
        source,
    )
    source = re.sub(r"(?m)^_PRETOOL_[A-Z0-9_]+\s*=.*\n", "", source)
    source = source.replace('    "review_pre_tool_native",\n', "")
    source = source.replace('    "native_pre_tool_native",\n', "")
    span = function_span(source, "native_command_shadow_proposal")
    if span is not None:
        start, end = span
        replacement = '''def native_command_shadow_proposal(*args: object, **kwargs: object) -> None:
    """Retired after direct-native PreToolUse cutover."""

    del args, kwargs
    return None

'''
        source = source[:start] + replacement + source[end:].lstrip("\n")
    path.write_text(source, encoding="utf-8")


def clean_hook_worker() -> None:
    path = Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py")
    source = path.read_text(encoding="utf-8")
    source = re.sub(
        r"(?m)^from \.\.native_command_model import review_pre_tool_native\n",
        "",
        source,
    )
    branch = re.compile(
        r'''(?ms)^        if event_name == ["']PreToolUse["']:\n.*?(?=^        if event_name != ["']PostToolUse["']:)'''
    )
    source, _count = branch.subn("", source, count=1)
    source = remove_functions(
        source,
        (
            "_pre_tool_command",
            "_harness_json_from_native_pre_tool",
        ),
    )
    source = source.replace(
        "fast path supports PreToolUse and PostToolUse",
        "fast path supports PostToolUse",
    )
    path.write_text(source, encoding="utf-8")


def main() -> int:
    clean_native_command_model()
    clean_hook_worker()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
