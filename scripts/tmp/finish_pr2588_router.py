from __future__ import annotations

from pathlib import Path


path = Path("src/codex_plugin_scanner/guard/cli/commands_router.py")
text = path.read_text(encoding="utf-8")
old = '''    handler = _resolve_guard_handler(_PRESTORE_HANDLERS, args.guard_command)
    if callable(handler):
        return _invoke_guard_handler(
            handler,
            args,
            guard_home=guard_home,
            workspace=workspace,
            context=context,
            input_text=input_text,
            output_stream=output_stream,
        )

    source = getattr(args, "source", "default")
'''
new = '''    handler = _resolve_guard_handler(_PRESTORE_HANDLERS, args.guard_command)
    if callable(handler):
        return _invoke_guard_handler(
            handler,
            args,
            guard_home=guard_home,
            workspace=workspace,
            context=context,
            input_text=input_text,
            output_stream=output_stream,
        )

    if args.guard_command == "explain" and bool(getattr(args, "explain_as_command", False)):
        handler = _resolve_guard_handler(_COMMON_HANDLERS, args.guard_command)
        return _invoke_guard_handler(
            handler,
            args,
            guard_home=guard_home,
            workspace=workspace,
            context=context,
            input_text=input_text,
            output_stream=output_stream,
        )

    source = getattr(args, "source", "default")
'''
count = text.count(old)
if count != 1:
    raise RuntimeError(f"pre-store semantic explain route: expected one match, found {count}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
