"""Identify user scripts sourced or launched inside compound shell commands."""

from __future__ import annotations

import shlex
from pathlib import Path

from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtensionRegistry
from .command_model import CommandSegment, parse_shell_command
from .command_tokens import executable_name
from .local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli

_SOURCE_BUILTINS = frozenset({".", "source"})
_INLINE_FLAGS = frozenset({"-c", "-lc"})


def identify_unlisted_cli_identities(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> tuple[UnlistedCliIdentity, ...]:
    """Return unlisted CLI identities from a single invocation or compound shell."""

    found: dict[str, UnlistedCliIdentity] = {}

    def add(identity: UnlistedCliIdentity | None) -> None:
        if identity is None:
            return
        found.setdefault(identity.cli_id, identity)

    add(identify_unlisted_cli(command_text, cwd=cwd, home_dir=home_dir, registry=registry))
    try:
        model = parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    except ValueError:
        return tuple(found.values())
    for segment in model.segments:
        add(_identity_from_segment(segment, cwd=cwd, home_dir=home_dir, registry=registry))
    return tuple(found.values())


def _identity_from_segment(
    segment: CommandSegment,
    *,
    cwd: Path,
    home_dir: Path | None,
    registry: CommandSafetyExtensionRegistry,
) -> UnlistedCliIdentity | None:
    exe = executable_name(segment.executable)
    if exe is None:
        return None
    if exe in _SOURCE_BUILTINS and segment.arguments:
        script = _resolve_existing_file(segment.arguments[0], cwd=cwd, home_dir=home_dir)
        if script is None:
            return None
        return identify_unlisted_cli(
            f"bash {shlex.quote(str(script))}",
            cwd=cwd,
            home_dir=home_dir,
            registry=registry,
        )
    if segment.arguments:
        first = segment.arguments[0]
        if first in _INLINE_FLAGS:
            return None
        script = _resolve_existing_file(first, cwd=cwd, home_dir=home_dir)
        if script is not None:
            return identify_unlisted_cli(
                f"{exe} {shlex.quote(str(script))}",
                cwd=cwd,
                home_dir=home_dir,
                registry=registry,
            )
    if segment.executable is None:
        return None
    script = _resolve_existing_file(segment.executable, cwd=cwd, home_dir=home_dir)
    if script is None:
        return None
    return identify_unlisted_cli(shlex.quote(str(script)), cwd=cwd, home_dir=home_dir, registry=registry)


def _resolve_existing_file(value: str, *, cwd: Path, home_dir: Path | None) -> Path | None:
    expanded = value.strip()
    if not expanded:
        return None
    home = (home_dir or Path.home()).expanduser()
    if expanded.startswith("~/"):
        expanded = str(home / expanded[2:])
    path = Path(expanded)
    if not path.is_absolute():
        path = cwd / path
    try:
        resolved = path.expanduser().resolve()
    except OSError:
        return None
    if not resolved.is_file():
        return None
    return resolved
