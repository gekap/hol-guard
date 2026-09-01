"""Structured matchers for option-heavy command-line interfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand, CommandSegment


@final
@dataclass(frozen=True, slots=True)
class LeadingOperandCountMatcher:
    """Match commands with enough operands after documented leading options."""

    executables: frozenset[str]
    minimum_operands: int
    options_with_values: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables:
            raise ValueError("LeadingOperandCountMatcher requires executables")
        if self.minimum_operands < 1:
            raise ValueError("LeadingOperandCountMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            leading_flags, operands = leading_flags_and_operands(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if self.forbidden_flags & leading_flags or len(operands) < self.minimum_operands:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail=f"Matched command with at least {self.minimum_operands} structured operands.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class SubcommandOperandPrefixMatcher:
    """Match prefixed operands for a subcommand without scanning option values."""

    executables: frozenset[str]
    subcommands: tuple[str, ...]
    operand_prefixes: frozenset[str]
    leading_options_with_values: frozenset[str] = frozenset()
    options_with_values: frozenset[str] = frozenset()
    leading_operands_to_skip: int = 0
    options_supplying_leading_operands: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_subcommands = tuple(value.strip().lower() for value in self.subcommands if value.strip())
        normalized_prefixes = frozenset(value for value in self.operand_prefixes if value)
        if not normalized_executables or not normalized_subcommands or not normalized_prefixes:
            raise ValueError("SubcommandOperandPrefixMatcher requires executables, subcommands, and prefixes")
        if self.leading_operands_to_skip < 0:
            raise ValueError("SubcommandOperandPrefixMatcher cannot skip a negative operand count")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "subcommands", normalized_subcommands)
        object.__setattr__(self, "operand_prefixes", normalized_prefixes)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            _flags, leading_operands = leading_flags_and_operands(
                segment.arguments,
                options_with_values=self.leading_options_with_values,
            )
            lowered = tuple(value.lower() for value in leading_operands)
            if lowered[: len(self.subcommands)] != self.subcommands:
                continue
            subcommand_arguments = leading_operands[len(self.subcommands) :]
            operands = _operands_without_options(
                subcommand_arguments,
                options_with_values=self.options_with_values,
            )
            supplied_leading_operands = (
                present_flags(
                    subcommand_arguments,
                    options_with_values=self.options_with_values,
                )
                & self.options_supplying_leading_operands
            )
            if not supplied_leading_operands:
                operands = operands[self.leading_operands_to_skip :]
            if not any(
                len(operand) > len(prefix) and operand.startswith(prefix)
                for operand in operands
                for prefix in self.operand_prefixes
            ):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a structured subcommand operand prefix.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class TrailingOperandPrefixMatcher:
    """Match commands whose final operand carries one of the given prefixes.

    Direction is part of the grammar for copy-style tools: the last operand is
    the destination, so a prefixed *final* operand means data leaving the host,
    while the same prefix in an earlier position is a read. Matching any operand
    would treat a restore exactly like an upload.
    """

    executables: frozenset[str]
    operand_prefixes: frozenset[str]
    options_with_values: frozenset[str] = frozenset()
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    minimum_operands: int = 2
    excluded_first_arguments: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_prefixes = frozenset(value for value in self.operand_prefixes if value)
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_required = frozenset(
            _normalize_option_token(value) for value in self.required_flags if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables or not normalized_prefixes:
            raise ValueError("TrailingOperandPrefixMatcher requires executables and operand prefixes")
        if self.minimum_operands < 1:
            raise ValueError("TrailingOperandPrefixMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "operand_prefixes", normalized_prefixes)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "required_flags", normalized_required)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if _first_argument_is_excluded(segment.arguments, self.excluded_first_arguments):
                continue
            flags = present_flags(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if self.required_flags - flags:
                continue
            if self.forbidden_flags & flags:
                continue
            operands = _operands_without_options(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if len(operands) < self.minimum_operands:
                continue
            destination = operands[-1]
            if not any(
                len(destination) > len(prefix) and destination.startswith(prefix) for prefix in self.operand_prefixes
            ):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a prefixed final operand.",
                )
            )
        return tuple(evidence)


def _is_remote_host_target(operand: str) -> bool:
    """Report whether an operand uses scp-style ``[user@]host:path`` syntax.

    Parsed by hand rather than by regular expression: the grammar is small, and
    a matcher on the review path should not carry backtracking behaviour that
    depends on attacker-influenced operand length.
    """
    if "://" in operand:
        return False  # a scheme, which the prefix matcher already owns
    rest = operand.split("@", 1)[1] if "@" in operand else operand
    if rest.startswith("["):  # bracketed IPv6 literal, e.g. [::1]:/srv
        closing = rest.find("]:")
        return closing > 1 and len(rest) > closing + 2
    separator = rest.find(":")
    if separator <= 0 or separator == len(rest) - 1:
        return False
    host = rest[:separator]
    if any(character.isspace() for character in host):
        return False
    # A single-letter host is a Windows drive (``C:\\backup``), not a remote.
    return not (len(host) == 1 and host.isalpha())


@final
@dataclass(frozen=True, slots=True)
class TrailingOperandHostTargetMatcher:
    """Match commands whose final operand is an scp-style remote host target.

    The companion to :class:`TrailingOperandPrefixMatcher` for tools that accept
    both ``scheme://`` endpoints and ``[user@]host:path``. Direction is read the
    same way: only the last operand is a destination, so an upload matches while
    a download from the same host does not.
    """

    executables: frozenset[str]
    options_with_values: frozenset[str] = frozenset()
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    minimum_operands: int = 2
    excluded_first_arguments: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_required = frozenset(
            _normalize_option_token(value) for value in self.required_flags if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables:
            raise ValueError("TrailingOperandHostTargetMatcher requires executables")
        if self.minimum_operands < 1:
            raise ValueError("TrailingOperandHostTargetMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "required_flags", normalized_required)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if _first_argument_is_excluded(segment.arguments, self.excluded_first_arguments):
                continue
            flags = present_flags(segment.arguments, options_with_values=self.options_with_values)
            if self.required_flags - flags:
                continue
            if self.forbidden_flags & flags:
                continue
            operands = _operands_without_options(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if len(operands) < self.minimum_operands:
                continue
            if not _is_remote_host_target(operands[-1]):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a remote host target as the final operand.",
                )
            )
        return tuple(evidence)


def _first_argument_is_excluded(arguments: tuple[str, ...], excluded: frozenset[str]) -> bool:
    """Report whether the raw first argument names an excluded subcommand.

    Deliberately the *raw* first argument and deliberately case-sensitive: tools
    that dispatch on ``argv[1]`` (blitcp checks ``sys.argv[1] == "creds"``) only
    enter the subcommand when it is literally the first argument with that exact
    spelling. ``tool --flag creds ...`` and ``tool Creds ...`` both fall through
    to the tool's ordinary copy grammar, so the matcher must keep looking at
    them.
    """
    return bool(excluded) and bool(arguments) and arguments[0] in excluded


def _is_remote_alias_target(operand: str, *, allow_bare_names: bool) -> bool:
    """Report whether an operand can name a saved connection (``NAME[:subpath]``).

    Mirrors the acceptor in blitcp's ``resolve_named_endpoint`` exclusion by
    exclusion, so the matcher and the tool read the same operand the same way:

    - an operand with ``://`` is a scheme endpoint, owned by the prefix matcher;
    - a head containing ``@`` is an scp-style target, owned by the host matcher;
    - a single-character head is a Windows drive (``C:\backup``);
    - a head containing a path separator is a local path with a colon in it.

    A bare name (no colon) is only accepted when ``allow_bare_names`` is set:
    without the colon nothing distinguishes a connection name from an ordinary
    relative destination, so callers gate that form on stronger evidence.
    """
    if "://" in operand:
        return False
    head, separator, _tail = operand.partition(":")
    if separator:
        if "@" in head or len(head) <= 1:
            return False
        if "/" in head or "\\" in head:
            return False
        return not any(character.isspace() for character in head)
    if not allow_bare_names:
        return False
    name = operand.rstrip("/").rstrip("\\")
    if len(name) <= 1 or name.startswith("-") or name in {".", ".."}:
        return False
    if "@" in name or "/" in name or "\\" in name:
        return False
    return not any(character.isspace() for character in name)


@final
@dataclass(frozen=True, slots=True)
class TrailingOperandRemoteAliasMatcher:
    """Match commands whose final operand names a saved remote connection.

    The third destination syntax for copy-style tools, next to
    :class:`TrailingOperandPrefixMatcher` (``scheme://``) and
    :class:`TrailingOperandHostTargetMatcher` (``[user@]host:path``): a saved
    connection referenced as ``NAME:subpath`` or, with ``allow_bare_names``, as
    a bare ``NAME``. Direction is read the same way — only the final operand is
    a destination, so a restore from the same alias does not match.
    """

    executables: frozenset[str]
    options_with_values: frozenset[str] = frozenset()
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    minimum_operands: int = 2
    allow_bare_names: bool = False
    excluded_first_arguments: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_required = frozenset(
            _normalize_option_token(value) for value in self.required_flags if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables:
            raise ValueError("TrailingOperandRemoteAliasMatcher requires executables")
        if self.minimum_operands < 1:
            raise ValueError("TrailingOperandRemoteAliasMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "required_flags", normalized_required)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if _first_argument_is_excluded(segment.arguments, self.excluded_first_arguments):
                continue
            flags = present_flags(segment.arguments, options_with_values=self.options_with_values)
            if self.required_flags - flags:
                continue
            if self.forbidden_flags & flags:
                continue
            operands = _operands_without_options(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if len(operands) < self.minimum_operands:
                continue
            if not _is_remote_alias_target(operands[-1], allow_bare_names=self.allow_bare_names):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a saved-connection alias as the final operand.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class OperandGatedFlagMatcher:
    """Match required flags only on commands with enough operands to act.

    A flag like ``--no-verify`` or ``--use-sudo`` describes how a copy runs, so
    on an invocation that copies nothing — ``tool --use-sudo``, a bare help run
    — it describes no risk. Gating the flag on the operand count keeps those
    from prompting, which is what preserves the prompt's signal for the copy
    that matters.
    """

    executables: frozenset[str]
    required_flags: frozenset[str]
    options_with_values: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    minimum_operands: int = 2
    excluded_first_arguments: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_required = frozenset(
            _normalize_option_token(value) for value in self.required_flags if value.strip()
        )
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables or not normalized_required:
            raise ValueError("OperandGatedFlagMatcher requires executables and required flags")
        if self.minimum_operands < 1:
            raise ValueError("OperandGatedFlagMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "required_flags", normalized_required)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if _first_argument_is_excluded(segment.arguments, self.excluded_first_arguments):
                continue
            flags = present_flags(segment.arguments, options_with_values=self.options_with_values)
            if self.required_flags - flags:
                continue
            if self.forbidden_flags & flags:
                continue
            operands = _operands_without_options(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if len(operands) < self.minimum_operands:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail=f"Matched required flags on a command with at least {self.minimum_operands} operands.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class OptionValueKeyMatcher:
    """Match documented option values whose leading key has execution semantics."""

    executables: frozenset[str]
    option_names: frozenset[str]
    value_keys: frozenset[str]
    forbidden_flags: frozenset[str] = frozenset()
    ignored_values: frozenset[str] = frozenset()
    required_key_values: tuple[tuple[str, str], ...] = ()
    cluster_options_with_values: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_options = frozenset(value.strip() for value in self.option_names if value.strip())
        normalized_keys = frozenset(value.strip().lower() for value in self.value_keys if value.strip())
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        normalized_ignored = frozenset(value.strip().lower() for value in self.ignored_values if value.strip())
        normalized_required = tuple(
            (key.strip().lower(), value.strip().lower())
            for key, value in self.required_key_values
            if key.strip() and value.strip()
        )
        if not normalized_executables or not normalized_options or not normalized_keys:
            raise ValueError("OptionValueKeyMatcher requires executables, option names, and value keys")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "option_names", normalized_options)
        object.__setattr__(self, "value_keys", normalized_keys)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)
        object.__setattr__(self, "ignored_values", normalized_ignored)
        object.__setattr__(self, "required_key_values", normalized_required)
        object.__setattr__(
            self,
            "cluster_options_with_values",
            frozenset(value.strip() for value in self.cluster_options_with_values if value.strip()),
        )

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            all_value_options = self.option_names | self.cluster_options_with_values
            matched_flags = present_flags(segment.arguments, options_with_values=all_value_options)
            if self.forbidden_flags & matched_flags:
                continue
            settings: dict[str, str] = {}
            for option_value in _option_values(
                segment.arguments,
                self.option_names,
                cluster_options_with_values=all_value_options,
            ):
                key, value = _split_option_setting(option_value)
                if key:
                    settings.setdefault(key, value)
            if any(settings.get(key) != value for key, value in self.required_key_values):
                continue
            for key in self.value_keys:
                value = settings.get(key)
                if value is None or value in self.ignored_values:
                    continue
                evidence.append(
                    MatcherEvidence(
                        segment_index=index,
                        executable=segment.executable,
                        detail="Matched a structured option value with command execution semantics.",
                    )
                )
                break
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class EnvironmentNameMatcher:
    """Match command-local environment names without retaining their values."""

    executables: frozenset[str]
    environment_names: frozenset[str]

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_names = frozenset(value.strip().upper() for value in self.environment_names if value.strip())
        if not normalized_executables or not normalized_names:
            raise ValueError("EnvironmentNameMatcher requires executables and environment names")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "environment_names", normalized_names)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            present_names = frozenset(name.upper() for name in segment.environment_names)
            if not self.environment_names & present_names:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a command-selecting environment name.",
                )
            )
        return tuple(evidence)


def structured_matcher_index_hints(matcher: CommandMatcher) -> tuple[frozenset[str], frozenset[str]] | None:
    """Return conservative registry hints for matchers in this module."""

    if isinstance(matcher, LeadingOperandCountMatcher):
        return matcher.executables, frozenset()
    if isinstance(matcher, SubcommandOperandPrefixMatcher):
        return matcher.executables, frozenset(matcher.subcommands)
    if isinstance(matcher, TrailingOperandPrefixMatcher):
        return matcher.executables, frozenset()
    if isinstance(matcher, TrailingOperandHostTargetMatcher):
        return matcher.executables, frozenset()
    if isinstance(matcher, OptionValueKeyMatcher):
        return matcher.executables, matcher.option_names
    if isinstance(matcher, EnvironmentNameMatcher):
        return matcher.executables, matcher.environment_names
    return None


def _segment_matches_executable(segment: CommandSegment, executables: frozenset[str]) -> bool:
    if segment.executable is None:
        return False
    executable = segment.executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return executable in executables


def leading_flags_and_operands(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> tuple[frozenset[str], tuple[str, ...]]:
    flags: set[str] = set()
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            index += 1
            break
        if not argument.startswith("-") or argument == "-":
            break
        option_name = _normalize_option_token(argument.split("=", 1)[0])
        flags.add(option_name)
        short_option = argument[:2] if argument.startswith("-") and not argument.startswith("--") else option_name
        clustered_value_option: str | None = None
        clustered_value_attached = False
        if argument.startswith("-") and not argument.startswith("--") and len(argument) > 2:
            for offset, character in enumerate(argument[1:], start=1):
                if not character.isalnum():
                    break
                clustered_flag = f"-{character}"
                flags.add(clustered_flag)
                if clustered_flag in options_with_values:
                    clustered_value_option = clustered_flag
                    clustered_value_attached = offset < len(argument) - 1
                    break
        takes_value = (
            option_name in options_with_values
            or short_option in options_with_values
            or clustered_value_option is not None
        )
        has_attached_value = (
            "=" in argument
            or (
                argument.startswith("-")
                and not argument.startswith("--")
                and short_option in options_with_values
                and len(argument) > 2
            )
            or clustered_value_attached
        )
        if takes_value and not has_attached_value:
            index += 1
        index += 1
    return frozenset(flags), arguments[index:]


def _option_values(
    arguments: tuple[str, ...],
    option_names: frozenset[str],
    *,
    cluster_options_with_values: frozenset[str] | None = None,
) -> tuple[str, ...]:
    values: list[str] = []
    ordered_options = sorted(option_names, key=len, reverse=True)
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        matched_option = next(
            (
                option
                for option in ordered_options
                if argument == option or argument.startswith(f"{option}=") or argument.startswith(option)
            ),
            None,
        )
        clustered_match = _clustered_short_value(
            argument,
            cluster_options_with_values or option_names,
        )
        if matched_option is None:
            if clustered_match is not None:
                option, value = clustered_match
                if option in option_names:
                    if value:
                        values.append(value)
                    elif index + 1 < len(arguments):
                        values.append(arguments[index + 1])
                        index += 2
                        continue
            index += 1
            continue
        if argument == matched_option:
            if index + 1 < len(arguments):
                values.append(arguments[index + 1])
                index += 2
                continue
        elif argument.startswith(f"{matched_option}="):
            values.append(argument[len(matched_option) + 1 :])
        elif matched_option.startswith("-") and not matched_option.startswith("--"):
            values.append(argument[len(matched_option) :])
        index += 1
    return tuple(values)


def _operands_without_options(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> tuple[str, ...]:
    operands: list[str] = []
    index = 0
    parse_options = True
    while index < len(arguments):
        argument = arguments[index]
        if parse_options and argument == "--":
            parse_options = False
            index += 1
            continue
        if parse_options and argument.startswith("-") and argument != "-":
            option_name = _normalize_option_token(argument.split("=", 1)[0])
            clustered_match = _clustered_short_value(argument, options_with_values)
            takes_separate_value = option_name in options_with_values and "=" not in argument
            if clustered_match is not None:
                _option, attached_value = clustered_match
                takes_separate_value = not attached_value
            index += 2 if takes_separate_value else 1
            continue
        operands.append(argument)
        index += 1
    return tuple(operands)


def _clustered_short_value(
    argument: str,
    option_names: frozenset[str],
) -> tuple[str, str] | None:
    if not argument.startswith("-") or argument.startswith("--") or len(argument) <= 2:
        return None
    for offset, character in enumerate(argument[1:], start=1):
        if not character.isalnum():
            return None
        option = f"-{character}"
        if option in option_names:
            return option, argument[offset + 1 :]
    return None


def _normalize_option_token(value: str) -> str:
    stripped = value.strip()
    return stripped.lower() if stripped.startswith("--") else stripped


def _split_option_setting(value: str) -> tuple[str, str]:
    normalized = value.strip()
    if not normalized:
        return "", ""
    if "=" in normalized:
        key, setting = normalized.split("=", 1)
    else:
        parts = normalized.split(None, 1)
        key, setting = parts[0], parts[1] if len(parts) == 2 else ""
    return key.lower(), setting.strip().lower()


def present_flags(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> frozenset[str]:
    flags: set[str] = set()
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            break
        flags.add(argument)
        if argument.startswith("-") and "=" in argument:
            flags.add(argument.split("=", 1)[0])
        if argument.startswith("-") and not argument.startswith("--") and len(argument) > 2:
            for character in argument[1:]:
                if not character.isalnum():
                    continue
                short_flag = f"-{character}"
                flags.add(short_flag)
                if short_flag in options_with_values:
                    break
        option_name = argument.split("=", 1)[0]
        index += 2 if option_name in options_with_values and "=" not in argument else 1
    return frozenset(flags)
