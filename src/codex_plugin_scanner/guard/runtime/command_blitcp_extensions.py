"""Structured rules and metadata for blitcp copy commands."""

from __future__ import annotations

from dataclasses import replace

from .command_extension_matchers import executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_rules import (
    CommandMatcher,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
)
from .command_structured_matchers import TrailingOperandPrefixMatcher

# blitcp takes `SOURCE... DESTINATION`, so the final operand decides whether a
# run reads remote data or writes it: `blitcp /data s3://bucket` sends data off
# the host, while `blitcp s3://bucket/data /restore` pulls it down. Matching any
# operand would prompt on both, which teaches people to approve the one that
# matters.
#
# Options may appear anywhere, so the ones that consume a following value have
# to be declared or that value is mistaken for the destination.
_BLITCP_OPTIONS_WITH_VALUES = frozenset(
    {
        "--az-account",
        "--az-connection-string",
        "--az-key",
        "--buffer",
        "--chunk-size",
        "--cloud-concurrency",
        "--credentials-file",
        "--endpoint-url",
        "--exclude",
        "--gcs-credentials",
        "--gcs-project",
        "--hash",
        "--index-existing",
        "--lang",
        "--log-file",
        "--preserve",
        "--s3-profile",
        "--s3-region",
        "--small-files",
        "--smb-domain",
        "--smb-password-env",
        "--smb-port",
        "--smb-user",
        "--ssh-dst-key",
        "--ssh-dst-password-env",
        "--ssh-dst-port",
        "--ssh-src-key",
        "--ssh-src-password-env",
        "--ssh-src-port",
        "--threads",
        "--update-sha256",
    }
)
# Case-sensitive on purpose: blitcp itself only accepts lower-case schemes, so
# matching "S3://bucket" would flag a command blitcp would refuse to run.
_BLITCP_REMOTE_DESTINATION = TrailingOperandPrefixMatcher(
    executables=executable_names("blitcp"),
    operand_prefixes=frozenset({"s3://", "az://", "gs://", "smb://"}),
    options_with_values=_BLITCP_OPTIONS_WITH_VALUES,
)
# The structured matcher is not an AnyMatcher of executable children, so it
# cannot go through safe_flag_variant; the variant is the same matcher with
# --dry-run required, which is what that helper builds for the others.
_BLITCP_REMOTE_DESTINATION_DRY_RUN = replace(
    _BLITCP_REMOTE_DESTINATION,
    required_flags=frozenset({"--dry-run"}),
)
_BLITCP_SELF_UPDATE = ExecutableMatcher(
    executables=executable_names("blitcp"),
    required_flags=frozenset({"--update"}),
)
_BLITCP_PRIVILEGE_ESCALATION = ExecutableMatcher(
    executables=executable_names("blitcp"),
    required_flags=frozenset({"--use-sudo"}),
)
# A dry run copies nothing, so there is nothing for verification to check and
# --no-verify says nothing about the outcome. Excluding it keeps previews
# distinct from real copies here too, not only on the destination rule.
_BLITCP_UNVERIFIED_COPY = ExecutableMatcher(
    executables=executable_names("blitcp"),
    required_flags=frozenset({"--no-verify"}),
    forbidden_flags=frozenset({"--dry-run"}),
)


def _blitcp_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: CommandMatcher,
    action_class: str,
    safer_alternative: str,
    severity: CommandRuleSeverity,
    risk_classes: tuple[str, ...] = ("destructive_shell", "network_egress"),
    safe_variants: tuple[CommandSafeVariant, ...] = (),
    example_command: str | None = None,
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        risk_classes=risk_classes,
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
        example_command=example_command,
    )


BLITCP_COMMAND_RULES = (
    _blitcp_rule(
        rule_id="command.blitcp.remote-destination",
        example_command="blitcp /data s3://backups/nightly",
        title="Blitcp copy to a remote destination",
        description=(
            "Identifies blitcp copies whose final operand is an object-store or SMB destination, "
            "which sends local data off the host. The same scheme in an earlier position is a "
            "source and reads data instead."
        ),
        matcher=_BLITCP_REMOTE_DESTINATION,
        action_class="Blitcp remote destination command",
        safer_alternative="Run the same command with --dry-run and confirm the destination before copying.",
        severity="high",
        risk_classes=("network_egress",),
        safe_variants=(
            CommandSafeVariant(
                variant_id="dry-run",
                title="Blitcp dry run",
                matcher=_BLITCP_REMOTE_DESTINATION_DRY_RUN,
            ),
        ),
    ),
    _blitcp_rule(
        rule_id="command.blitcp.privilege-escalation",
        example_command="blitcp --use-sudo /var/lib/data /mnt/backup",
        title="Blitcp privilege escalation",
        description="Identifies blitcp runs that re-execute the copier under sudo.",
        matcher=_BLITCP_PRIVILEGE_ESCALATION,
        action_class="Blitcp privilege escalation command",
        safer_alternative="Copy as a user that already reaches both paths rather than elevating the copier.",
        severity="critical",
        risk_classes=("execution",),
    ),
    _blitcp_rule(
        rule_id="command.blitcp.self-update",
        example_command="blitcp --update",
        title="Blitcp self-update",
        description=(
            "Identifies blitcp self-update runs, which download a release over the network and "
            "replace the running executable in place."
        ),
        matcher=_BLITCP_SELF_UPDATE,
        action_class="Blitcp self-update command",
        safer_alternative="Update through the package manager that installed blitcp instead of rewriting the binary.",
        severity="high",
        risk_classes=("execution", "network_egress"),
    ),
    _blitcp_rule(
        rule_id="command.blitcp.unverified-copy",
        example_command="blitcp --no-verify /data /mnt/backup",
        title="Blitcp copy without verification",
        description=(
            "Identifies blitcp runs that skip the whole post-copy verification phase, so the run "
            "reports success without reading anything back. The result is a silently incomplete "
            "copy rather than a destructive action."
        ),
        matcher=_BLITCP_UNVERIFIED_COPY,
        action_class="Blitcp unverified copy command",
        safer_alternative="Drop --no-verify so every copied file is read back and compared against the source.",
        severity="medium",
        risk_classes=("destructive_shell",),
    ),
)

BLITCP_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.blitcp",
        name="Blitcp transfer protection",
        description="Reviews blitcp copies that leave the host, elevate privileges, or skip verification.",
        action_classes=(
            "Blitcp remote destination command",
            "Blitcp privilege escalation command",
            "Blitcp self-update command",
            "Blitcp unverified copy command",
        ),
        risk_classes=("destructive_shell", "execution", "network_egress"),
        safer_alternatives=("Use --dry-run to print the plan, and keep verification enabled on real copies.",),
        reference_urls=("https://blitcp.dev/docs/", "https://github.com/gekap/blitcp"),
    ),
)
