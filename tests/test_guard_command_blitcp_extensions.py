"""Structured blitcp transfer command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_structured_matchers import (
    TrailingOperandHostTargetMatcher,
    TrailingOperandPrefixMatcher,
)
from tests.command_extension_contracts import (
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

BLITCP_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "blitcp /data s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data az://container/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data gs://bucket/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data smb://fileserver/share",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    # Several sources into one destination is the documented multi-source form,
    # so the last operand is still what decides direction.
    (
        "blitcp /srv/a /srv/b /srv/c s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    # An option that consumes its value must not shift which operand is last.
    (
        "blitcp --threads 8 /data s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp --exclude '*.tmp' /data s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp.exe /data s3://backups/nightly",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    # SSH is blitcp's oldest remote transport and is the same egress as an
    # object-store write, so it belongs to the same rule.
    (
        "blitcp /data user@host.example:/srv/backup",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data host.example:/srv/backup",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data user@[2001:db8::1]:/srv/backup",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp /data user@host.example:/srv/backup --ssh-dst-port 2222",
        "Blitcp remote destination command",
        "command.blitcp.remote-destination",
    ),
    (
        "blitcp --use-sudo /var/lib/data /mnt/backup",
        "Blitcp privilege escalation command",
        "command.blitcp.privilege-escalation",
    ),
    (
        "blitcp --update",
        "Blitcp self-update command",
        "command.blitcp.self-update",
    ),
    (
        "blitcp --no-verify /data /mnt/backup",
        "Blitcp unverified copy command",
        "command.blitcp.unverified-copy",
    ),
)


def test_blitcp_rules_feed_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(BLITCP_REVIEW_CASES, tmp_path)


BLITCP_SAFE_COMMANDS: tuple[str, ...] = (
    # The maintainer's direction contract: a remote SOURCE is a read, and a
    # restore must not prompt the way an upload does.
    "blitcp s3://backups/nightly /local/restore",
    "blitcp az://container/nightly /local/restore",
    "blitcp gs://bucket/nightly /local/restore",
    "blitcp smb://fileserver/share /local/restore",
    # A preview of an upload plans the transfer without performing it.
    "blitcp --dry-run /data s3://backups/nightly",
    "blitcp /data s3://backups/nightly --dry-run",
    # A dry run verifies nothing because it copies nothing, so --no-verify
    # on a preview describes no risk.
    "blitcp --dry-run --no-verify /data /mnt/backup",
    "blitcp --dry-run --no-verify /data s3://backups/nightly",
    # An SSH source is a restore, exactly as an object-store source is.
    "blitcp user@host.example:/srv/backup /local/restore",
    "blitcp host.example:/srv/backup /local/restore",
    "blitcp --dry-run /data user@host.example:/srv/backup",
    # A single-letter host is a Windows drive, not a remote — blitcp itself
    # makes this distinction, so a copy to C:\\backup must not read as egress.
    "blitcp /data C:\\backup",
    "blitcp C:\\data D:\\backup",
    # Purely local copies carry none of these risks.
    "blitcp /data /mnt/usb",
    "blitcp -a /data /mnt/usb",
    "blitcp --version",
    "blitcp --help",
    "blitcp --check-update",
    # blitcp only accepts lower-case schemes, so an upper-case one would flag a
    # command blitcp itself refuses to run.
    "blitcp /data S3://backups/nightly",
    # A scheme that is not a supported remote endpoint is an ordinary path.
    "blitcp /data ftp://host/share",
    # The scheme has to start the operand, not merely appear inside it.
    "blitcp /data /mnt/s3://notascheme",
    # Neither a mention of the command nor a grep for it is an invocation.
    "grep 'blitcp /data s3://bucket' docs",
    "echo blitcp /data s3://backups/nightly",
)


def test_blitcp_reads_and_previews_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(BLITCP_SAFE_COMMANDS, tmp_path)


def test_blitcp_extension_publishes_official_references() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.blitcp")

    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)


def test_blitcp_actions_publish_risk_classes() -> None:
    assert risk_classes_for_command_action("Blitcp remote destination command") == ("network_egress",)
    assert risk_classes_for_command_action("Blitcp privilege escalation command") == ("execution",)
    assert risk_classes_for_command_action("Blitcp self-update command") == (
        "execution",
        "network_egress",
    )


def test_blitcp_option_values_cannot_forge_a_local_destination(tmp_path: Path) -> None:
    """An option value that looks like a path must not become the destination."""
    for command in (
        "blitcp --log-file /var/log/blitcp.log /data s3://backups/nightly",
        "blitcp --hash xxh128 /data s3://backups/nightly",
        "blitcp --preserve mode /data s3://backups/nightly",
        # Options may follow the operands. If the trailing option's value is
        # mistaken for the destination, the upload stops matching entirely,
        # so every value-taking option has to be declared.
        "blitcp /data s3://backups/nightly --s3-region eu-west-1",
        "blitcp /data s3://backups/nightly --endpoint-url https://minio.example",
        "blitcp /data s3://backups/nightly --s3-profile archive",
        "blitcp /data smb://fileserver/share --smb-user backup-svc",
        "blitcp /data az://container/nightly --az-account storageacct",
    ):
        payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

        assert payload["status"] == "review", command
        assert payload["controlling_rule_id"] == "command.blitcp.remote-destination", command


def test_trailing_operand_matcher_ignores_prefixes_in_earlier_operands(tmp_path: Path) -> None:
    matcher = TrailingOperandPrefixMatcher(
        executables=frozenset({"transfer"}),
        operand_prefixes=frozenset({"s3://"}),
    )
    upload = parse_shell_command("transfer /data s3://bucket/key", cwd=tmp_path, home_dir=tmp_path)
    download = parse_shell_command("transfer s3://bucket/key /data", cwd=tmp_path, home_dir=tmp_path)

    assert matcher.match(upload)
    assert matcher.match(download) == ()


def test_trailing_operand_matcher_consumes_separate_long_option_value(tmp_path: Path) -> None:
    matcher = TrailingOperandPrefixMatcher(
        executables=frozenset({"transfer"}),
        operand_prefixes=frozenset({"s3://"}),
        options_with_values=frozenset({"--profile"}),
    )
    command = parse_shell_command(
        "transfer --profile s3://not-a-destination /data s3://bucket/key",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert matcher.match(command)


def test_trailing_operand_matcher_requires_a_source_and_a_destination(tmp_path: Path) -> None:
    """A lone remote operand names a target to list, not a copy that writes to it."""
    matcher = TrailingOperandPrefixMatcher(
        executables=frozenset({"transfer"}),
        operand_prefixes=frozenset({"s3://"}),
    )
    command = parse_shell_command("transfer s3://bucket/key", cwd=tmp_path, home_dir=tmp_path)

    assert matcher.match(command) == ()


def test_trailing_operand_matcher_honours_required_and_forbidden_flags(tmp_path: Path) -> None:
    base = TrailingOperandPrefixMatcher(
        executables=frozenset({"transfer"}),
        operand_prefixes=frozenset({"s3://"}),
    )
    requires_preview = TrailingOperandPrefixMatcher(
        executables=frozenset({"transfer"}),
        operand_prefixes=frozenset({"s3://"}),
        required_flags=frozenset({"--dry-run"}),
    )
    rejects_preview = TrailingOperandPrefixMatcher(
        executables=frozenset({"transfer"}),
        operand_prefixes=frozenset({"s3://"}),
        forbidden_flags=frozenset({"--dry-run"}),
    )
    live = parse_shell_command("transfer /data s3://bucket/key", cwd=tmp_path, home_dir=tmp_path)
    preview = parse_shell_command("transfer --dry-run /data s3://bucket/key", cwd=tmp_path, home_dir=tmp_path)

    assert base.match(live)
    assert base.match(preview)
    assert requires_preview.match(live) == ()
    assert requires_preview.match(preview)
    assert rejects_preview.match(live)
    assert rejects_preview.match(preview) == ()


def test_host_target_matcher_reads_direction_and_excludes_drive_letters(tmp_path: Path) -> None:
    matcher = TrailingOperandHostTargetMatcher(executables=frozenset({"transfer"}))

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert matcher.match(parsed("transfer /data user@host.example:/srv"))
    assert matcher.match(parsed("transfer /data host.example:/srv"))
    assert matcher.match(parsed("transfer /data user@[2001:db8::1]:/srv"))
    # Direction, a Windows drive, a bare local path, and a scheme the prefix
    # matcher already owns must all stay unmatched.
    assert matcher.match(parsed("transfer user@host.example:/srv /data")) == ()
    assert matcher.match(parsed("transfer /data C:\\backup")) == ()
    assert matcher.match(parsed("transfer /data /mnt/usb")) == ()
    assert matcher.match(parsed("transfer /data s3://bucket/key")) == ()
    # A host with no path, and a path with no host, are not remote targets.
    assert matcher.match(parsed("transfer /data host.example:")) == ()
    assert matcher.match(parsed("transfer /data :/srv")) == ()
