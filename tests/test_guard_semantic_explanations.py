from __future__ import annotations

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.runtime.semantic_explanations import (
    CommandSemanticInput,
    explain_command,
    stable_semantic_catalog_digest,
)


def _input(executable: str, *arguments: str, command: str | None = None, exact: bool = False) -> CommandSemanticInput:
    return CommandSemanticInput(
        action_identity=f"action:{executable}:{len(arguments)}",
        canonical_identity=f"canonical:{executable}:{len(arguments)}",
        actor_label="Cursor",
        executable=executable,
        arguments=tuple(arguments),
        command_display=command,
        normalized_command_display=command,
        dialect="posix",
        transport="shell",
        exact_details_authorized=exact,
    )


@pytest.mark.parametrize(
    ("executable", "arguments", "headline_fragment"),
    [
        ("rm", ("-rf", "./build"), "folder and everything"),
        ("rmdir", ("--recursive", "cache"), "folder and everything"),
        ("del.exe", ("notes.txt",), "Delete a file"),
        ("Remove-Item", ("-Recurse", "dist"), "folder and everything"),
        ("cp", ("a.txt", "backup/a.txt"), "Copy files"),
        ("Copy-Item", ("a.txt", "backup"), "Copy files"),
        ("mv", ("draft.txt", "final.txt"), "Move or rename"),
        ("Rename-Item", ("draft.txt", "final.txt"), "Move or rename"),
        ("chmod", ("777", "deploy.sh"), "Change who can access"),
        ("icacls.exe", ("report.txt", "/grant", "Everyone:F"), "Change who can access"),
        ("cat", ("~/.aws/credentials",), "Read saved credentials"),
        ("Get-Content", ("$HOME/.ssh/id_ed25519",), "Read saved credentials"),
        ("curl", ("https://example.com/status",), "Connect to a website"),
        ("curl", ("-o", "tool.sh", "https://example.com/tool.sh"), "Download a file"),
        ("curl", ("--data", "name=test", "https://example.com/api"), "Send data"),
        ("Invoke-WebRequest", ("-OutFile", "tool.zip", "https://example.com/tool.zip"), "Download a file"),
        ("scp", ("report.pdf", "alice@example.com:/tmp/report.pdf"), "Transfer files"),
        ("npm", ("install", "left-pad@1.3.0"), "Install software"),
        ("pnpm", ("add", "react@19"), "Install software"),
        ("pip", ("install", "requests==2.32.0"), "Install software"),
        ("uv", ("add", "httpx"), "Install software"),
        ("cargo", ("install", "ripgrep"), "Install software"),
        ("npm", ("uninstall", "left-pad"), "Remove software"),
        ("pip", ("uninstall", "requests"), "Remove software"),
        ("npm", ("publish",), "Publish a software"),
        ("cargo", ("publish",), "Publish a software"),
    ],
)
def test_known_commands_have_deterministic_everyday_explanations(executable: str, arguments: tuple[str, ...], headline_fragment: str) -> None:
    explanation = explain_command(_input(executable, *arguments))
    assert headline_fragment in explanation.everyday.headline
    assert explanation.confidence in {"exact", "derived"}
    assert explanation.technical.available is False
    assert explanation.technical.command_display is None


def test_unknown_command_is_explicitly_limited_not_inferred_safe() -> None:
    explanation = explain_command(_input("future-cli", "quantum-delete", "--all"))
    assert explanation.kind == "unknown"
    assert explanation.confidence == "limited"
    assert "could not" in explanation.everyday.headline.casefold()
    assert "semantic_rule_unavailable" in explanation.uncertainty_reasons


def test_ordinary_file_read_is_not_misclassified_as_credentials() -> None:
    explanation = explain_command(_input("cat", "README.md"))
    assert explanation.kind == "unknown"
    assert "credentials" not in explanation.everyday.headline.casefold()


def test_everyday_projection_never_contains_full_path_or_secret() -> None:
    secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
    explanation = explain_command(
        _input(
            "curl",
            "--data",
            f"token={secret}",
            "https://upload.example/private",
            command=f"curl --data token={secret} https://upload.example/private",
            exact=True,
        )
    )
    everyday = f"{explanation.everyday.headline} {explanation.everyday.summary} {explanation.everyday.impact}"
    assert secret not in everyday
    assert "/private" not in everyday
    assert secret not in (explanation.technical.command_display or "")
    assert explanation.redaction.secret_like_values_removed is True


def test_exact_details_require_retention_and_authorization() -> None:
    base = _input("rm", "-rf", "./build", command="rm -rf ./build", exact=True)
    visible = explain_command(base)
    assert visible.technical.available is True
    assert visible.technical.command_display == "rm -rf ./build"

    unauthorized = explain_command(replace(base, exact_details_authorized=False))
    assert unauthorized.technical.available is False
    assert unauthorized.technical.command_display is None

    unretained = explain_command(replace(base, retained=False))
    assert unretained.technical.available is False
    assert unretained.technical.unavailable_reason == "not_retained"


def test_windows_executable_suffixes_and_paths_are_normalized() -> None:
    explanation = explain_command(_input(r"C:\\Windows\\System32\\del.exe", r"C:\\Temp\\notes.txt"))
    assert "Delete a file" in explanation.everyday.headline
    assert "C:\\Temp" not in explanation.everyday.summary


def test_catalog_digest_is_stable_and_content_addressed() -> None:
    first = stable_semantic_catalog_digest()
    second = stable_semantic_catalog_digest()
    assert first == second
    assert len(first) == 64
    int(first, 16)


def test_builder_is_side_effect_free(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("side effect attempted")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    explanation = explain_command(_input("rm", "-rf", "./build"))
    assert explanation.everyday.headline
