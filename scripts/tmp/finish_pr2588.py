from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def replace_block(text: str, start_marker: str, end_marker: str, replacement: str, *, label: str) -> str:
    try:
        start = text.index(start_marker)
        end = text.index(end_marker, start)
    except ValueError as error:
        raise RuntimeError(f"{label}: expected block markers were not found") from error
    return text[:start] + replacement.rstrip() + "\n\n" + text[end:]


semantic_path = Path("src/codex_plugin_scanner/guard/runtime/semantic_explanations.py")
semantic = semantic_path.read_text(encoding="utf-8")

semantic = replace_block(
    semantic,
    "_SECRET_MARKERS =",
    "_URL_RE =",
    r'''_SECRET_MARKERS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "credentials",
        "application_default_credentials",
        ".aws",
        ".ssh",
        ".gnupg",
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_ed25519",
        "keychain",
    }
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:"
    r"\bauthorization\s*:\s*bearer\s+\S+"
    r"|sk-[a-z0-9_-]{12,}"
    r"|gh[pousr]_[a-z0-9]{20,}"
    r"|(?:api[_-]?key|token|password|secret)\s*[=:]\s*\S+"
    r")"
)''',
    label="secret redaction constants",
)

action_kind_replacements = {
    'rule_id="filesystem.move", action_kind="file_write"': 'rule_id="filesystem.move", action_kind="file_move"',
    'rule_id="credentials.read", action_kind="credential_access"': 'rule_id="credentials.read", action_kind="secret_read"',
    'rule_id="network.upload", action_kind="network_request"': 'rule_id="network.upload", action_kind="network_send"',
    'rule_id="network.download", action_kind="network_request"': 'rule_id="network.download", action_kind="download"',
    'rule_id="network.request", action_kind="network_request"': 'rule_id="network.request", action_kind="network_read"',
    'rule_id="network.remote-copy", action_kind="network_request"': 'rule_id="network.remote-copy", action_kind="network_send"',
    'rule_id="package.publish", action_kind="package_change"': 'rule_id="package.publish", action_kind="package_script"',
    'rule_id="package.remove", action_kind="package_change"': 'rule_id="package.remove", action_kind="package_remove"',
    'rule_id="package.install", action_kind="package_change"': 'rule_id="package.install", action_kind="package_install"',
}
for old, new in action_kind_replacements.items():
    semantic = replace_once(semantic, old, new, label=f"action kind {old}")

semantic = replace_once(
    semantic,
    "    match = _render_match(rule, input, args)\n",
    "    match = _render_match(rule, input, args, executable)\n",
    label="render match call",
)

semantic = replace_block(
    semantic,
    "    technical_available = bool(input.retained and input.exact_details_authorized and input.command_display)",
    "    omitted: list[str] = []",
    '''    technical_available = bool(input.retained and input.exact_details_authorized and input.command_display)
    command_display = _redact_technical_value(input.command_display) if technical_available else None
    normalized_display = _redact_technical_value(input.normalized_command_display) if technical_available else None
    arguments_display = [_redact_technical_value(arg) or "[redacted]" for arg in args] if technical_available else None
    secret_like_values_removed = _secret_like_value_present((input.command_display or "", *args))
    if technical_available:
        technical_unavailable_reason = None
    elif not input.retained:
        technical_unavailable_reason = "not_retained"
    else:
        technical_unavailable_reason = "not_authorized"

    action_kind = match.rule.action_kind if match.rule else "unknown_action"
    if action_kind not in ACTION_KINDS:
        action_kind = "unknown_action"
    semantic_rule_id = match.rule.rule_id if match.rule else "unknown"
    target_strategy = match.rule.target_strategy if match.rule else "generic"
    everyday_targets: list[dict[str, object]] = []
    if match.rule is not None:
        everyday_targets.append(
            {
                "kind": target_strategy,
                "label": _bounded(match.target_label, 240) or "the requested target",
                "scope": None,
                "sensitivity": "secret" if target_strategy == "sensitive" else "normal",
            }
        )
    consequence_level = match.rule.consequence_level if match.rule else "medium"
    if consequence_level not in {"info", "low", "medium", "high", "critical"}:
        consequence_level = "medium"
    everyday_consequences = (
        [
            {
                "message_id": f"guard.everyday.{semantic_rule_id}.consequence",
                "message": _bounded(match.impact, 500) or "Review the possible consequences before continuing.",
                "severity": consequence_level,
                "confirmed": False,
            }
        ]
        if match.impact
        else []
    )
    everyday_alternatives = [
        {
            "message_id": f"guard.everyday.{semantic_rule_id}.alternative.{index}",
            "message": _bounded(message, 500) or "Review a safer option before continuing.",
            "kind": _alternative_kind(message),
        }
        for index, message in enumerate(match.safer_alternatives[:12], start=1)
    ]''',
    label="explanation projection setup",
)

replacements = {
    '        "action_identity": _bounded(input.action_identity, 256),': '        "action_identity": _bounded(input.action_identity, 512),',
    '            "summary": _bounded(match.summary, 1000),': '            "summary": _bounded(match.summary, 800),',
    '            "impact": _bounded(match.impact, 1000),': '            "impact": _bounded(match.impact, 800),',
    '            "recommendation": _bounded(match.recommendation, 1000),': '            "recommendation": _bounded(match.recommendation, 800),',
    '            "actor_label": _bounded(_safe_actor(input.actor_label), 160),': '            "actor_label": _bounded(_safe_actor(input.actor_label), 120),',
    '            "targets": [], "consequences": [], "safer_alternatives": [],': '            "targets": everyday_targets, "consequences": everyday_consequences,\n            "safer_alternatives": everyday_alternatives,',
    '            "unavailable_reason": None if technical_available else ("not_retained" if not input.retained else "not_authorized"),': '            "unavailable_reason": technical_unavailable_reason,',
    '            "command_display": _bounded(command_display, 12000),': '            "command_display": _bounded(command_display, 4096),',
    '            "normalized_command_display": _bounded(normalized_display, 12000),': '            "normalized_command_display": _bounded(normalized_display, 4096),',
    '            "executable": _bounded(executable or None, 512),': '            "executable": _bounded(executable or None, 240),',
    '            "arguments_display": [_bounded(value, 2000) or "" for value in arguments_display] if arguments_display is not None else None,': '            "arguments_display": [_bounded(value, 240) or "" for value in arguments_display[:128]] if arguments_display is not None else None,',
    '            "dialect": _bounded(input.dialect, 128), "transport": _bounded(input.transport, 128),': '            "dialect": _bounded(input.dialect, 64), "transport": _bounded(input.transport, 64),',
    '            "working_scope_display": _bounded(_safe_scope(input.working_scope_display), 1000) if input.exact_details_authorized else None,': '            "working_scope_display": _bounded(_safe_scope(input.working_scope_display), 240) if input.exact_details_authorized else None,',
    '            "extension_ids": [_bounded(value, 256) or "" for value in input.extension_ids],': '            "extension_ids": [_bounded(value, 128) or "" for value in input.extension_ids[:64]],',
    '            "rule_ids": [_bounded(value, 256) or "" for value in input.rule_ids],': '            "rule_ids": [_bounded(value, 128) or "" for value in input.rule_ids[:64]],',
    '            "reason_codes": [_bounded(value, 256) or "" for value in input.reason_codes],': '            "reason_codes": [_bounded(value, 128) or "" for value in input.reason_codes[:64]],',
    '            "policy_source": _bounded(input.policy_source, 256),': '            "policy_source": _bounded(input.policy_source, 128),',
    '            "parse_confidence": _bounded(input.parse_confidence, 128),': '            "parse_confidence": _bounded(input.parse_confidence, 64),',
    '            "proof_level": _bounded(input.proof_level, 128),': '            "proof_level": _bounded(input.proof_level, 64),',
    '            "action_id": _bounded(input.action_identity, 256),': '            "action_id": _bounded(input.action_identity, 512),',
    '            "level": "none" if technical_available else "redacted",': '            "level": "redacted" if secret_like_values_removed or not technical_available else "none",',
    '            "secret_like_values_removed": _secret_like_value_present((input.command_display or "", *args)),': '            "secret_like_values_removed": secret_like_values_removed,',
}
for old, new in replacements.items():
    semantic = replace_once(semantic, old, new, label=old)

semantic = replace_block(
    semantic,
    "def stable_semantic_catalog_digest() -> str:",
    "def _render_match(",
    '''def stable_semantic_catalog_digest() -> str:
    material = [
        {
            "rule_id": rule.rule_id,
            "action_kind": rule.action_kind,
            "executables": sorted(rule.executables),
            "required_tokens": [sorted(group) for group in rule.required_tokens],
            "forbidden_tokens": sorted(rule.forbidden_tokens),
            "headline": rule.headline,
            "summary": rule.summary,
            "impact": rule.impact,
            "recommendation": rule.recommendation,
            "target_strategy": rule.target_strategy,
            "confidence": rule.confidence,
            "consequence_level": rule.consequence_level,
            "safer_alternatives": list(rule.safer_alternatives),
        }
        for rule in SEMANTIC_RULES
    ]
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _alternative_kind(message: str) -> str:
    normalized = message.casefold()
    if any(token in normalized for token in ("preview", "inspect", "dry run", "check")):
        return "preview"
    if any(token in normalized for token in ("backup", "recycle bin", "trash", "copy first")):
        return "backup"
    if any(token in normalized for token in ("isolated", "empty folder", "environment")):
        return "isolate"
    if any(token in normalized for token in ("minimum", "narrow", "one item")):
        return "narrow"
    return "review"''',
    label="catalog digest and alternative kind",
)

semantic = replace_once(
    semantic,
    "def _render_match(rule: SemanticRule | None, input: CommandSemanticInput, args: Sequence[str]) -> SemanticMatch:",
    "def _render_match(\n    rule: SemanticRule | None,\n    input: CommandSemanticInput,\n    args: Sequence[str],\n    executable: str,\n) -> SemanticMatch:",
    label="render match signature",
)
semantic = replace_once(
    semantic,
    "    target = _target_label(rule.target_strategy, args)\n",
    "    target = _target_label(rule.target_strategy, args, executable)\n",
    label="target label call",
)

semantic = replace_block(
    semantic,
    "def _target_label(",
    "def _safe_basename(",
    r'''def _target_label(strategy: str, arguments: Sequence[str], executable: str) -> str:
    positional = [arg for arg in arguments if arg and not arg.startswith("-")]
    if strategy == "sensitive":
        return "saved credentials or another sensitive file"
    if strategy == "network":
        for argument in arguments:
            match = _URL_RE.search(argument)
            if match:
                return f"the service at {_bounded(match.group(1).strip('[]').casefold(), 253)}"
        return "an external website or service"
    if strategy == "remote":
        for argument in arguments:
            if ":" in argument and not _DRIVE_RE.match(argument):
                host = argument.split(":", 1)[0].split("@")[-1]
                if host:
                    return f"another computer ({_bounded(host, 160)})"
        return "another computer"
    if strategy == "package":
        packages = [
            arg
            for arg in positional
            if arg.casefold()
            not in {
                "install",
                "add",
                "i",
                "get",
                "remove",
                "rm",
                "uninstall",
                "erase",
                "publish",
                "upload",
                "push",
            }
        ]
        if packages:
            shown = ", ".join(_safe_basename(value) for value in packages[:3])
            return f"the software package{'s' if len(packages) != 1 else ''} {shown}"
        return "one or more software packages"
    if strategy == "filesystem":
        candidates = _filesystem_operands(executable, arguments)
        if candidates:
            label = _safe_basename(candidates[-1])
            return f"the item named {label}" if label else "files or folders in the selected location"
        return "files or folders in the selected location"
    return "the requested target"


def _filesystem_operands(executable: str, arguments: Sequence[str]) -> tuple[str, ...]:
    path_options = frozenset({"-path", "-literalpath", "-file", "-filepath", "/f"})
    destination_options = frozenset({"-destination", "-dest", "-target", "-t", "--target-directory"})
    value_options = frozenset(
        {
            "--backup",
            "--suffix",
            "--context",
            "--reference",
            "--from",
            "--preserve-root",
            "-filter",
            "-include",
            "-exclude",
            "-credential",
            "-aclobject",
        }
    )
    slash_value_options = frozenset({"/grant", "/deny", "/remove", "/setowner", "/findsid", "/substitute"})
    slash_flags = frozenset({"/s", "/q", "/a", "/c", "/l", "/t", "/e", "/h", "/k", "/y", "/n"})
    operands: list[str] = []
    destination: str | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        folded = argument.casefold()
        if folded in path_options or folded in destination_options:
            if index + 1 < len(arguments):
                value = arguments[index + 1]
                if folded in destination_options:
                    destination = value
                else:
                    operands.append(value)
            index += 2
            continue
        if folded in value_options or folded in slash_value_options:
            index += 2
            continue
        if folded in slash_flags:
            index += 1
            continue
        if folded.startswith("--") and "=" in folded:
            option, value = argument.split("=", 1)
            if option.casefold() in destination_options and value:
                destination = value
            index += 1
            continue
        if folded.startswith("-"):
            index += 1
            continue
        operands.append(argument)
        index += 1
    if destination:
        operands.append(destination)
    if executable in {"chmod", "chown", "chgrp"} and len(operands) > 1:
        operands = operands[1:]
    if executable == "icacls" and operands:
        return (operands[0],)
    if executable == "robocopy" and len(operands) >= 2:
        return (operands[1],)
    return tuple(operands)''',
    label="target extraction",
)

semantic = replace_block(
    semantic,
    "def _contains_sensitive_marker(",
    "def _secret_like_value_present(",
    r'''def _is_public_key_path(value: str) -> bool:
    basename = value.strip().strip("'\"`[]{}(),;").replace("\\", "/").rsplit("/", 1)[-1].casefold()
    return basename in {"id_rsa.pub", "id_ed25519.pub"}


def _sensitive_components(value: str) -> Iterable[str]:
    for token in re.split(r"\s+", value.casefold()):
        normalized = token.strip().strip("'\"`[]{}(),;:")
        if not normalized:
            continue
        for component in re.split(r"[\\/]", normalized):
            component = component.strip().strip("'\"`[]{}(),;:")
            if not component:
                continue
            yield component
            if component.startswith(".env."):
                yield ".env"
            elif component.startswith(".") and component.count(".") > 1:
                yield "." + component[1:].split(".", 1)[0]
            elif "." in component:
                yield component.rsplit(".", 1)[0]


def _contains_sensitive_marker(values: Iterable[str]) -> bool:
    for value in values:
        if _is_public_key_path(value):
            continue
        if any(component in _SECRET_MARKERS for component in _sensitive_components(value)):
            return True
    return False''',
    label="sensitive marker detection",
)

semantic_path.write_text(semantic, encoding="utf-8")


test_path = Path("tests/test_guard_semantic_explanations.py")
tests = test_path.read_text(encoding="utf-8")
tests = replace_once(
    tests,
    "import pytest\n\nfrom codex_plugin_scanner.guard.runtime.semantic_explanations import (",
    "import pytest\n\nfrom codex_plugin_scanner.guard.runtime import semantic_explanations as semantic_module\nfrom codex_plugin_scanner.guard.runtime.semantic_explanations import (",
    label="semantic module test import",
)
tests = tests.replace('assert explanation.kind == "unknown"', 'assert explanation.kind == "unknown_action"')
addition_marker = "def test_review_remediations_cover_security_and_production_contract()"
if addition_marker not in tests:
    tests += r'''


def test_review_remediations_cover_security_and_production_contract() -> None:
    recognized = explain_command(_input("rm", "-rf", "./build"))
    unknown = explain_command(_input("future-cli", "quantum-delete", "--all"))
    assert recognized.everyday.safer_alternatives
    assert unknown.everyday.safer_alternatives
    assert recognized.everyday.targets
    assert recognized.everyday.consequences

    bearer = "opaque-value-123456789"
    header = f"Authorization: Bearer {bearer}"
    redacted = explain_command(
        _input(
            "curl",
            "-H",
            header,
            "https://api.example.test/data",
            command=f"curl -H '{header}' https://api.example.test/data",
            exact=True,
        )
    )
    assert bearer not in (redacted.technical.command_display or "")
    assert all(bearer not in value for value in (redacted.technical.arguments_display or ()))
    assert redacted.redaction.secret_like_values_removed is True
    assert redacted.redaction.level == "redacted"


def test_sensitive_upload_keeps_safe_destination_label() -> None:
    explanation = explain_command(
        _input(
            "curl",
            "--data",
            "token=opaque-value-123456",
            "https://upload.example/private",
        )
    )
    assert "service at upload.example" in explanation.everyday.summary
    assert "saved credentials" not in explanation.everyday.summary


def test_filesystem_target_parser_skips_options_and_option_values() -> None:
    icacls = explain_command(_input("icacls.exe", "report.txt", "/grant", "Everyone:F"))
    assert "report.txt" in icacls.everyday.summary
    assert "Everyone:F" not in icacls.everyday.summary

    delete = explain_command(_input("del.exe", "target.txt", "/s"))
    assert "target.txt" in delete.everyday.summary
    assert "/s" not in delete.everyday.summary

    powershell = explain_command(_input("Remove-Item", "-Path", r"C:\\Temp\\notes.txt", "-Force"))
    assert "notes.txt" in powershell.everyday.summary
    assert "Force" not in powershell.everyday.summary


@pytest.mark.parametrize("filename", ("secretary.txt", "tokenizer.py", "password-reset.md"))
def test_marker_lexical_collisions_are_not_credentials(filename: str) -> None:
    explanation = explain_command(_input("cat", filename))
    assert explanation.kind == "unknown_action"
    assert "credentials" not in explanation.everyday.headline.casefold()


def test_public_key_variant_is_not_private_credential() -> None:
    explanation = explain_command(_input("cat", "~/.ssh/id_ed25519.pub"))
    assert explanation.kind == "unknown_action"


def test_catalog_digest_changes_for_every_output_affecting_field(monkeypatch: pytest.MonkeyPatch) -> None:
    original = semantic_module.SEMANTIC_RULES
    baseline = semantic_module.stable_semantic_catalog_digest()
    changed = replace(original[0], impact="A materially different consequence.")
    monkeypatch.setattr(semantic_module, "SEMANTIC_RULES", (changed, *original[1:]))
    assert semantic_module.stable_semantic_catalog_digest() != baseline
'''
test_path.write_text(tests, encoding="utf-8")


service_path = Path("src/codex_plugin_scanner/guard/cli/commands_support_service.py")
service = service_path.read_text(encoding="utf-8")
helper_marker = "def _build_semantic_command_explain_payload("
if helper_marker not in service:
    helper = '''def _build_semantic_command_explain_payload(
    command_text: str,
    *,
    workspace: Path | None = None,
) -> dict[str, object]:
    from ..runtime.command_model import parse_shell_command
    from ..runtime.semantic_explanations import (
        CommandSemanticInput,
        explain_command,
        stable_semantic_catalog_digest,
    )

    command = command_text.strip()
    if not command:
        raise ValueError("Command text cannot be empty")
    working_directory = (workspace or Path.cwd()).resolve()
    canonical = parse_shell_command(command, cwd=working_directory, home_dir=Path.home())
    primary_segment = next(
        (segment for segment in canonical.segments if segment.execution_context == "top"),
        canonical.segments[0] if canonical.segments else None,
    )
    reason_codes = tuple(value for value in (canonical.uncertainty_reason,) if value)
    explanation = explain_command(
        CommandSemanticInput(
            action_identity=f"command:{canonical.security_identity}",
            canonical_identity=canonical.security_identity,
            actor_label="Guard CLI",
            executable=primary_segment.executable if primary_segment is not None else None,
            arguments=primary_segment.arguments if primary_segment is not None else (),
            command_display=command,
            normalized_command_display=canonical.normalized_text,
            dialect=canonical.dialect,
            transport=canonical.transport,
            working_scope_display=str(working_directory),
            reason_codes=reason_codes,
            policy_source="command-inspection",
            parse_confidence=canonical.confidence,
            proof_level="local_side_effect_free",
            catalog_digest=stable_semantic_catalog_digest(),
            exact_details_authorized=True,
            retained=True,
        )
    )
    return {
        "generated_at": _now(),
        "mode": "command",
        "command_model": canonical.to_dict(),
        "action_explanation": explanation.to_dict(),
        "policy_evaluation": "not_run",
        "side_effects": "none",
    }


'''
    service = replace_once(
        service,
        "def _build_explain_payload_with_mode(store: GuardStore, target: str, cisco_mode: str) -> dict[str, object]:\n",
        helper + "def _build_explain_payload_with_mode(store: GuardStore, target: str, cisco_mode: str) -> dict[str, object]:\n",
        label="production semantic helper insertion",
    )
service_path.write_text(service, encoding="utf-8")


parser_path = Path("src/codex_plugin_scanner/guard/cli/commands_parser_local.py")
parser = parser_path.read_text(encoding="utf-8")
command_option = '''    explain_parser.add_argument(
        "--command",
        dest="explain_as_command",
        action="store_true",
        help="Interpret target as an exact shell command and render the versioned local explanation contract",
    )
'''
if command_option not in parser:
    parser = replace_once(
        parser,
        '    explain_parser.add_argument("target")\n',
        '    explain_parser.add_argument("target")\n' + command_option,
        label="top-level explain command option",
    )
parser_path.write_text(parser, encoding="utf-8")


admin_path = Path("src/codex_plugin_scanner/guard/cli/commands_dispatch_admin.py")
admin = admin_path.read_text(encoding="utf-8")
old_admin = '''    store = _require_guard_store(store)
    if str(args.target).strip().lower() == "install-connect":
        payload = build_install_connect_docs_payload()
    else:
        payload = _build_explain_payload_with_mode(store, args.target, cisco_mode=args.cisco_mode)
'''
new_admin = '''    store = _require_guard_store(store)
    if bool(getattr(args, "explain_as_command", False)):
        from .commands_support_service import _build_semantic_command_explain_payload

        payload = _build_semantic_command_explain_payload(str(args.target), workspace=workspace)
    elif str(args.target).strip().lower() == "install-connect":
        payload = build_install_connect_docs_payload()
    else:
        payload = _build_explain_payload_with_mode(store, args.target, cisco_mode=args.cisco_mode)
'''
if new_admin not in admin:
    admin = replace_once(admin, old_admin, new_admin, label="top-level explain production route")
admin_path.write_text(admin, encoding="utf-8")


dispatch_path = Path("src/codex_plugin_scanner/guard/cli/commands_dispatch_local.py")
dispatch = dispatch_path.read_text(encoding="utf-8")
old_dispatch = '''        payload = inspect_command(str(getattr(args, "command_text", "")), cwd=Path.cwd(), home_dir=Path.home())
    except ValueError as error:
'''
new_dispatch = '''        command_text = str(getattr(args, "command_text", ""))
        payload = inspect_command(command_text, cwd=Path.cwd(), home_dir=Path.home())
        if command_command == "explain":
            from .commands_support_service import _build_semantic_command_explain_payload

            semantic_payload = _build_semantic_command_explain_payload(command_text, workspace=Path.cwd())
            payload["action_explanation"] = semantic_payload["action_explanation"]
    except ValueError as error:
'''
if new_dispatch not in dispatch:
    dispatch = replace_once(dispatch, old_dispatch, new_dispatch, label="command explain production route")
dispatch_path.write_text(dispatch, encoding="utf-8")


cli_test_path = Path("tests/test_guard_semantic_explanations_cli.py")
cli_test_path.write_text(
    '''from __future__ import annotations

from codex_plugin_scanner.guard.cli.commands_support_service import _build_semantic_command_explain_payload


def test_production_command_explain_uses_versioned_semantic_contract(tmp_path) -> None:
    payload = _build_semantic_command_explain_payload("rm -rf ./build", workspace=tmp_path)
    explanation = payload["action_explanation"]
    assert isinstance(explanation, dict)
    assert explanation["schema_version"] == "guard.action-explanation.v1"
    assert explanation["kind"] == "file_delete"
    assert explanation["everyday"]["safer_alternatives"]
    assert payload["command_model"]["security_identity"] == explanation["canonical_identity"]
    assert payload["side_effects"] == "none"


def test_production_command_explain_redacts_bearer_credentials(tmp_path) -> None:
    bearer = "opaque-production-token-123456"
    payload = _build_semantic_command_explain_payload(
        f"curl -H 'Authorization: Bearer {bearer}' https://example.test/data",
        workspace=tmp_path,
    )
    explanation = payload["action_explanation"]
    assert bearer not in explanation["technical"]["command_display"]
    assert explanation["redaction"]["secret_like_values_removed"] is True
''',
    encoding="utf-8",
)
