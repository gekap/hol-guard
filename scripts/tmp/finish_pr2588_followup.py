from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


service_path = Path("src/codex_plugin_scanner/guard/cli/commands_support_service.py")
service = service_path.read_text(encoding="utf-8")
service = replace_once(
    service,
    '''def _build_semantic_command_explain_payload(
    command_text: str,
    *,
    workspace: Path | None = None,
) -> dict[str, object]:''',
    '''def _build_semantic_command_explain_payload(
    command_text: str,
    *,
    workspace: Path | None = None,
    exact_details_authorized: bool = True,
    retained: bool = True,
) -> dict[str, object]:''',
    label="semantic helper signature",
)
service = replace_once(
    service,
    '''            exact_details_authorized=True,
            retained=True,''',
    '''            exact_details_authorized=exact_details_authorized,
            retained=retained,''',
    label="semantic helper trust inputs",
)
service_path.write_text(service, encoding="utf-8")


admin_path = Path("src/codex_plugin_scanner/guard/cli/commands_dispatch_admin.py")
admin = admin_path.read_text(encoding="utf-8")
admin = replace_once(
    admin,
    '''    store = _require_guard_store(store)
    if bool(getattr(args, "explain_as_command", False)):
        from .commands_support_service import _build_semantic_command_explain_payload

        payload = _build_semantic_command_explain_payload(str(args.target), workspace=workspace)
    elif str(args.target).strip().lower() == "install-connect":
        payload = build_install_connect_docs_payload()
    else:
        payload = _build_explain_payload_with_mode(store, args.target, cisco_mode=args.cisco_mode)
''',
    '''    if bool(getattr(args, "explain_as_command", False)):
        from .commands_support_service import _build_semantic_command_explain_payload

        payload = _build_semantic_command_explain_payload(str(args.target), workspace=workspace)
    else:
        store = _require_guard_store(store)
        if str(args.target).strip().lower() == "install-connect":
            payload = build_install_connect_docs_payload()
        else:
            payload = _build_explain_payload_with_mode(store, args.target, cisco_mode=args.cisco_mode)
''',
    label="store-free command explanation route",
)
admin_path.write_text(admin, encoding="utf-8")


cli_test_path = Path("tests/test_guard_semantic_explanations_cli.py")
tests = cli_test_path.read_text(encoding="utf-8")
addition = '''


def test_production_helper_preserves_authorization_and_retention(tmp_path) -> None:
    unauthorized = _build_semantic_command_explain_payload(
        "rm -rf ./build",
        workspace=tmp_path,
        exact_details_authorized=False,
    )["action_explanation"]
    assert unauthorized["technical"]["available"] is False
    assert unauthorized["technical"]["unavailable_reason"] == "not_authorized"
    assert unauthorized["technical"]["command_display"] is None

    unretained = _build_semantic_command_explain_payload(
        "rm -rf ./build",
        workspace=tmp_path,
        retained=False,
    )["action_explanation"]
    assert unretained["technical"]["available"] is False
    assert unretained["technical"]["unavailable_reason"] == "not_retained"
    assert unretained["technical"]["command_display"] is None
'''
if "def test_production_helper_preserves_authorization_and_retention" not in tests:
    tests += addition
cli_test_path.write_text(tests, encoding="utf-8")
