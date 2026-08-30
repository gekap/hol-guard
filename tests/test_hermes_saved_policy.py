"""Hermes saved-policy regressions for issue 2675."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import service
from codex_plugin_scanner.guard.models import DecisionScope, GuardArtifact, HarnessDetection, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.types import GuardVerdict, GuardVerdictAction

_NOW = "2026-08-30T13:00:00+00:00"


def _verdict(*, suppressible: bool = True, action: GuardVerdictAction = "warn") -> GuardVerdict:
    return GuardVerdict(
        action=action,
        severity=5 if suppressible else 7,
        confidence=0.9,
        reasons=("Hermes regression warning",),
        recommended_next_actions=("review_network_destination",),
        suppressible=suppressible,
        review_priority="medium" if suppressible else "high",
        evidence_sources=("artifact",),
        provenance_state="none",
    )


def _hermes_detection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    artifact_count: int,
) -> tuple[HarnessDetection, GuardStore, Path, Path]:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir(parents=True)
    hermes_home = home / ".hermes"
    category = hermes_home / "skills" / "apple"
    category.mkdir(parents=True)
    for index in range(artifact_count):
        skill = category / f"skill-{index:03d}"
        skill.mkdir()
        (skill / "SKILL.md").write_text(
            "---\n"
            f"name: skill-{index:03d}\n"
            "description: Hermes saved-policy regression fixture\n"
            "---\n"
            "Read notes and summarize them.\n",
            encoding="utf-8",
        )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    detection = HermesHarnessAdapter().detect(
        HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)
    )
    assert len(detection.artifacts) == artifact_count
    return detection, GuardStore(guard_home), guard_home, workspace


def _record_allow(store: GuardStore, scope: DecisionScope) -> None:
    store.upsert_policy(
        PolicyDecision(
            harness="hermes",
            scope=scope,
            action="allow",
            reason="issue-2675 regression",
        ),
        _NOW,
    )


@pytest.mark.parametrize("scope", ("harness", "global"))
def test_hermes_durable_allow_is_policy_not_exact_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope: DecisionScope,
) -> None:
    detection, store, guard_home, workspace = _hermes_detection(
        tmp_path, monkeypatch, artifact_count=3
    )
    _record_allow(store, scope)
    monkeypatch.setattr(service, "score_verdict", lambda *_args, **_kwargs: _verdict())

    result = service.evaluate_detection(
        detection,
        store,
        GuardConfig(
            guard_home=guard_home,
            workspace=workspace,
            default_action="review",
            changed_hash_action="review",
        ),
        persist=True,
    )

    assert result["blocked"] is False
    assert {item["policy_action"] for item in result["artifacts"]} == {"allow"}
    assert {item["approval_reuse_status"] for item in result["artifacts"]} == {"not-applicable"}
    assert {item["approval_reuse_reason_code"] for item in result["artifacts"]} == {
        "saved_policy_rule_applied"
    }
    assert {item["scanner_evidence"][-1]["source"] for item in result["artifacts"]} == {
        "saved_policy"
    }
    assert {receipt["approval_source"] for receipt in store.list_receipts(limit=10)} == {
        "saved-policy"
    }


def test_hermes_run_scale_honors_one_allow_for_350_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detection, store, guard_home, workspace = _hermes_detection(
        tmp_path, monkeypatch, artifact_count=350
    )
    _record_allow(store, "harness")
    monkeypatch.setattr(service, "score_verdict", lambda *_args, **_kwargs: _verdict())

    result = service.evaluate_detection(
        detection,
        store,
        GuardConfig(
            guard_home=guard_home,
            workspace=workspace,
            default_action="allow",
            changed_hash_action="allow",
            harness_actions={"hermes": "allow"},
        ),
        persist=False,
    )

    assert result["blocked"] is False
    assert len(result["artifacts"]) == 350
    assert {item["policy_action"] for item in result["artifacts"]} == {"allow"}
    assert {item["approval_reuse_reason_code"] for item in result["artifacts"]} == {
        "saved_policy_rule_applied"
    }


def test_hermes_explicit_allow_suppresses_only_suppressible_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detection, store, guard_home, workspace = _hermes_detection(
        tmp_path, monkeypatch, artifact_count=1
    )
    config = GuardConfig(
        guard_home=guard_home,
        workspace=workspace,
        default_action="allow",
        changed_hash_action="allow",
        harness_actions={"hermes": "allow"},
    )
    monkeypatch.setattr(service, "score_verdict", lambda *_args, **_kwargs: _verdict())

    suppressible = service.evaluate_detection(detection, store, config, persist=False)

    item = suppressible["artifacts"][0]
    assert item["policy_action"] == "allow"
    assert item["policy_composition"]["scanner_action"] is None
    assert item["policy_composition"]["scanner_recommendation_suppressed"] is True
    assert item["approval_reuse_reason_code"] == "approval_reuse_no_saved_decision"

    monkeypatch.setattr(
        service,
        "score_verdict",
        lambda *_args, **_kwargs: _verdict(suppressible=False),
    )
    non_suppressible = service.evaluate_detection(detection, store, config, persist=False)

    assert non_suppressible["artifacts"][0]["policy_action"] == "warn"
    assert non_suppressible["artifacts"][0]["policy_composition"]["scanner_action"] == "warn"


def test_hermes_durable_allow_never_lowers_reapproval_floor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detection, store, guard_home, workspace = _hermes_detection(
        tmp_path, monkeypatch, artifact_count=1
    )
    _record_allow(store, "harness")
    monkeypatch.setattr(
        service,
        "score_verdict",
        lambda *_args, **_kwargs: _verdict(
            suppressible=False, action="require_reapproval"
        ),
    )

    result = service.evaluate_detection(
        detection,
        store,
        GuardConfig(
            guard_home=guard_home,
            workspace=workspace,
            default_action="allow",
            changed_hash_action="allow",
            harness_actions={"hermes": "allow"},
        ),
        persist=False,
    )

    assert result["blocked"] is True
    assert result["artifacts"][0]["policy_action"] == "require-reapproval"
    assert result["artifacts"][0]["approval_reuse_reason_code"] == (
        "approval_reuse_reapproval_required"
    )


def test_hermes_broad_policy_cannot_approve_live_tool_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir()
    artifact = GuardArtifact(
        artifact_id="hermes:runtime:tool-action",
        name="Hermes live tool action",
        harness="hermes",
        artifact_type="tool_action_request",
        source_scope="workspace",
        config_path=str(workspace / "request.json"),
        command="python",
        args=("-c", "print('live')"),
        metadata={"guard_default_action": "review"},
    )
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    store = GuardStore(guard_home)
    _record_allow(store, "harness")
    monkeypatch.setattr(service, "score_verdict", lambda *_args, **_kwargs: _verdict(action="allow"))

    result = service.evaluate_detection(
        detection,
        store,
        GuardConfig(guard_home=guard_home, workspace=workspace),
        persist=False,
    )

    item = result["artifacts"][0]
    assert item["policy_action"] == "review"
    assert item["approval_reuse_reason_code"] == "approval_reuse_content_changed"
    assert item["policy_composition"].get("saved_policy_rule_selected", False) is False
