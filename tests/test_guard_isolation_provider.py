"""Tests for the isolation provider contract and Guard-owned registry (wave two)."""

from __future__ import annotations

import hashlib

import pytest

from codex_plugin_scanner.guard.runtime import isolation_provider as isolation_provider_module
from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuarantee,
    AtomicGuaranteeKind,
    DecisionContext,
    ExecutionLease,
    GuardExecutionAssuranceBoundary,
    ProviderHealthState,
    ProviderIdentity,
    TerminalStatement,
)
from codex_plugin_scanner.guard.runtime.isolation_provider import (
    IsolationProvider,
    ProviderHealth,
    ProviderPlanError,
    ProviderRegistry,
    validate_provider_plan_inputs,
)

_SHA = "a" * 64
_OTHER = "b" * 64


class _FakeProvider:
    def __init__(self, kind: str = "local-seatbelt") -> None:
        self._identity = ProviderIdentity(
            provider_kind=kind,
            implementation_version="1.0.0",
            binary_or_image_digest=_SHA,
            signing_identity="guard-local",
            trust_domain="guard.local",
        )

    def identity(self) -> ProviderIdentity:
        return self._identity

    def capabilities(self) -> tuple[AtomicGuarantee, ...]:
        return (
            AtomicGuarantee(
                kind=AtomicGuaranteeKind.FILESYSTEM,
                enforced=True,
                boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
            ),
        )

    def health_check(self) -> ProviderHealth:
        return ProviderHealth(state=ProviderHealthState.HEALTHY, guarantees=self.capabilities())

    def plan(self, context: DecisionContext, minimum_boundary: GuardExecutionAssuranceBoundary) -> ExecutionLease:
        return ExecutionLease(
            plan_digest=_SHA,
            provider_thumbprint=self._identity.thumbprint(),
            fencing_generation=1,
            lease_expiry_epoch_seconds=1000,
            attempt_nonce="n1",
            input_manifest_digest=_OTHER,
        )

    def execute(self, lease: ExecutionLease) -> TerminalStatement:
        raise NotImplementedError

    def cancel(self, execution_instance: str) -> None:
        return None

    def cleanup(self, execution_instance: str) -> None:
        return None


def _registry(*, artifact_digest: str = _SHA) -> ProviderRegistry:
    return ProviderRegistry(artifact_digest_resolver=lambda _path: artifact_digest)


def _register(registry: ProviderRegistry, provider: _FakeProvider, path: str) -> ProviderIdentity:
    return registry.register(provider, configured_path=path, trust_anchor=provider.identity())


class TestProtocolConformance:
    def test_fake_provider_satisfies_protocol(self) -> None:
        assert isinstance(_FakeProvider(), IsolationProvider)

    def test_incomplete_provider_fails_protocol(self) -> None:
        class _NotAProvider:
            pass

        assert not isinstance(_NotAProvider(), IsolationProvider)


class TestPlanInputValidation:
    @pytest.mark.parametrize(
        "path",
        [
            "/home/user/project/.env",
            "secrets/.env",
            "/root/.ssh/id_rsa",
            "/repo/.git/config",
            "/var/run/docker.sock",
            "/run/containerd/containerd.sock",
            "/home/user/.hol-guard/state.db",
        ],
    )
    def test_rejects_forbidden_input(self, path: str) -> None:
        with pytest.raises(ProviderPlanError):
            validate_provider_plan_inputs((path,), ())

    @pytest.mark.parametrize(
        "path",
        [
            "/home/user/project/src/main.py",
            "/tmp/workspace/output.txt",
            "build/artifact.bin",
        ],
    )
    def test_allows_benign_input(self, path: str) -> None:
        validate_provider_plan_inputs((path,), ())

    def test_rejects_forbidden_declared_output(self) -> None:
        with pytest.raises(ProviderPlanError):
            validate_provider_plan_inputs((), ("/app/.env",))


class TestProviderRegistry:
    def test_registers_guard_owned_path(self) -> None:
        registry = _registry()
        identity = _register(registry, _FakeProvider(), "/usr/libexec/hol-guard/providers/seatbelt")
        assert identity.provider_kind == "local-seatbelt"

    def test_rejects_workspace_path(self) -> None:
        registry = _registry()
        with pytest.raises(ValueError, match="outside the Guard-owned provider root"):
            _register(registry, _FakeProvider(), "/home/user/project/.guard/provider")

    def test_rejects_relative_path(self) -> None:
        registry = _registry()
        with pytest.raises(ValueError, match="outside the Guard-owned provider root"):
            _register(registry, _FakeProvider(), "providers/seatbelt")

    def test_rejects_non_guard_root(self) -> None:
        with pytest.raises(ValueError, match="Guard-owned system path"):
            ProviderRegistry(provider_root="/home/user/providers")

    def test_identity_thumbprint_lookup(self) -> None:
        registry = _registry()
        provider = _FakeProvider()
        identity = _register(registry, provider, "/usr/libexec/hol-guard/providers/seatbelt")
        assert registry.get(identity.thumbprint()) is provider

    def test_rejects_thumbprint_collision_with_distinct_provider(self) -> None:
        registry = _registry()
        first = _FakeProvider()
        identity = _register(registry, first, "/usr/libexec/hol-guard/providers/seatbelt")
        other = _FakeProvider()
        with pytest.raises(ValueError, match="thumbprint collision"):
            _register(registry, other, "/usr/libexec/hol-guard/providers/seatbelt")
        assert registry.get(identity.thumbprint()) is first

    def test_rejects_untrusted_identity(self) -> None:
        provider = _FakeProvider()
        registry = _registry()
        untrusted = _FakeProvider(kind="other-provider").identity()
        with pytest.raises(ValueError, match="configured trust anchor"):
            registry.register(
                provider,
                configured_path="/usr/libexec/hol-guard/providers/seatbelt",
                trust_anchor=untrusted,
            )

    def test_rejects_artifact_digest_mismatch(self) -> None:
        provider = _FakeProvider()
        with pytest.raises(ValueError, match="artifact digest"):
            _register(_registry(artifact_digest=_OTHER), provider, "/usr/libexec/hol-guard/providers/seatbelt")


class TestProviderHealth:
    def test_rejects_non_state(self) -> None:
        with pytest.raises(ValueError, match="ProviderHealthState"):
            ProviderHealth(state="healthy", guarantees=())  # type: ignore[arg-type]


def test_registry_rejects_traversal_escape() -> None:
    registry = _registry()
    with __import__("pytest").raises(ValueError, match="outside the Guard-owned provider root"):
        _register(registry, _FakeProvider(), "/usr/libexec/hol-guard/providers/../evil/bin")


def test_artifact_digest_reader_rejects_symlinks(tmp_path) -> None:
    artifact = tmp_path / "provider"
    artifact.write_bytes(b"trusted-provider")
    expected = hashlib.sha256(b"trusted-provider").hexdigest()
    assert isolation_provider_module._sha256_regular_file(artifact) == expected

    link = tmp_path / "provider-link"
    link.symlink_to(artifact)
    with pytest.raises(ValueError, match="missing or unreadable"):
        isolation_provider_module._sha256_regular_file(link)


def test_plan_rejects_additional_vcs_names() -> None:
    for vcs in (".hg", ".svn", ".bzr"):
        with __import__("pytest").raises(ProviderPlanError):
            validate_provider_plan_inputs((f"/repo/{vcs}/config",), ())


def test_plan_rejects_symlink_to_forbidden_path(tmp_path) -> None:
    from codex_plugin_scanner.guard.runtime.isolation_provider import validate_provider_plan_inputs

    secret = tmp_path / ".ssh"
    secret.mkdir()
    link = tmp_path / "link"
    link.symlink_to(secret)
    with __import__("pytest").raises(ProviderPlanError):
        validate_provider_plan_inputs((str(link / "id_rsa"),), (str(tmp_path / "out"),))
