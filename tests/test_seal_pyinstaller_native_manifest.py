from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SEALER = ROOT / "scripts" / "release" / "seal_pyinstaller_native_manifest.py"
VERIFIER = ROOT / "scripts" / "release" / "verify_pyinstaller_native_runtime.py"
SIGNING = ROOT / "scripts" / "release" / "verify_pyinstaller_macos_signing.py"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fake_archive(
    path: Path,
    *,
    declared_runtime: str,
    entries: list[tuple[str, bytes, str]],
) -> None:
    signing = _load(SIGNING, "verify_pyinstaller_macos_signing")
    payload = bytearray()
    toc = bytearray()
    for name, data, typecode in entries:
        offset = len(payload)
        payload.extend(data)
        raw_name = name.encode("utf-8") + b"\0"
        entry_length = signing.TOC_HEADER_LENGTH + len(raw_name)
        toc.extend(
            struct.pack(
                signing.TOC_FORMAT,
                entry_length,
                offset,
                len(data),
                len(data),
                0,
                typecode.encode("ascii"),
            )
        )
        toc.extend(raw_name)

    raw_runtime = declared_runtime.encode("utf-8")
    assert len(raw_runtime) < 64
    cookie = struct.pack(
        signing.COOKIE_FORMAT,
        signing.COOKIE_MAGIC,
        len(payload) + len(toc) + signing.COOKIE_LENGTH,
        len(payload),
        len(toc),
        312,
        raw_runtime + (b"\0" * (64 - len(raw_runtime))),
    )
    path.write_bytes(bytes(payload) + bytes(toc) + cookie)


def _manifest(*, runtime: bytes, digest: str | None = None) -> dict[str, object]:
    return {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "3.0.14",
        "target": "aarch64-apple-darwin",
        "platform_tag": "macosx_11_0_arm64",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": digest if digest is not None else hashlib.sha256(runtime).hexdigest(),
        "runtime_size": len(runtime),
    }


def test_sealer_rewrites_stale_manifest_after_packaged_runtime_changes(tmp_path: Path) -> None:
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"re-signed-native-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=[
            ("Python", b"\xcf\xfa\xed\xfe-runtime", "b"),
            ("codex_plugin_scanner/_native/hol-guard-runtime", runtime, "x"),
            (
                "codex_plugin_scanner/_native/runtime-manifest.json",
                json.dumps(_manifest(runtime=runtime, digest="c" * 64)).encode("utf-8"),
                "x",
            ),
        ],
    )

    with pytest.raises(ValueError, match="digest"):
        verifier.verify(archive)

    sealer.seal(archive)
    verifier.verify(archive)


def test_sealer_is_idempotent_when_manifest_already_matches(tmp_path: Path) -> None:
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"signed-native-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=[
            ("Python", b"\xcf\xfa\xed\xfe-runtime", "b"),
            ("codex_plugin_scanner/_native/hol-guard-runtime", runtime, "x"),
            (
                "codex_plugin_scanner/_native/runtime-manifest.json",
                json.dumps(_manifest(runtime=runtime)).encode("utf-8"),
                "x",
            ),
        ],
    )

    sealer.seal(archive)
    verifier.verify(archive)
