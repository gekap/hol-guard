#!/usr/bin/env python3
"""Rewrite the bundled native manifest to match PyInstaller-packaged runtime bytes."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import zlib
from pathlib import Path

_SIGNING_PATH = Path(__file__).with_name("verify_pyinstaller_macos_signing.py")
_RUNTIME_NAMES = {"hol-guard-runtime", "hol-guard-runtime.exe"}
_MANIFEST_NAME = "runtime-manifest.json"
_NATIVE_PARENT = "_native"
_MANIFEST_SCHEMA = "hol-guard-native-runtime.v1"


class NativeManifestSealError(ValueError):
    """Raised when the packaged native manifest cannot be resealed in place."""


def _load_signing_module():
    spec = importlib.util.spec_from_file_location("verify_pyinstaller_macos_signing", _SIGNING_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("PyInstaller signing verifier is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _posix_name(name: str) -> str:
    return name.replace("\\", "/")


def _is_native_runtime_entry(name: str) -> bool:
    parts = Path(_posix_name(name)).parts
    return len(parts) >= 2 and parts[-1] in _RUNTIME_NAMES and parts[-2] == _NATIVE_PARENT


def _is_native_manifest_entry(name: str) -> bool:
    parts = Path(_posix_name(name)).parts
    return len(parts) >= 2 and parts[-1] == _MANIFEST_NAME and parts[-2] == _NATIVE_PARENT


def _encode_manifest(payload: dict[str, object], *, compressed: bool, stored_length: int) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    packed = zlib.compress(encoded) if compressed else encoded
    if len(packed) > stored_length:
        raise NativeManifestSealError("resealed native manifest does not fit the packaged entry")
    if compressed and len(packed) != stored_length:
        raise NativeManifestSealError("compressed native manifest cannot be padded in place")
    if not compressed:
        packed = packed + (b" " * (stored_length - len(packed)))
    return packed


def seal(binary: Path) -> None:
    signing = _load_signing_module()
    archive_start, _declared_runtime, entries = signing._archive_layout(binary)
    runtime_entries = [entry for entry in entries if _is_native_runtime_entry(entry[0])]
    manifest_entries = [entry for entry in entries if _is_native_manifest_entry(entry[0])]
    if len(runtime_entries) != 1:
        raise NativeManifestSealError(
            f"Core archive must contain exactly one native runtime; found {len(runtime_entries)}"
        )
    if len(manifest_entries) != 1:
        raise NativeManifestSealError(
            f"Core archive must contain exactly one native manifest; found {len(manifest_entries)}"
        )
    runtime_name, runtime_offset, runtime_length, runtime_compressed, _typecode = runtime_entries[0]
    manifest_name, manifest_offset, manifest_length, manifest_compressed, _manifest_type = manifest_entries[0]
    with binary.open("r+b") as handle:
        runtime = signing._entry_bytes(
            handle,
            archive_start,
            runtime_name,
            runtime_offset,
            runtime_length,
            runtime_compressed,
        )
        manifest_bytes = signing._entry_bytes(
            handle,
            archive_start,
            manifest_name,
            manifest_offset,
            manifest_length,
            manifest_compressed,
        )
        try:
            payload = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NativeManifestSealError("Bundled native manifest is not valid JSON") from error
        if not isinstance(payload, dict) or payload.get("schema") != _MANIFEST_SCHEMA:
            raise NativeManifestSealError("Bundled native manifest failed identity checks")
        digest = hashlib.sha256(runtime).hexdigest()
        if payload.get("runtime_sha256") == digest and payload.get("runtime_size") == len(runtime):
            print(f"native manifest already matches packaged runtime {runtime_name!r}")
            return
        payload["runtime_sha256"] = digest
        payload["runtime_size"] = len(runtime)
        packed = _encode_manifest(payload, compressed=manifest_compressed, stored_length=manifest_length)
        handle.seek(archive_start + manifest_offset)
        written = handle.write(packed)
        if written != manifest_length:
            raise NativeManifestSealError("failed to overwrite the packaged native manifest")
    print(f"resealed native manifest for {runtime_name!r} ({len(runtime)} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file():
        raise SystemExit(f"Binary does not exist: {args.binary}")
    try:
        seal(args.binary)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
