from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "contracts/managed-controls/fleet-extension-contract-manifest.json"


def test_fleet_extension_manifest_pins_every_shared_file() -> None:
    manifest = cast(dict[str, object], json.loads(MANIFEST.read_text(encoding="utf-8")))
    assert manifest["schemaVersion"] == "guard.fleet-extension-contract-manifest.v1"
    files = cast(list[dict[str, str]], manifest["files"])
    assert len(files) == len({entry["path"] for entry in files})
    for entry in files:
        shared_file = ROOT / entry["path"]
        assert shared_file.is_file(), entry["path"]
        assert hashlib.sha256(shared_file.read_bytes()).hexdigest() == entry["sha256"]
