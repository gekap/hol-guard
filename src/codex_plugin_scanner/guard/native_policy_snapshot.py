"""Generation-bound native policy snapshots for PostToolUse envelopes."""

from __future__ import annotations

import hashlib
import itertools
import json
import time

_POLICY_GENERATIONS = itertools.count(max(1, time.time_ns()))


def native_policy_snapshot(*, rule_digest: str, observe_mode: bool) -> dict[str, object]:
    mode = "observe" if observe_mode else "enforce"
    config_bytes = json.dumps({"mode": mode}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    policy_bytes = json.dumps(
        {"config_digest": config_digest, "rule_digest": rule_digest},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "schema": "hol-guard-native-policy.v1",
        "generation": next(_POLICY_GENERATIONS),
        "policy_digest": hashlib.sha256(policy_bytes).hexdigest(),
        "config_digest": config_digest,
        "rule_digest": rule_digest,
        "mode": mode,
    }
