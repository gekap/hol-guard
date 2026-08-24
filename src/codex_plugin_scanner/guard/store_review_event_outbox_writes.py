"""Transactional writes for the local Review event outbox."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from hashlib import blake2b
from uuid import uuid4

from .store_review_event_outbox_binding import load_review_oauth_binding
from .store_review_event_outbox_schema import REVIEW_EVENT_SCHEMA_VERSION, review_event_payload_json

# pyright: reportAny=false, reportUnusedCallResult=false


def _binding_for_append(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    source: str,
) -> tuple[Mapping[str, str | None], str, str | None]:
    current = load_review_oauth_binding(connection, source)
    prior = connection.execute(
        """
        select oauth_subject_hash, workspace_id, machine_id, machine_installation_id
        from guard_review_outbox_request_sequences
        where local_request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if prior is None:
        values = current or {
            "oauth_subject_hash": None,
            "workspace_id": None,
            "machine_id": None,
            "machine_installation_id": None,
        }
        return (
            values,
            "ready" if current is not None else "quarantined",
            (None if current is not None else "identity_incomplete"),
        )
    prior_values = {
        key: prior[key] for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    prior_complete = all(isinstance(value, str) and value.strip() for value in prior_values.values())
    if not prior_complete:
        return prior_values, "quarantined", "identity_incomplete"
    if current is None or (
        prior_values["oauth_subject_hash"] != current["oauth_subject_hash"]
        or prior_values["workspace_id"] != current["workspace_id"]
    ):
        return prior_values, "quarantined", "identity_changed_requires_confirmation"
    return current, "ready", None


def append_request_snapshot_event(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    source: str,
    event_type: str,
    occurred_at: str,
) -> int:
    """Append a request snapshot without replacing any unacknowledged event."""

    request = connection.execute(
        "select * from approval_requests where request_id = ?",
        (request_id,),
    ).fetchone()
    if request is None:
        return 0
    values, binding_status, quarantine_reason = _binding_for_append(
        connection,
        request_id=request_id,
        source=source,
    )
    payload = review_event_payload_json(
        dict(request),
        event_type=event_type,
        occurred_at=occurred_at,
    )
    connection.execute(
        """
        insert into guard_review_outbox_request_sequences (
          local_request_id, last_sequence, updated_at
        ) values (?, 1, ?)
        on conflict(local_request_id) do update set
          last_sequence = guard_review_outbox_request_sequences.last_sequence + 1,
          updated_at = excluded.updated_at
        """,
        (request_id, occurred_at),
    )
    row = connection.execute(
        "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("Review event request sequence allocation failed.")
    request_sequence = int(row["last_sequence"])
    cursor = connection.execute(
        """
        insert into guard_review_outbox_events (
          event_id, local_request_id, request_sequence, event_type, event_schema_version,
          payload_json, payload_hash, occurred_at, oauth_source, oauth_subject_hash,
          workspace_id, machine_id, machine_installation_id, binding_status, quarantine_reason
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            uuid4().hex,
            request_id,
            request_sequence,
            event_type,
            REVIEW_EVENT_SCHEMA_VERSION,
            payload,
            blake2b(payload.encode("utf-8"), digest_size=32).hexdigest(),
            occurred_at,
            source,
            values["oauth_subject_hash"],
            values["workspace_id"],
            values["machine_id"],
            values["machine_installation_id"],
            binding_status,
            quarantine_reason,
        ),
    )
    return max(0, int(cursor.rowcount or 0))


def requeue_pending_request_events(connection: sqlite3.Connection, *, source: str, changed_at: str) -> int:
    connection.execute("begin immediate")
    rows = connection.execute(
        """
        select request_id from approval_requests
        where status = 'pending' and oauth_source = ?
        order by coalesce(last_seen_at, created_at), request_id
        """,
        (source,),
    ).fetchall()
    return sum(
        append_request_snapshot_event(
            connection,
            request_id=str(row["request_id"]),
            source=source,
            event_type="review.request.snapshot_requeued",
            occurred_at=changed_at,
        )
        for row in rows
    )
