"""Unit tests for typed task-completion record schema and validation (#4185)."""

from __future__ import annotations

import pytest

from bernstein.core.tasks.completion_record import (
    AssumptionItem,
    CompletionRecordValidationError,
    ExportItem,
    ReopenTriggerItem,
    ReopenTriggerKind,
    TaskCompletionRecord,
    validate_completion_record,
)

_VALID_HASH_1 = "a" * 64
_VALID_HASH_2 = "b" * 64
_VALID_HASH_3 = "c" * 64


def test_valid_completion_record_round_trips() -> None:
    """A fully-valid record round-trips: serialize -> parse -> equal."""
    record = TaskCompletionRecord(
        task_id="T-4185",
        exports=(ExportItem(path="src/main.py", content_hash=_VALID_HASH_1),),
        assumptions=(
            AssumptionItem(kind="file", key_or_path="docs/spec.md", expected_value_or_hash=_VALID_HASH_2),
            AssumptionItem(
                kind="config", key_or_path="MAX_CONCURRENCY", expected_value_or_hash="10", note="check limit"
            ),
        ),
        receipt_refs=(_VALID_HASH_1, _VALID_HASH_3),
        reopen_triggers=(
            ReopenTriggerItem(kind=ReopenTriggerKind.ASSUMPTION_HASH_MISMATCH, referenced_hash=_VALID_HASH_2),
            ReopenTriggerItem(kind=ReopenTriggerKind.RECEIPT_INVALIDATED, referenced_hash=_VALID_HASH_3),
        ),
        timestamp=1700000000.0,
    )

    data = record.to_dict()
    restored = TaskCompletionRecord.from_dict(data)

    assert restored.task_id == record.task_id
    assert restored.exports == record.exports
    assert restored.assumptions == record.assumptions
    assert restored.receipt_refs == record.receipt_refs
    assert restored.reopen_triggers == record.reopen_triggers
    assert restored.timestamp == record.timestamp


def test_rejection_unknown_top_level_field() -> None:
    """Unknown top-level field is rejected with a clear reason."""
    payload = {
        "task_id": "T-1",
        "unknown_extra": 123,
    }
    with pytest.raises(CompletionRecordValidationError, match="Unknown top-level field"):
        TaskCompletionRecord.from_dict(payload)


def test_rejection_missing_or_empty_task_id() -> None:
    """Missing or empty task_id is rejected."""
    with pytest.raises(CompletionRecordValidationError, match="task_id"):
        TaskCompletionRecord.from_dict({"task_id": "   "})


def test_rejection_malformed_hash() -> None:
    """Malformed hash in exports or receipt_refs is rejected."""
    payload = {
        "task_id": "T-1",
        "receipt_refs": ["short_hash"],
    }
    with pytest.raises(CompletionRecordValidationError, match="malformed receipt hash"):
        TaskCompletionRecord.from_dict(payload)


def test_rejection_trigger_referencing_absent_hash() -> None:
    """A trigger referencing a hash present nowhere in the record is rejected."""
    record = TaskCompletionRecord(
        task_id="T-1",
        receipt_refs=(_VALID_HASH_1,),
        reopen_triggers=(ReopenTriggerItem(kind=ReopenTriggerKind.RECEIPT_INVALIDATED, referenced_hash=_VALID_HASH_2),),
    )
    with pytest.raises(CompletionRecordValidationError, match="present nowhere in record's sections"):
        validate_completion_record(record)


def test_rejection_claim_without_evidence() -> None:
    """A record whose receipt_refs is empty while exports assert verification fails validation."""
    record = TaskCompletionRecord(
        task_id="T-1",
        exports=(ExportItem(path="src/out.py", content_hash=_VALID_HASH_1),),
        receipt_refs=(),
    )
    with pytest.raises(CompletionRecordValidationError, match="receipt_refs' cannot be empty"):
        validate_completion_record(record)


def test_canonical_bytes_determinism_and_timestamp_exclusion() -> None:
    """Canonical bytes: two records built from same data serialize byte-identically; timestamp envelope changes do not alter canonical bytes."""
    r1 = TaskCompletionRecord(
        task_id="T-4185",
        exports=(ExportItem(path="src/a.py", content_hash=_VALID_HASH_1),),
        receipt_refs=(_VALID_HASH_1,),
        timestamp=100.0,
    )
    r2 = TaskCompletionRecord(
        task_id="T-4185",
        exports=(ExportItem(path="src/a.py", content_hash=_VALID_HASH_1),),
        receipt_refs=(_VALID_HASH_1,),
        timestamp=99999.9,
    )

    assert r1.canonical_bytes() == r2.canonical_bytes()
    assert b"timestamp" not in r1.canonical_bytes()
