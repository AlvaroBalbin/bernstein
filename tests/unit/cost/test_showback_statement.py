"""Showback statements: byte-identical projection, offline resolution (#2554 AC1, AC2).

The load-bearing test in this file is the field-flip sweep: every field of every
line item is mutated in turn and the verifier must reject each one. A statement
whose verifier passes a tampered item is a CSV with extra ceremony.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from bernstein.core.cost.showback_canonical import (
    FloatRejectedError,
    NonCanonicalTextError,
    nano_usd_from_float,
)
from bernstein.core.cost.showback_statement import (
    STATEMENT_SCHEMA,
    ShowbackLineItem,
    build_statement,
    line_items_root,
    statement_bytes,
    statement_hash,
    verify_statement,
)
from bernstein.core.cost.spend_ledger import LedgerEntry
from bernstein.core.security.tenant_charter import (
    CHARTER_MEMBER_ADD,
    CHARTER_OPEN,
    fold_charter,
    next_event,
)

HEAD = "a" * 64
SINCE = "2026-07-01"
UNTIL = "2026-08-01"


def _charter(tenant: str = "acme"):
    stamps = ["2026-07-01T00:00:00.000000Z", "2026-07-01T00:01:00.000000Z", "2026-07-01T00:02:00.000000Z"]
    events = [next_event(None, tenant_id=tenant, kind=CHARTER_OPEN, principal="alice", recorded_at=stamps[0])]
    for index, principal in enumerate(("alice", "bob"), start=1):
        events.append(
            next_event(
                events[-1],
                tenant_id=tenant,
                kind=CHARTER_MEMBER_ADD,
                principal="alice",
                body={"principal": principal, "role": "member"},
                recorded_at=stamps[index],
            )
        )
    return fold_charter(events)


def _items(tenant: str = "acme") -> list[ShowbackLineItem]:
    return [
        ShowbackLineItem(
            line_id=f"line:{index:032d}",
            tenant_id=tenant,
            task_id=f"task-{index}",
            run_id=f"run-{index}",
            model="claude-opus-4",
            occurred_at=f"2026-07-1{index}T12:00:00Z",
            amount_nano_usd=amount,
            lineage_record_id=f"lineage-{index}",
            audit_entry_hmac=f"{index:064x}",
        )
        for index, amount in enumerate((1_234_567_891, 250_000_000, 7), start=1)
    ]


def _statement(tenant: str = "acme") -> dict[str, Any]:
    return build_statement(
        charter=_charter(tenant),
        line_items=_items(tenant),
        since=SINCE,
        until=UNTIL,
        head_sha256=HEAD,
    )


# ---------------------------------------------------------------------------
# AC1 - byte-identical statements
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_repeated_builds_are_byte_identical(self) -> None:
        assert statement_bytes(_statement()) == statement_bytes(_statement())

    def test_totals_are_exact_integer_sums(self) -> None:
        statement = _statement()
        assert statement["totals"]["amount_nano_usd"] == str(1_234_567_891 + 250_000_000 + 7)
        assert statement["totals"]["amount_usd"] == "1.484567898"
        assert statement["totals"]["line_item_count"] == 3

    def test_aggregation_order_cannot_change_a_digit(self) -> None:
        """Totals are integer sums, so summing in any order gives one answer."""
        items = _items()
        forward = build_statement(charter=_charter(), line_items=items, since=SINCE, until=UNTIL, head_sha256=HEAD)
        backward = build_statement(
            charter=_charter(), line_items=list(reversed(items)), since=SINCE, until=UNTIL, head_sha256=HEAD
        )
        assert forward["totals"]["amount_nano_usd"] == backward["totals"]["amount_nano_usd"]
        # Order still matters to the fold, which is what catches reordering.
        assert forward["line_items_root"] != backward["line_items_root"]

    def test_statement_is_byte_identical_in_a_fresh_interpreter(self, tmp_path: Path) -> None:
        """AC1: finance and the team recompute rather than reconcile."""
        statement = _statement()
        expected = statement_bytes(statement)
        payload_path = tmp_path / "statement.json"
        payload_path.write_bytes(expected)

        script = (
            "import json,sys;"
            "from bernstein.core.cost.showback_statement import statement_bytes;"
            "d=json.loads(open(sys.argv[1],'rb').read());"
            "sys.stdout.buffer.write(statement_bytes(d))"
        )
        for seed in ("0", "7", "99991"):
            proc = subprocess.run(
                [sys.executable, "-c", script, str(payload_path)],
                check=True,
                capture_output=True,
                env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
            )
            assert proc.stdout == expected

    def test_statement_carries_the_charter_binding(self) -> None:
        charter = _charter()
        statement = build_statement(
            charter=charter,
            line_items=_items(),
            since=SINCE,
            until=UNTIL,
            head_sha256=HEAD,
            certificate_hash="sha256:beef",
            certificate_version="3",
        )
        assert statement["binding"]["charter_hash"] == charter.charter_hash()
        assert statement["binding"]["certificate_version"] == "3"
        assert statement["schema"] == STATEMENT_SCHEMA


# ---------------------------------------------------------------------------
# Money discipline
# ---------------------------------------------------------------------------


class TestMoneyDiscipline:
    def test_rounding_happens_once_from_the_ledger_float(self) -> None:
        entry = LedgerEntry(
            ts=1.0,
            ts_iso="2026-07-10T00:00:00Z",
            run_id="run-1",
            task_id="task-1",
            agent_id="agent-1",
            role="backend",
            feature_label="f",
            model="claude-opus-4",
            input_tokens=1,
            output_tokens=1,
            cache_read_tokens=0,
            cache_write_tokens=0,
            cost_usd=0.0000000015,
        )
        item = ShowbackLineItem.from_ledger_entry(entry, tenant_id="acme")
        assert item.amount_nano_usd == nano_usd_from_float(0.0000000015)
        assert item.to_body()["amount_nano_usd"] == str(item.amount_nano_usd)
        # And the encoded amount is a string, so no float reaches the payload.
        assert isinstance(item.to_body()["amount_nano_usd"], str)

    def test_line_id_is_derived_deterministically(self) -> None:
        entry = LedgerEntry(
            ts=1.0,
            ts_iso="2026-07-10T00:00:00Z",
            run_id="run-1",
            task_id="task-1",
            agent_id="agent-1",
            role="backend",
            feature_label="f",
            model="claude-opus-4",
            input_tokens=1,
            output_tokens=1,
            cache_read_tokens=0,
            cache_write_tokens=0,
            cost_usd=1.0,
        )
        first = ShowbackLineItem.from_ledger_entry(entry, tenant_id="acme")
        second = ShowbackLineItem.from_ledger_entry(entry, tenant_id="acme")
        assert first.line_id == second.line_id

    def test_a_float_in_a_payload_is_rejected(self) -> None:
        statement = _statement()
        statement["line_items"][0]["amount_nano_usd"] = 1.5
        with pytest.raises(FloatRejectedError):
            statement_bytes(statement)

    def test_non_nfc_text_is_rejected_not_normalized(self) -> None:
        statement = _statement()
        statement["line_items"][0]["model"] = "café-model"
        with pytest.raises(NonCanonicalTextError):
            statement_bytes(statement)

    def test_foreign_tenant_items_are_refused_at_build_time(self) -> None:
        stray = _items("globex")
        with pytest.raises(ValueError, match="foreign tenants"):
            build_statement(charter=_charter(), line_items=stray, since=SINCE, until=UNTIL, head_sha256=HEAD)

    def test_empty_window_is_refused(self) -> None:
        with pytest.raises(ValueError, match="must be <"):
            build_statement(charter=_charter(), line_items=[], since=UNTIL, until=SINCE, head_sha256=HEAD)

    def test_an_empty_statement_is_well_formed(self) -> None:
        statement = build_statement(charter=_charter(), line_items=[], since=SINCE, until=UNTIL, head_sha256=HEAD)
        assert statement["totals"]["amount_nano_usd"] == "0"
        assert verify_statement(statement).ok


# ---------------------------------------------------------------------------
# AC2 - every line item resolves offline; any flip is detected
# ---------------------------------------------------------------------------


class TestVerification:
    def test_a_clean_statement_verifies(self) -> None:
        statement = _statement()
        result = verify_statement(statement, expected_head_sha256=HEAD, expected_charter_hash=_charter().charter_hash())
        assert result.ok, result.errors
        assert result.line_item_count == 3
        assert result.total_nano_usd == 1_484_567_898

    def test_verification_needs_only_the_statement(self, tmp_path: Path) -> None:
        """AC2: the statement, and nothing else, is sufficient to verify."""
        path = tmp_path / "statement.json"
        path.write_bytes(statement_bytes(_statement()))
        reloaded = json.loads(path.read_text(encoding="utf-8"))
        assert verify_statement(reloaded).ok

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("line_id", "line:tampered"),
            ("task_id", "task-999"),
            ("run_id", "run-999"),
            ("model", "cheap-model"),
            ("occurred_at", "2020-01-01T00:00:00Z"),
            ("amount_nano_usd", "1"),
            ("amount_usd", "0.000000001"),
            ("lineage_record_id", "lineage-999"),
            ("audit_entry_hmac", "f" * 64),
            ("tenant_id", "globex"),
        ],
    )
    def test_flipping_any_line_item_field_is_detected(self, field: str, value: str) -> None:
        """AC2: flipping any single field of any line item fails verification."""
        for index in range(3):
            statement = copy.deepcopy(_statement())
            assert statement["line_items"][index][field] != value, "the flip must actually change something"
            statement["line_items"][index][field] = value
            result = verify_statement(statement)
            assert not result.ok, f"flipping line_items[{index}].{field} went undetected"
            assert result.errors

    def test_flipping_a_field_and_repairing_the_statement_hash_is_still_detected(self) -> None:
        """A tamperer who recomputes the outer hash still trips the item fold."""
        statement = copy.deepcopy(_statement())
        statement["line_items"][1]["amount_nano_usd"] = "999999999999"
        statement["line_items"][1]["amount_usd"] = "999.999999999"
        statement["statement_hash"] = statement_hash(statement)
        result = verify_statement(statement)
        assert not result.ok
        assert any("line_items_root" in err for err in result.errors)

    def test_repairing_the_root_too_still_trips_the_totals(self) -> None:
        statement = copy.deepcopy(_statement())
        statement["line_items"][1]["amount_nano_usd"] = "999999999999"
        statement["line_items"][1]["amount_usd"] = "999.999999999"
        items = [ShowbackLineItem.from_body(raw) for raw in statement["line_items"]]
        statement["line_items_root"] = line_items_root(items)
        statement["statement_hash"] = statement_hash(statement)
        result = verify_statement(statement)
        assert not result.ok
        assert any("amount_nano_usd" in err for err in result.errors)

    def test_dropping_a_line_item_is_detected(self) -> None:
        statement = copy.deepcopy(_statement())
        del statement["line_items"][1]
        result = verify_statement(statement)
        assert not result.ok
        assert any("line_items_root" in err for err in result.errors)

    def test_inserting_a_line_item_is_detected(self) -> None:
        statement = copy.deepcopy(_statement())
        statement["line_items"].append(dict(statement["line_items"][0]))
        assert not verify_statement(statement).ok

    def test_reordering_line_items_is_detected(self) -> None:
        statement = copy.deepcopy(_statement())
        statement["line_items"].reverse()
        result = verify_statement(statement)
        assert not result.ok
        assert any("reordered" in err for err in result.errors)

    def test_flipping_the_window_is_detected(self) -> None:
        statement = copy.deepcopy(_statement())
        statement["window"]["until"] = "2027-01-01"
        assert not verify_statement(statement).ok

    def test_flipping_the_head_anchor_is_detected(self) -> None:
        statement = copy.deepcopy(_statement())
        statement["head_anchor"]["head_sha256"] = "b" * 64
        assert not verify_statement(statement).ok

    def test_a_head_anchor_mismatch_against_the_shared_head_is_reported(self) -> None:
        statement = _statement()
        result = verify_statement(statement, expected_head_sha256="b" * 64)
        assert not result.ok
        assert any("head anchor" in err for err in result.errors)

    def test_a_charter_hash_mismatch_is_reported(self) -> None:
        result = verify_statement(_statement(), expected_charter_hash="sha256:not-this-one")
        assert not result.ok
        assert any("charter" in err for err in result.errors)

    def test_a_wrong_schema_tag_is_reported(self) -> None:
        statement = copy.deepcopy(_statement())
        statement["schema"] = "something-else-v1"
        result = verify_statement(statement)
        assert not result.ok
        assert any("schema" in err for err in result.errors)

    def test_a_missing_line_items_list_is_reported(self) -> None:
        result = verify_statement({"tenant_id": "acme", "schema": STATEMENT_SCHEMA})
        assert not result.ok
        assert any("line_items" in err for err in result.errors)

    def test_a_corrupted_totals_block_is_reported(self) -> None:
        statement = copy.deepcopy(_statement())
        statement["totals"]["amount_nano_usd"] = "not-a-number"
        result = verify_statement(statement)
        assert not result.ok
        assert any("not an integer" in err for err in result.errors)

    def test_verification_result_serializes(self) -> None:
        payload = verify_statement(_statement()).to_dict()
        assert payload["ok"] is True
        assert payload["total_usd"] == "1.484567898"
        json.dumps(payload)
