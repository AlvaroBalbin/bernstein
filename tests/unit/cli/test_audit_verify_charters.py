"""``bernstein audit verify`` must fold recorded tenant charters, not just the HMAC chain.

``audit_chain_ok`` answers "are these bytes authentic". It does not answer "is
the guarantee intact". A charter segment carrying two events that claim the same
``seq`` is permanently unreadable while every one of its bytes is authentically
signed, so before this pillar existed the command exited 0 on a bricked charter.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from click.testing import CliRunner

from bernstein.cli.commands.audit_cmd import audit_group
from bernstein.core.security.audit import AUDIT_KEY_ENV
from bernstein.core.security.audit_chain import EVENT_TENANT_CHARTER, AuditChainStore
from bernstein.core.security.tenant_charter import (
    CHARTER_MEMBER_ADD,
    CHARTER_OPEN,
    next_event,
    record_charter_event,
)

AUDIT_DIR = Path(".sdd/audit")


@pytest.fixture
def isolated_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    key_path = tmp_path / "audit.key"
    key_path.write_bytes(b"a" * 64)
    key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    monkeypatch.setenv(AUDIT_KEY_ENV, str(key_path))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _open_charter(tenant_id: str = "acme") -> AuditChainStore:
    chain = AuditChainStore(AUDIT_DIR)
    opening = next_event(None, tenant_id=tenant_id, kind=CHARTER_OPEN, principal="alice")
    member = next_event(
        opening,
        tenant_id=tenant_id,
        kind=CHARTER_MEMBER_ADD,
        principal="alice",
        body={"principal": "alice", "role": "owner"},
    )
    for event in (opening, member):
        record_charter_event(chain, event)
    return chain


def _splice_duplicate_opening(tenant_id: str = "acme") -> None:
    """Append a second, individually valid, ``seq == 0`` event for *tenant_id*.

    This is what two racing processes produced: both records HMAC-verify, and
    the log is append-only, so the duplicate can never be taken back out.
    """
    from bernstein.core.security.audit import AuditLog, load_or_create_audit_key

    log = AuditLog(AUDIT_DIR, key=load_or_create_audit_key())
    day_file = next(iter(sorted(AUDIT_DIR.glob("*.jsonl"))))
    first = next(
        json.loads(line)
        for line in day_file.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["event_type"] == EVENT_TENANT_CHARTER
    )
    body = dict(first["details"]["charter"])
    body["principal"] = "mallory"
    log.log(
        event_type=EVENT_TENANT_CHARTER,
        actor="mallory",
        resource_type="tenant",
        resource_id=tenant_id,
        details={"charter": body, "tenant_id": tenant_id},
    )


def test_verify_passes_on_an_intact_charter(isolated_audit: Path) -> None:
    _open_charter()
    # ``--hmac-only`` skips the Merkle seal; the charter pillar is orthogonal to
    # both and must still run.
    result = CliRunner().invoke(audit_group, ["verify", "--hmac-only"])
    assert result.exit_code == 0, result.output
    assert "Tenant Charter Verification Passed" in result.output


def test_verify_is_a_silent_no_op_when_no_charter_exists(isolated_audit: Path) -> None:
    AuditChainStore(AUDIT_DIR).log(event_type="unrelated", actor="a", resource_type="r", resource_id="i")
    # ``--hmac-only`` skips the Merkle seal; the charter pillar is orthogonal to
    # both and must still run.
    result = CliRunner().invoke(audit_group, ["verify", "--hmac-only"])
    assert result.exit_code == 0, result.output
    assert "Tenant Charter" not in result.output


def test_verify_fails_on_a_duplicate_seq_while_the_hmac_chain_stays_clean(isolated_audit: Path) -> None:
    """The whole point of the pillar: authentic bytes, broken history.

    The HMAC pillar must still pass - the duplicate is a genuine, correctly
    signed record - and the charter pillar must still fail. If the HMAC pillar
    failed too, this test would be proving something else.
    """
    _open_charter()
    _splice_duplicate_opening()

    # ``--hmac-only`` skips the Merkle seal; the charter pillar is orthogonal to
    # both and must still run.
    result = CliRunner().invoke(audit_group, ["verify", "--hmac-only"])
    assert result.exit_code == 1, result.output
    assert "HMAC Chain Verification Passed" in result.output, "the bytes are authentic; only the fold is broken"
    assert "Tenant Charter Verification FAILED" in result.output
    assert "charter acme" in result.output


def test_the_fold_reason_stays_distinct_from_an_hmac_error(isolated_audit: Path) -> None:
    """Different causes, different remedies: altered bytes vs inconsistent history.

    Collapsing the two would destroy the diagnostic that tells an operator
    whether they are looking at tampering or at a concurrency defect.
    """
    _open_charter()
    _splice_duplicate_opening()

    # ``--hmac-only`` skips the Merkle seal; the charter pillar is orthogonal to
    # both and must still run.
    result = CliRunner().invoke(audit_group, ["verify", "--hmac-only"])
    assert "gap" in result.output or "bad_seq" in result.output, result.output
    assert "HMAC mismatch" not in result.output
