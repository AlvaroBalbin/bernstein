"""Charter writes must not hold the append section across archive reads.

The charter write commands read the full charter history - archived segments
included - before deciding what to append. Doing that read *inside* the
cross-process append section made the exclusive flock hold time O(total
history bytes): every archived segment was decompressed under the lock, and
every audit writer in every bernstein process stalled for the duration
(measured at ~0.6 s on a 270 MB archive, growing linearly).

The read is now two-phase. The full-history read (the expensive,
archive-decompressing one) runs before the section; inside the section only
live segments are re-read and merged. The merge is exact because every charter
append lands in the current day's live segment and retention never archives
the current day, so nothing recorded between the two phases can be missed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

import bernstein.core.security.audit as audit_mod
from bernstein.cli.commands.tenant_cmd import tenant_group

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    key_path = tmp_path / "audit.key"
    key_path.write_bytes(b"\x33" * 32)
    key_path.chmod(0o600)
    monkeypatch.setenv("BERNSTEIN_AUDIT_KEY_PATH", str(key_path))
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".sdd" / "audit").mkdir(parents=True)
    return tmp_path


def _run(args: list[str], workdir: Path) -> object:
    return CliRunner().invoke(tenant_group, [*args, "--workdir", str(workdir)])


def _archive_everything(workdir: Path) -> None:
    """Ordinary retention: every current segment ages out and is compressed."""
    from bernstein.core.security.audit import AuditLog, RetentionPolicy

    audit_dir = workdir / ".sdd" / "audit"
    key = (workdir / "audit.key").read_bytes()
    for path in sorted(audit_dir.glob("*.jsonl")):
        path.rename(audit_dir / "2020-01-01.jsonl")
    archived = AuditLog(audit_dir=audit_dir, key=key).archive(RetentionPolicy(retention_days=1)).archived
    assert archived == ["2020-01-01.jsonl"]


class TestTwoPhaseCharterRead:
    def test_archive_decompression_happens_outside_the_append_section(
        self, workdir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _run(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        _archive_everything(workdir)
        audit_dir = workdir / ".sdd" / "audit"

        in_section: list[bool] = []
        real_read = audit_mod._read_archived_segment

        def spy(gz_path: Path, errors: list[str]) -> bytes | None:
            in_section.append(audit_mod._inside_append_section(audit_dir))
            return real_read(gz_path, errors)

        monkeypatch.setattr(audit_mod, "_read_archived_segment", spy)
        granted = _run(["grant", "acme", "--principal", "carol", "--by", "alice"], workdir)
        assert granted.exit_code == 0, granted.output

        assert in_section, "the full-history charter read must consult the archive"
        assert not any(in_section), "archived segments were decompressed while holding the exclusive append section"

    def test_the_write_still_honours_the_archived_history(self, workdir: Path) -> None:
        """Two-phase must stay exact: the archived tail is the real predecessor."""
        import json

        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        assert _run(["grant", "acme", "--principal", "bob", "--by", "alice"], workdir).exit_code == 0
        _archive_everything(workdir)

        granted = _run(["grant", "acme", "--principal", "carol", "--by", "alice", "--json"], workdir)
        assert granted.exit_code == 0, granted.output

        shown = _run(["show", "acme", "--json"], workdir)
        payload = json.loads(shown.output)
        assert {m["principal"] for m in payload["state"]["members"]} == {"alice", "bob", "carol"}
        assert payload["state"]["version"] == 3

        verified = _run(["verify", "acme", "--json"], workdir)
        assert verified.exit_code == 0, verified.output

    def test_merge_is_exact_when_a_writer_lands_between_the_phases(self, workdir: Path) -> None:
        from bernstein.core.security.audit_chain import AuditChainStore
        from bernstein.core.security.tenant_charter import (
            CHARTER_MEMBER_ADD,
            next_event,
            read_charter_entries,
            read_charter_events,
            record_charter_event,
            refreshed_charter_events,
        )

        assert _run(["create", "acme", "--principal", "alice"], workdir).exit_code == 0
        chain = AuditChainStore(workdir / ".sdd" / "audit", key=(workdir / "audit.key").read_bytes())

        prior = read_charter_entries(chain, "acme")

        # A second writer lands between the pre-section read and the section.
        interloper = next_event(
            read_charter_events(chain, "acme")[-1],
            tenant_id="acme",
            kind=CHARTER_MEMBER_ADD,
            principal="alice",
            body={"principal": "eve", "role": "member"},
        )
        record_charter_event(chain, interloper)

        with chain.chain_transaction():
            merged = refreshed_charter_events(chain, "acme", prior)
        assert [event.seq for event in merged] == [0, 1]
        assert merged[-1].event_hash() == interloper.event_hash()
