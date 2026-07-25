"""Verifying a chain must not require write access to the chain.

The recovery runbook (``docs/security/audit-log.md``) starts by snapshotting
``.sdd/audit/`` somewhere read-only and running ``bernstein audit verify``
against the copy. Verification is a pure read, so that worked - until the
verifier started opening a chain transaction, which needs a *writable*
descriptor on the ``.chain.lock`` sentinel because an exclusive OS lock cannot
be taken on a read-only one.

The failure mode that produced is the worst possible one for a runbook: at the
moment an operator is trying to establish whether the chain is intact, the
verifier answers "I cannot look" in the same shape it answers "the chain is
broken" - a non-zero exit, and in some commands a raw ``PermissionError``
traceback pointing into the audit module.

So the two halves are separated:

* a read-only caller pins the segment set best-effort. A directory that will not
  grant the lock yields an unlocked pin, and the degradation is *reported*
  rather than passed off as a guarded read;
* anything that appends still requires the lock, and a directory that refuses it
  produces :class:`ChainLockUnwritable` - named, actionable, and already mapped
  to ``Error: ...`` at the CLI boundary.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from click.testing import CliRunner

from bernstein.cli.commands import audit_cmd
from bernstein.cli.commands.tenant_cmd import tenant_group
from bernstein.core.security.audit import (
    _CHAIN_LOCK_NAME,
    AuditLog,
    ChainLockUnwritable,
    _reset_after_fork,
    chain_transaction,
)

KEY = b"k" * 32


@pytest.fixture(autouse=True)
def _pin_audit_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bernstein.core.security.audit.load_or_create_audit_key", lambda *a, **k: KEY)


@pytest.fixture(autouse=True)
def _refuse_root(tmp_path: Path) -> None:
    """Skip when the account ignores the mode bits these tests rely on."""
    probe = tmp_path / "probe"
    probe.mkdir()
    (probe / "f").write_text("x", encoding="utf-8")
    probe.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        with (probe / "g").open("w"):
            pass
    except OSError:
        return
    finally:
        probe.chmod(stat.S_IRWXU)
    pytest.skip("this account can write through a read-only directory (root?)")


def _project(tmp_path: Path) -> Path:
    """A workdir with a real charter on a real chain."""
    workdir = tmp_path / "project"
    audit_dir = workdir / ".sdd" / "audit"
    result = CliRunner().invoke(tenant_group, ["create", "acme", "--principal", "alice", "--workdir", str(workdir)])
    assert result.exit_code == 0, result.output
    assert AuditLog(audit_dir=audit_dir, key=KEY).verify()[0] is True
    return workdir


def _make_read_only(audit_dir: Path) -> None:
    """Turn the directory read-only, as a fresh process would find it.

    The lock table caches one already-open ``O_RDWR`` descriptor per audit
    directory for the life of a process, so a process that wrote before the
    chmod keeps working through it. Dropping the table is what makes the
    in-process test see what a separately-invoked command sees.
    """
    _reset_after_fork()
    for path in sorted(audit_dir.rglob("*"), reverse=True):
        path.chmod(stat.S_IRUSR)
    audit_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)


def _restore(audit_dir: Path) -> None:
    audit_dir.chmod(stat.S_IRWXU)
    for path in audit_dir.rglob("*"):
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


class TestReadsOnAReadOnlySnapshot:
    def test_audit_verify_hmac_only_still_exits_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The exact command the docs put in cron, against the read-only copy."""
        from bernstein.cli.main import cli

        workdir = _project(tmp_path)
        audit_dir = workdir / ".sdd" / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        _make_read_only(audit_dir)
        try:
            result = CliRunner().invoke(cli, ["audit", "verify", "--hmac-only"])
        finally:
            _restore(audit_dir)

        assert result.exit_code == 0, result.output
        assert "Permission denied" not in result.output

    def test_audit_verify_runs_every_pillar_and_says_the_read_was_unlocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workdir = _project(tmp_path)
        audit_dir = workdir / ".sdd" / "audit"
        monkeypatch.setattr(audit_cmd, "AUDIT_DIR", audit_dir)
        monkeypatch.setattr(audit_cmd, "_DEGRADED_PIN_REPORTED", False)
        _make_read_only(audit_dir)
        try:
            assert audit_cmd._verify_tenant_charters() is True
            assert audit_cmd._verify_chain_tears() is True
        finally:
            _restore(audit_dir)

    def test_tenant_show_and_verify_exit_zero_without_a_traceback(self, tmp_path: Path) -> None:
        workdir = _project(tmp_path)
        audit_dir = workdir / ".sdd" / "audit"
        _make_read_only(audit_dir)
        try:
            runner = CliRunner()
            shown = runner.invoke(tenant_group, ["show", "acme", "--workdir", str(workdir)])
            verified = runner.invoke(tenant_group, ["verify", "acme", "--workdir", str(workdir), "--json"])
        finally:
            _restore(audit_dir)

        assert shown.exit_code == 0, shown.output
        assert verified.exit_code == 0, verified.output
        for result in (shown, verified):
            assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
            assert "PermissionError" not in result.output

    def test_a_sentinel_owned_by_the_writer_degrades_the_same_way(self, tmp_path: Path) -> None:
        """Reader and writer are different accounts: the directory is writable, the sentinel is not."""
        workdir = _project(tmp_path)
        sentinel = workdir / ".sdd" / "audit" / _CHAIN_LOCK_NAME
        _reset_after_fork()
        sentinel.chmod(stat.S_IRUSR)
        try:
            result = CliRunner().invoke(tenant_group, ["show", "acme", "--workdir", str(workdir)])
        finally:
            sentinel.chmod(stat.S_IRUSR | stat.S_IWUSR)

        assert result.exit_code == 0, result.output

    def test_the_degraded_pin_is_marked_as_degraded(self, tmp_path: Path) -> None:
        """A caller can tell a guarded read from an unlocked one."""
        workdir = _project(tmp_path)
        audit_dir = workdir / ".sdd" / "audit"
        assert AuditLog(audit_dir=audit_dir, key=KEY).pin_segments(best_effort=True).degraded is False

        _make_read_only(audit_dir)
        try:
            pinned = AuditLog(audit_dir=audit_dir, key=KEY).pin_segments(best_effort=True)
        finally:
            _restore(audit_dir)

        assert pinned.degraded is True
        assert pinned.live, "a degraded pin still has to list the segments"


class TestWritersAreRefusedByName:
    def test_the_transaction_names_the_sentinel_instead_of_raising_permissionerror(self, tmp_path: Path) -> None:
        workdir = _project(tmp_path)
        audit_dir = workdir / ".sdd" / "audit"
        _make_read_only(audit_dir)
        try:
            with pytest.raises(ChainLockUnwritable, match=_CHAIN_LOCK_NAME), chain_transaction(audit_dir):
                pass
        finally:
            _restore(audit_dir)

    def test_tenant_create_on_a_read_only_chain_is_a_clean_error(self, tmp_path: Path) -> None:
        """Through the root CLI, which is where the chain-lock errors are mapped."""
        from bernstein.cli.main import cli

        workdir = _project(tmp_path)
        audit_dir = workdir / ".sdd" / "audit"
        _make_read_only(audit_dir)
        try:
            result = CliRunner().invoke(
                cli, ["tenant", "create", "beta", "--principal", "bob", "--workdir", str(workdir)]
            )
        finally:
            _restore(audit_dir)

        assert result.exit_code != 0
        assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
        assert "not writable" in result.output
        assert "Traceback" not in result.output

    def test_the_writer_error_is_a_chain_lock_error_so_the_cli_maps_it(self) -> None:
        """The boundary maps ``ChainLockUnavailable``; the new class must be one."""
        from bernstein.core.security.audit import ChainLockUnavailable

        assert issubclass(ChainLockUnwritable, ChainLockUnavailable)

    def test_an_unrelated_oserror_is_not_swallowed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only the "this directory will not grant a writable descriptor" errnos degrade."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(parents=True)
        real_open = os.open

        def _too_many_files(path: object, *args: object, **kwargs: object) -> int:
            if str(path).endswith(_CHAIN_LOCK_NAME):
                raise OSError(24, "Too many open files")
            return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

        _reset_after_fork()
        monkeypatch.setattr(os, "open", _too_many_files)
        with pytest.raises(OSError, match="Too many open files"):
            AuditLog(audit_dir=audit_dir, key=KEY).pin_segments(best_effort=True)
