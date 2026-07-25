"""Chain-lock contention must reach the operator as an error, not a traceback.

:class:`ChainLockUnavailable` and :class:`ChainLockMisuse` are ``RuntimeError``
subclasses, and nothing caught them. An operator whose ``bernstein tenant
create`` collided with a scheduled ``bernstein audit verify`` therefore got a
Python stack trace ending in the audit module.

That is the wrong signal twice over. Contention is an operational condition -
another process is inside a read-modify-append section and this one waited out
its budget - not a defect. And on the audit substrate specifically, a traceback
out of the chain code reads as corruption, which is the opposite of what
happened. Every other failure in these commands surfaces as ``Error: ...``
through :class:`click.ClickException`.

The message itself is passed through unchanged: it already names how to find the
holder and warns against removing the lock file, which is the one "fix" that
actually admits a second writer alongside the current one.
"""

from __future__ import annotations

import threading
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from bernstein.cli.main import cli
from bernstein.core.security.audit import (
    ChainLockMisuse,
    ChainLockUnavailable,
    chain_transaction,
)


class _HeldLock:
    """Hold the chain transaction on *audit_dir* from another thread.

    A second thread is refused by the same ownership check a second process is,
    and takes the in-process mutex for exactly as long as it holds the OS lock,
    so the command under test hits the real contention path rather than a
    stubbed exception.
    """

    def __init__(self, audit_dir: Path) -> None:
        self._audit_dir = audit_dir
        self._acquired = threading.Event()
        self._release = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        with chain_transaction(self._audit_dir, timeout=30):
            self._acquired.set()
            self._release.wait(60)

    def __enter__(self) -> _HeldLock:
        self._thread.start()
        assert self._acquired.wait(30), "the holding thread never acquired the lock"
        return self

    def __exit__(self, *exc: object) -> None:
        self._release.set()
        self._thread.join(timeout=30)


@pytest.fixture
def _fast_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shorten the acquire budget so the test spends milliseconds, not 30s.

    The budget is what the operator waits out; its length is not what is under
    test here, so paying it in full would only make the suite slower.
    """
    monkeypatch.setattr("bernstein.core.security.audit.CHAIN_LOCK_TIMEOUT_S", 0.25)


class TestContentionOnARealCommand:
    def test_contention_prints_an_operator_error_rather_than_a_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _fast_budget: None
    ) -> None:
        """End to end through the real command group, against a really held lock."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(parents=True)
        monkeypatch.setattr("bernstein.cli.commands.audit_cmd.AUDIT_DIR", audit_dir)

        with _HeldLock(audit_dir):
            result = CliRunner().invoke(
                cli,
                ["audit", "ack-tear", "--segment", "2026-07-25.jsonl", "--offset", "0", "--reason", "x"],
            )

        assert result.exit_code == 1, result.output
        assert not isinstance(result.exception, ChainLockUnavailable), (
            "the lock fault reached the terminal as a RuntimeError; the operator sees a traceback"
        )
        assert "Traceback" not in result.output, result.output
        assert result.output.strip().startswith("Error:"), result.output

    def test_the_message_still_names_lsof_and_warns_against_deleting_the_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _fast_budget: None
    ) -> None:
        """The wrapping must not replace the text with a generic one.

        The existing message is the actionable part: it says how to identify the
        holder, and it says not to remove the lock file, because a fresh inode
        admits a second writer alongside the one still running.
        """
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(parents=True)
        monkeypatch.setattr("bernstein.cli.commands.audit_cmd.AUDIT_DIR", audit_dir)

        with _HeldLock(audit_dir):
            result = CliRunner().invoke(
                cli,
                ["audit", "ack-tear", "--segment", "2026-07-25.jsonl", "--offset", "0", "--reason", "x"],
            )

        flat = " ".join(result.output.split())
        assert "lsof" in flat, result.output
        assert "rather than removing the lock file" in flat, result.output
        assert "could not acquire the audit chain transaction" in flat, result.output


class TestBoundaryMapping:
    """The group-level handler, exercised through subcommands added for the test.

    Registered on the real ``cli`` object rather than on a lookalike, so the test
    also fails if the group stops using the class that carries the handler.
    """

    @staticmethod
    def _register(name: str, exc: BaseException) -> None:
        @cli.command(name=name, hidden=True)
        def _raiser() -> None:
            raise exc

    def test_chain_lock_misuse_is_mapped_too(self) -> None:
        """Misuse is a programming error, but it still reaches an operator."""
        self._register("chainlock-misuse-probe", ChainLockMisuse("held by another asyncio task"))
        try:
            result = CliRunner().invoke(cli, ["chainlock-misuse-probe"])
        finally:
            cli.commands.pop("chainlock-misuse-probe", None)

        assert result.exit_code == 1
        assert "Traceback" not in result.output
        assert result.output.strip().startswith("Error:"), result.output
        assert "held by another asyncio task" in result.output

    def test_an_ordinary_runtime_error_is_left_alone(self) -> None:
        """The handler must catch the two chain-lock types, not RuntimeError.

        Swallowing every ``RuntimeError`` into a tidy ``Error: ...`` would hide
        real defects behind an operator-shaped message, which is the same
        mistake in the other direction.
        """
        self._register("plain-runtimeerror-probe", RuntimeError("something is genuinely broken"))
        try:
            result = CliRunner().invoke(cli, ["plain-runtimeerror-probe"])
        finally:
            cli.commands.pop("plain-runtimeerror-probe", None)

        assert isinstance(result.exception, RuntimeError), result.output
        assert not isinstance(result.exception, click.ClickException)
