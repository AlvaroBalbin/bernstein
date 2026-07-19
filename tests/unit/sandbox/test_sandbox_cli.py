"""CLI-surface tests for ``bernstein sandbox fork-race`` base validation (#2613).

These pin the guard added in response to review: a malformed *or* absent
``--base`` must fail as a clean ``ClickException`` (exit 1, no traceback) and,
critically, *before* any side-effectful state - no Ed25519 signing key is
minted for a doomed run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from click.testing import CliRunner

from bernstein.cli.commands.sandbox_cmd import sandbox_group

if TYPE_CHECKING:
    from pathlib import Path


def _invoke(base: str, tmp_path: Path) -> tuple[int, str, bool]:
    key_path = tmp_path / "keys" / "selection.key"
    result = CliRunner().invoke(
        sandbox_group,
        [
            "fork-race",
            "--base",
            base,
            "--cmd",
            "true",
            "--out",
            str(tmp_path / "receipt.json"),
            "--cas-dir",
            str(tmp_path / "cas"),
            "--key",
            str(key_path),
            "--audit-dir",
            str(tmp_path / "audit"),
        ],
    )
    return result.exit_code, (result.output or ""), key_path.exists()


def test_fork_race_malformed_base_fails_cleanly_without_minting_key(tmp_path: Path) -> None:
    exit_code, output, key_minted = _invoke("not-a-hex-digest", tmp_path)
    assert exit_code == 1
    assert "invalid base snapshot digest" in output
    assert not key_minted


def test_fork_race_absent_base_fails_cleanly_without_minting_key(tmp_path: Path) -> None:
    # Well-formed 64-char hex digest that is simply not present in the CAS.
    exit_code, output, key_minted = _invoke("0" * 64, tmp_path)
    assert exit_code == 1
    assert "not found in CAS" in output
    assert not key_minted
