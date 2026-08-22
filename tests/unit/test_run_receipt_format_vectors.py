"""``tools/verify_run_receipt.py`` against the committed run-receipt vectors (#4204).

The run-receipt format spec (``docs/security/run-receipt-format.md``) promises
a reader can implement a conforming verifier without opening ``src/`` and
check it against two committed test vectors: a valid receipt and a tampered
copy. This test runs the actual reference verifier as a subprocess against
both, so the worked example in the spec cannot drift from what the script
does, and asserts the script never imports the bernstein package - the
concrete claim the spec and the script's own docstring both make.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOL = _REPO_ROOT / "tools" / "verify_run_receipt.py"
_DEMO_RUN = _REPO_ROOT / "docs" / "assets" / "demo-run"
_VALID_RECEIPT = _DEMO_RUN / "run-receipt.json"
_TAMPERED_RECEIPT = _DEMO_RUN / "run-receipt.tampered.json"
_PUBKEY = _DEMO_RUN / "run-receipt.pub.pem"


def _run_verifier(receipt: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_TOOL), "--receipt", str(receipt), "--public-key", str(_PUBKEY)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_verifier_script_never_imports_bernstein() -> None:
    """The whole point of the spec is that a verifier needs no ``src/``."""
    source = _TOOL.read_text(encoding="utf-8")
    assert "import bernstein" not in source
    assert "from bernstein" not in source


def test_the_valid_vector_verifies_with_the_pinned_key() -> None:
    proc = _run_verifier(_VALID_RECEIPT)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OVERALL: OK (provenance)" in proc.stdout


def test_the_tampered_vector_fails_closed_at_the_forged_step() -> None:
    proc = _run_verifier(_TAMPERED_RECEIPT)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "OVERALL: TAMPER DETECTED" in proc.stdout
    assert "journal step 0: event_hash mismatch" in proc.stdout
