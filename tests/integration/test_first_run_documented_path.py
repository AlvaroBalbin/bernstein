"""The documented first-run path for ``bernstein init`` (issue #3825).

``docs/getting-started/first-run.md`` step 3 tells a new operator to run
``bernstein init`` in a fresh project and shows the output they should see.
This holds that promise to the code: the command is invoked exactly as the
docs write it, from an empty directory, and the strings the docs print are
asserted individually.

Asserting only on the exit code would pass on a command that prints nothing,
which is the failure mode this test exists to catch.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def _cli(workdir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "bernstein", *args],
        cwd=workdir,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def test_init_succeeds_in_an_empty_directory(tmp_path: Path) -> None:
    """``bernstein init`` is the first command the docs ask for, and it works.

    The directory is empty and is deliberately not a git repository: the docs
    only require git before a *run* spawns worktree-isolated agents, not
    before ``init``.
    """
    result = _cli(tmp_path, "init")

    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"


@pytest.mark.parametrize(
    "promised",
    [
        "Created bernstein.yaml",
        "Done. Next steps:",
        "Edit bernstein.yaml: set a goal",
    ],
)
def test_init_prints_what_the_docs_promise(tmp_path: Path, promised: str) -> None:
    """Each line ``first-run.md`` shows for step 3 is really printed."""
    result = _cli(tmp_path, "init")

    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert promised in result.stdout, (
        f"docs/getting-started/first-run.md promises {promised!r} but init printed:\n{result.stdout}"
    )


def test_init_creates_the_artifacts_the_docs_describe(tmp_path: Path) -> None:
    """The four things ``first-run.md`` says happened actually happened."""
    result = _cli(tmp_path, "init")
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"

    assert (tmp_path / ".sdd" / "config.yaml").is_file()
    assert (tmp_path / "bernstein.yaml").is_file()
    assert (tmp_path / "templates").is_dir()
    assert ".sdd/runtime/" in (tmp_path / ".gitignore").read_text(encoding="utf-8")
