"""The documented first-run path for the graduation subsystem (#3828).

``docs/operations/graduation.md`` states there is no ``bernstein graduation``
CLI command: the subsystem's documented surface is REST. So its first run is
an operator standing up a server and driving the endpoint table on that page,
and that is what this exercises - against a real server process, not a
threaded stand-in.

The lifecycle asserted here is the one the page describes: read the policies,
record task events against a session, watch it become eligible at the
documented sandbox threshold, then promote it a stage.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

_TOKEN = "GRADUATION-TEST-TOKEN"
_BOOT_TIMEOUT_S = 120.0


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _call(base: str, path: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> tuple[int, Any]:
    """Call the task server the way the docs' endpoint table describes."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{base}{path}",
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {_TOKEN}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    """A real ``bernstein serve`` process, torn down at the end of the module."""
    import tempfile

    with tempfile.TemporaryDirectory() as raw:
        workdir = Path(raw)
        subprocess.run(["git", "init", "-q", "."], cwd=workdir, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.email=t@example.com",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "init",
            ],
            cwd=workdir,
            check=True,
        )

        port = _free_port()
        env = os.environ.copy()
        env.update({"PYTHONUTF8": "1", "BERNSTEIN_AUTH_TOKEN": _TOKEN})
        log = (workdir / "serve.log").open("wb")
        process = subprocess.Popen(
            [sys.executable, "-m", "bernstein", "serve", "--port", str(port)],
            cwd=workdir,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        base = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + _BOOT_TIMEOUT_S
            while time.monotonic() < deadline:
                try:
                    status, _ = _call(base, "/health")
                    if status == 200:
                        break
                except (urllib.error.URLError, OSError):
                    pass
                time.sleep(0.25)
            else:
                raise AssertionError(f"server never became ready:\n{(workdir / 'serve.log').read_text()}")
            yield base
        finally:
            process.kill()
            process.wait(timeout=30)
            log.close()


def test_policies_match_the_documented_defaults(server: str) -> None:
    """The published thresholds table is served, not just written down."""
    status, policies = _call(server, "/graduation/config/policies")

    assert status == 200
    # docs/operations/graduation.md, "Default policies"
    assert policies["sandbox"]["min_tasks_completed"] == 3
    assert policies["sandbox"]["min_success_rate"] == pytest.approx(0.8)
    assert policies["shadow"]["min_tasks_completed"] == 5
    assert policies["assisted"]["min_success_rate"] == pytest.approx(0.9)


def test_status_is_served_on_a_fresh_workspace(server: str) -> None:
    status, payload = _call(server, "/graduation/status")

    assert status == 200
    assert "sessions" in payload


def test_unknown_session_is_a_404_not_a_crash(server: str) -> None:
    """The control for the lifecycle below: absence is reported, not invented."""
    status, _ = _call(server, "/graduation/no-such-session-in-this-test")

    assert status == 404


def test_a_session_graduates_once_it_clears_the_sandbox_threshold(server: str) -> None:
    """Record → become eligible → promote, the lifecycle the page describes."""
    session = "first-run-graduation-session"

    for index in range(3):  # the documented sandbox minimum
        status, _ = _call(
            server,
            f"/graduation/{session}/record-event",
            method="POST",
            body={"task_id": f"task-{index}", "success": True},
        )
        assert status == 200

    status, record = _call(server, f"/graduation/{session}")
    assert status == 200
    assert record["current_stage"] == "sandbox"
    assert record["stage_metrics"]["sandbox"]["tasks_completed"] == 3
    assert record["can_graduate"] is True, record

    status, promotion = _call(server, f"/graduation/{session}/promote", method="POST", body={})
    assert status == 200
    assert promotion["from_stage"] == "sandbox"
    assert promotion["to_stage"] == "shadow"
    assert promotion["promoted"] is True
