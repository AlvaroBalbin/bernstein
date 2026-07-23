"""Unit tests for explicit-override-aware Docker backend attachment.

Regression coverage for issue #2809: an explicit ``--sandbox docker``
override that cannot be satisfied (missing Docker SDK, dead daemon) must
fail loudly with :class:`SandboxSelectionError` instead of silently
degrading to host / worktree execution. Auto-selected Docker (no explicit
override) must still fall back quietly.
"""

from __future__ import annotations

from typing import Any

import pytest

from bernstein.core.sandbox.backends.docker import DockerUnavailableError
from bernstein.core.sandbox.explicit_attach import attach_docker_backend
from bernstein.core.sandbox.selector import SandboxSelectionError


class _UnavailableBackend:
    """Docker backend stub whose availability probe always fails."""

    name = "docker"

    def ensure_available(self) -> None:
        raise DockerUnavailableError(
            "Install the 'docker' extra to use DockerSandboxBackend: `pip install bernstein[docker]`."
        )


class _AvailableBackend:
    """Docker backend stub whose availability probe succeeds."""

    name = "docker"

    def ensure_available(self) -> None:
        return None


def test_explicit_docker_unavailable_raises_selection_error() -> None:
    """Explicit override + unavailable Docker must raise, not fall back."""
    with pytest.raises(SandboxSelectionError) as excinfo:
        attach_docker_backend(explicit=True, backend=_UnavailableBackend())  # type: ignore[arg-type]

    err = excinfo.value
    assert err.attempted == ("docker",)
    # The message must name the actual cause so the operator can fix it.
    assert "docker" in err.reason.lower()
    assert "host" in err.reason.lower()


def test_explicit_docker_unavailable_does_not_return_host_backend() -> None:
    """The explicit failure path must never yield a usable backend."""
    with pytest.raises(SandboxSelectionError):
        _result: Any = attach_docker_backend(
            explicit=True,
            backend=_UnavailableBackend(),  # type: ignore[arg-type]
        )


def test_auto_selected_docker_unavailable_falls_back_quietly() -> None:
    """Auto-selection (explicit False) degrades gracefully to ``None``."""
    result = attach_docker_backend(explicit=False, backend=_UnavailableBackend())  # type: ignore[arg-type]
    assert result is None


def test_explicit_docker_available_returns_backend() -> None:
    """When Docker is usable the same backend instance is returned."""
    backend = _AvailableBackend()
    result = attach_docker_backend(explicit=True, backend=backend)  # type: ignore[arg-type]
    assert result is backend


def test_auto_selected_docker_available_returns_backend() -> None:
    """Auto-selection also returns the backend when Docker is usable."""
    backend = _AvailableBackend()
    result = attach_docker_backend(explicit=False, backend=backend)  # type: ignore[arg-type]
    assert result is backend
