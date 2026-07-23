"""Explicit-override-aware attachment of the Docker sandbox backend.

The deterministic selector (:mod:`bernstein.core.sandbox.selector`) already
treats an explicit ``--sandbox <name>`` override as a hard contract and
raises :class:`~bernstein.core.sandbox.selector.SandboxSelectionError`
rather than silently picking a different runtime. The runtime *attach*
step, however, has to probe a live Docker daemon, and that probe used to
degrade quietly: a missing Docker SDK or dead daemon logged a warning and
fell through to legacy-container and then plain host-worktree execution,
dropping the isolation boundary the operator explicitly asked for with no
console signal (issue #2809).

This module carries the same override-first contract into the attach step.
When Docker is requested by an explicit override, an unavailable backend is
a loud failure; when Docker was merely auto-selected, an unavailable
backend degrades gracefully. Threading the ``explicit`` bit through is what
distinguishes the two, so the loud-fail path is gated on operator intent,
not on Docker availability alone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from bernstein.core.sandbox.selector import SandboxSelectionError

if TYPE_CHECKING:
    from bernstein.core.sandbox.backends.docker import DockerSandboxBackend


def attach_docker_backend(
    *,
    explicit: bool,
    backend: DockerSandboxBackend | None = None,
) -> DockerSandboxBackend | None:
    """Instantiate and verify the Docker sandbox backend.

    The backend's availability probe (SDK import + daemon ping) runs at
    wiring time so a broken setup surfaces before any agent spawns rather
    than per spawn.

    Args:
        explicit: Whether Docker was chosen by an explicit operator
            override (``--sandbox docker``) as opposed to automatic
            selection. Only the explicit path fails loudly; auto-selection
            keeps the historical graceful fallback.
        backend: Pre-built backend to verify. Defaults to a fresh
            :class:`~bernstein.core.sandbox.backends.docker.DockerSandboxBackend`.
            Tests inject a stub to exercise the availability branches
            without a live daemon.

    Returns:
        The ready backend when Docker is usable. ``None`` when Docker is
        unavailable *and* the choice was auto-selected (``explicit`` is
        ``False``), signalling the caller to fall back gracefully.

    Raises:
        SandboxSelectionError: When ``explicit`` is ``True`` and Docker is
            unavailable. The operator requested container isolation with an
            explicit ``--sandbox docker`` override; silently degrading to
            host execution would drop that isolation boundary without a
            signal, so the failure is raised instead of swallowed.
    """
    from bernstein.core.sandbox.backends.docker import (
        DockerSandboxBackend,
        DockerUnavailableError,
    )

    candidate = backend if backend is not None else DockerSandboxBackend()
    try:
        candidate.ensure_available()
    except DockerUnavailableError as exc:
        if explicit:
            raise SandboxSelectionError(
                "Explicit '--sandbox docker' could not be honored: "
                f"{exc} Refusing to fall back to host execution because "
                "container isolation was explicitly requested. Re-run "
                "without --sandbox to allow automatic fallback, or install "
                "the Docker SDK and start the Docker daemon.",
                attempted=("docker",),
            ) from exc
        return None
    return candidate


__all__ = ["attach_docker_backend"]
