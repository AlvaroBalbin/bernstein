"""Containment barrier for the MCP shutdown-signal path.

``bernstein_stop`` takes a ``workdir`` from the caller and turns it into a
``.sdd/runtime/signals/SHUTDOWN`` write. With no barrier that is an
arbitrary directory-creation and file-write primitive reachable over MCP: a
crafted workdir addresses any directory on the machine, ``mkdir(parents=True)``
builds the tree there, and the write stops an unrelated Bernstein project.

Two checks, neither sufficient on its own:

1. **Existing project root.** The resolved workdir must already contain a
   ``.sdd`` directory. The tool can only stop a Bernstein project that is
   already on disk; it never materialises a tree at a path it was handed.
2. **Realpath containment.** The signal path is rebuilt through
   :func:`~bernstein.core.security.path_containment.contained_path` - the
   same barrier ``run_journal_path`` puts in front of the run journal -
   so a ``.sdd``, ``runtime``, ``signals``, or ``SHUTDOWN`` entry that is a
   symlink out of the project cannot redirect the write.

Resolving the workdir is not the barrier by itself. ``Path.resolve`` and
``os.path.realpath`` follow symlinks but do not fold case, so on a
case-insensitive filesystem a resolved path is normalised, not canonical: a
case variant of a project root resolves to a different string for the same
directory. Containment, not the resolve, is what decides whether the write
lands inside the named root, and it is evaluated against the root as
resolved from that same call, so a case variant is measured against itself.

Naming a root is allowed; escaping it is not. An absolute path to another
Bernstein project on the same machine is a legitimate stop target - the
barrier is against a workdir that reaches outside the root it names.
"""

from __future__ import annotations

from pathlib import Path

from bernstein.core.security.path_containment import PathContainmentError, contained_path

#: Marker directory that makes a workdir a Bernstein project root.
SDD_DIR_NAME = ".sdd"

#: Fixed segments from the project root down to the signal file. Constants,
#: not caller data - the caller only names the root - but they are still
#: routed through the barrier because any of them can be a symlink on disk.
SHUTDOWN_SEGMENTS = (SDD_DIR_NAME, "runtime", "signals", "SHUTDOWN")


class ShutdownSignalPathError(PathContainmentError):
    """Raised when a workdir cannot safely name a shutdown-signal path.

    Subclasses :class:`~bernstein.core.security.path_containment.PathContainmentError`
    (and so :class:`ValueError`), matching how ``JournalPathError`` reports a
    refused run id, so both MCP surfaces render it with the same structured
    error shape.
    """


def shutdown_signal_path(workdir: str | Path) -> Path:
    """Return the contained ``SHUTDOWN`` path for an existing project root.

    Args:
        workdir: Project root named by the caller. Untrusted.

    Returns:
        The normalised, containment-checked path of the ``SHUTDOWN`` signal
        file. Callers must write through this return value: it is the only
        path proven to live inside the resolved root.

    Raises:
        ShutdownSignalPathError: The resolved workdir holds no ``.sdd``
            directory, or the signal path resolves outside that root.
    """
    root = Path(workdir).resolve()
    if not (root / SDD_DIR_NAME).is_dir():
        msg = f"workdir is not an existing Bernstein project root (no {SDD_DIR_NAME} directory): {workdir!r}"
        raise ShutdownSignalPathError(msg)
    try:
        return contained_path(root, *SHUTDOWN_SEGMENTS, label="workdir")
    except PathContainmentError as exc:
        msg = f"shutdown signal path resolves outside the project root named by workdir: {workdir!r}"
        raise ShutdownSignalPathError(msg) from exc


__all__ = [
    "SDD_DIR_NAME",
    "SHUTDOWN_SEGMENTS",
    "ShutdownSignalPathError",
    "shutdown_signal_path",
]
