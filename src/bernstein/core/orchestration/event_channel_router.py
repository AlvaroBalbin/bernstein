"""Route a spawned adapter's lifecycle by its declared ``EventChannel``.

Follow-up to the ACP event transport (#2522). That work added a first-class,
content-addressed ACP client transport
(:mod:`bernstein.core.protocols.acp.client`), the adapter-side binding
(:func:`bernstein.adapters.acp_channel.run_acp_channel`), and migrated the
``goose`` and ``kilo`` adapters to
:attr:`bernstein.adapters._contract.EventChannel.ACP`. What it did not add was a
consumer: the orchestrator's monitoring loop never read the declared channel, so
in a real run an ACP-declared adapter still fell through the text-signal
lifecycle path and none of its structured events reached the run journal.

This module is that missing dispatch seam. It reads an adapter's declared
``EventChannel`` and, for an ACP-channel adapter, drives the upstream agent's
JSON-RPC frame stream through ``run_acp_channel`` - every frame schema-validated
and chained into the run's Merkle journal content-addressed, so the run's replay
identity covers the agent's output and a mutated event surfaces as a hash
divergence at a precise step index rather than a silent drift. Text-signal
adapters return ``None`` and keep their existing path unchanged; the dispatch is
strictly additive.

The seam lives in ``core.orchestration`` rather than ``adapters`` on purpose:
the ``adapters-no-scheduler`` import-linter contract forbids an adapter from
importing the scheduler, but the scheduler may import
:mod:`bernstein.adapters.acp_channel`, so this is the correct side of the
boundary for wiring the declared channel into the monitoring loop.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from bernstein.adapters.acp_channel import (
    AcpLifecycleResult,
    adapter_speaks_acp,
    run_acp_channel,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path

    from bernstein.core.replay.journal import EventJournal

__all__ = [
    "AcpLifecycleResult",
    "agent_uses_acp_channel",
    "iter_journal_frames",
    "route_agent_lifecycle",
]


def agent_uses_acp_channel(adapter_name: str) -> bool:
    """Return whether *adapter_name* declares :attr:`EventChannel.ACP`.

    Resolution goes through
    :func:`bernstein.adapters.acp_channel.adapter_speaks_acp`, so the name may be
    either a registry key (``"kilo"``) or the session-namespace form, and an
    undeclared or empty name answers ``False`` (its conservative default channel
    is text signals).
    """
    return bool(adapter_name) and adapter_speaks_acp(adapter_name)


def iter_journal_frames(log_path: Path) -> Iterator[bytes]:
    """Yield the JSON-RPC frame lines a finished ACP agent wrote to its log.

    The detached-worker model captures an agent's stdout to a per-session log
    file, so once the process has exited its ACP frame stream can be replayed
    from that file byte for byte. Blank lines are skipped and a missing file
    yields nothing, mirroring
    :func:`bernstein.adapters.acp_channel.iter_process_frames` for the live-pipe
    case.

    Args:
        log_path: The file capturing the upstream agent's stdout.

    Yields:
        Each non-empty line, including its trailing newline.
    """
    if not log_path.exists():
        return
    with log_path.open("rb") as fh:
        for line in fh:
            if line.strip():
                yield line


def route_agent_lifecycle(
    adapter_name: str,
    inbound: Iterable[bytes | str],
    *,
    journal: EventJournal,
    session_id: str,
    stop_at_terminal: bool = True,
) -> AcpLifecycleResult | None:
    """Dispatch a spawned adapter's lifecycle by its declared ``EventChannel``.

    An ACP-channel adapter is driven through
    :func:`bernstein.adapters.acp_channel.run_acp_channel`: the structured
    JSON-RPC lifecycle with content-addressed journaling into *journal*. The
    returned :class:`AcpLifecycleResult` carries the terminal outcome and the
    Merkle journal head. Every other adapter returns ``None`` - the caller keeps
    the existing text-signal lifecycle path, and *journal* is left untouched.

    Args:
        adapter_name: Registry key or namespace form of the session's adapter.
        inbound: The upstream agent's JSON-RPC frames (for a finished agent,
            :func:`iter_journal_frames` over its captured log).
        journal: The run's event journal; every inbound ACP event is recorded
            content-addressed.
        session_id: The adapter session id, retained for correlation.
        stop_at_terminal: Stop after the first terminal ACP event.

    Returns:
        An :class:`AcpLifecycleResult` for an ACP-channel adapter, otherwise
        ``None``.

    Raises:
        ACPSchemaError: An inbound frame failed schema validation. The malformed
            frame is refused at the boundary and journals nothing; events already
            recorded before it remain.
    """
    if not agent_uses_acp_channel(adapter_name):
        return None
    return run_acp_channel(
        inbound,
        journal=journal,
        session_id=session_id,
        stop_at_terminal=stop_at_terminal,
    )
