"""Unit tests for the microVM sandbox backend (#2613).

The backend runs the full :class:`SandboxBackendConformance` suite over a
:class:`FakeMonitor` (which really executes commands and really freezes the
workspace, so these are honest exercises of the snapshot pipeline, not mock
echoes). Backend-specific tests then cover the content-addressed snapshot
contract: digest determinism, tamper rejection on resume, the strict
no-silent-downgrade preflight, and path-traversal hardening of the image
format.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from bernstein.core.persistence.cas_store import CASIntegrityError, CASStore
from bernstein.core.sandbox.backend import ExecResult, SandboxCapability
from bernstein.core.sandbox.backends._vmmonitor import (
    FakeMonitor,
    MicroVMUnavailableError,
    canonical_workspace_image,
    extract_workspace_image,
)
from bernstein.core.sandbox.backends.microvm import (
    MicroVMProvisioningError,
    MicroVMSandboxBackend,
)
from bernstein.core.sandbox.conformance import SandboxBackendConformance
from bernstein.core.sandbox.manifest import FileEntry, GitRepoEntry, WorkspaceManifest

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping
    from pathlib import Path


def _backend(tmp_path: Path) -> MicroVMSandboxBackend:
    return MicroVMSandboxBackend(
        monitor_factory=lambda root: FakeMonitor(root=root),
        cas=CASStore(tmp_path / "cas"),
    )


class TestMicroVMConformance(SandboxBackendConformance):
    """Run the full backend conformance suite over the FakeMonitor."""

    @pytest_asyncio.fixture
    async def backend(self, tmp_path: Path) -> AsyncIterator[MicroVMSandboxBackend]:
        yield _backend(tmp_path)

    @pytest.fixture
    def manifest(self) -> WorkspaceManifest:
        return WorkspaceManifest(root="/workspace", env={"LC_ALL": "C"}, timeout_seconds=60)


def test_backend_declares_hardware_boundary_capabilities(tmp_path: Path) -> None:
    # Inject a tmp_path-rooted CAS so the test never creates a repo-local
    # .sdd/cas directory as a side effect of constructing the backend.
    backend = MicroVMSandboxBackend(cas=CASStore(tmp_path / "cas"))
    assert backend.capabilities == frozenset(
        {
            SandboxCapability.FILE_RW,
            SandboxCapability.EXEC,
            SandboxCapability.NETWORK,
            SandboxCapability.SNAPSHOT,
        },
    )


@pytest.mark.asyncio
async def test_snapshot_digest_is_deterministic(tmp_path: Path) -> None:
    """Two identical workspaces snapshot to the same content address."""
    backend = _backend(tmp_path)
    manifest = WorkspaceManifest(root="/workspace", files=(FileEntry(path="a.txt", content=b"hi"),))
    s1 = await backend.create(manifest)
    await s1.write("state.txt", b"same")
    d1 = await s1.snapshot()
    s2 = await backend.create(manifest)
    await s2.write("state.txt", b"same")
    d2 = await s2.snapshot()
    assert d1 == d2
    await backend.destroy(s1)
    await backend.destroy(s2)


@pytest.mark.asyncio
async def test_resume_rejects_tampered_snapshot(tmp_path: Path) -> None:
    cas = CASStore(tmp_path / "cas")
    backend = MicroVMSandboxBackend(monitor_factory=lambda root: FakeMonitor(root=root), cas=cas)
    session = await backend.create(WorkspaceManifest(root="/workspace"))
    await session.write("state.txt", b"captured")
    digest = await session.snapshot()
    await backend.destroy(session)

    blob = cas.root / digest[:2] / digest
    corrupt = bytearray(blob.read_bytes())
    corrupt[5] ^= 0xFF
    blob.write_bytes(bytes(corrupt))

    with pytest.raises(CASIntegrityError):
        await backend.resume(digest)


@pytest.mark.asyncio
async def test_resume_unknown_digest_raises(tmp_path: Path) -> None:
    backend = _backend(tmp_path)
    with pytest.raises(KeyError):
        await backend.resume("0" * 64)


class _CloneFailsMonitor:
    """A VMMonitor stub whose ``git clone`` fails, to exercise create() cleanup.

    Structurally satisfies the (runtime-checkable) ``VMMonitor`` protocol; only
    the methods create() touches are meaningful. Records ``shutdown`` calls so a
    test can assert the guest is always torn down on a provisioning failure.
    """

    def __init__(self, root: str) -> None:
        self._root = root
        self.shutdown_calls = 0

    @property
    def workdir(self) -> str:
        return self._root

    async def boot(self, *, base_env: Mapping[str, str]) -> None:
        return None

    async def exec(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int | None = None,
        stdin: bytes | None = None,
    ) -> ExecResult:
        return ExecResult(exit_code=1, stdout=b"", stderr=b"fatal: repo not found", duration_seconds=0.0)

    async def write_file(self, path: str, data: bytes, *, mode: int = 0o644) -> None:
        return None

    async def read_file(self, path: str) -> bytes:
        return b""

    async def ls(self, path: str) -> list[str]:
        return []

    async def freeze_image(self) -> bytes:
        return b""

    async def restore_image(self, image: bytes) -> None:
        return None

    async def shutdown(self) -> None:
        self.shutdown_calls += 1


@pytest.mark.asyncio
async def test_create_tears_down_guest_when_clone_fails(tmp_path: Path) -> None:
    """A non-zero ``git clone`` fails loudly and never leaks the booted monitor."""
    monitors: list[_CloneFailsMonitor] = []

    def factory(root: str) -> _CloneFailsMonitor:
        monitor = _CloneFailsMonitor(root)
        monitors.append(monitor)
        return monitor

    backend = MicroVMSandboxBackend(monitor_factory=factory, cas=CASStore(tmp_path / "cas"))
    manifest = WorkspaceManifest(
        root="/workspace",
        repo=GitRepoEntry(src_path=str(tmp_path / "missing-repo"), branch="main"),
    )

    with pytest.raises(MicroVMProvisioningError):
        await backend.create(manifest)

    assert monitors, "monitor factory was never invoked"
    assert monitors[0].shutdown_calls == 1
    # A failed create must not register a session in the tracking table.
    assert backend._sessions == {}


@pytest.mark.asyncio
async def test_default_backend_refuses_without_kvm(tmp_path: Path) -> None:
    """The production backend never silently degrades: it raises on an unsupported host.

    On a KVM host this test's premise does not hold, so it is skipped.
    """
    backend = MicroVMSandboxBackend(cas=CASStore(tmp_path / "cas"))
    from bernstein.core.sandbox.backends._vmmonitor import FirecrackerMonitor

    if not FirecrackerMonitor().preflight():
        pytest.skip("host actually supports Firecracker; no-downgrade path not exercisable here")
    with pytest.raises(MicroVMUnavailableError):
        await backend.create(WorkspaceManifest(root="/workspace"))


def test_canonical_image_roundtrip_and_traversal_guard(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "f.txt").write_bytes(b"data")
    (src / "top.txt").write_bytes(b"top")
    image = canonical_workspace_image(src)
    # deterministic: same tree -> same bytes
    assert image == canonical_workspace_image(src)

    dest = tmp_path / "dest"
    extract_workspace_image(image, dest)
    assert (dest / "sub" / "f.txt").read_bytes() == b"data"
    assert (dest / "top.txt").read_bytes() == b"top"

    # A hostile image with a traversal member is rejected.
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo(name="../escape.txt")
        payload = b"x"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    with pytest.raises(MicroVMUnavailableError):
        extract_workspace_image(buf.getvalue(), tmp_path / "dest2")


def test_extract_rejects_symlink_then_child_traversal(tmp_path: Path) -> None:
    """A symlink escaping root, followed by a child written through it, is refused.

    This is the TOCTOU a name-only pre-check misses: ``link -> ../../outside``
    passes a name check, then ``link/pwned`` writes outside root once the link
    exists. The stdlib ``data`` filter validates links at extraction time.
    """
    import io
    import tarfile

    outside = tmp_path / "outside"
    outside.mkdir()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        link = tarfile.TarInfo(name="link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        tar.addfile(link)
        child = tarfile.TarInfo(name="link/pwned.txt")
        payload = b"escaped"
        child.size = len(payload)
        tar.addfile(child, io.BytesIO(payload))

    with pytest.raises(MicroVMUnavailableError):
        extract_workspace_image(buf.getvalue(), tmp_path / "dest3")
    assert not (outside / "pwned.txt").exists()


def test_extract_rejects_absolute_symlink(tmp_path: Path) -> None:
    """A symlink whose target is an absolute path outside root is refused."""
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        link = tarfile.TarInfo(name="evil")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)

    with pytest.raises(MicroVMUnavailableError):
        extract_workspace_image(buf.getvalue(), tmp_path / "dest4")
