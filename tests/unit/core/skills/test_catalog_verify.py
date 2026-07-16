"""``bernstein skills catalog verify`` offline verification (issue #2527).

Acceptance:
- an install produces a receipt that verify proves offline;
- mutating one byte of the recorded catalog state makes verify fail;
- an installed entry under a signed revocation fails verify.
"""

from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from bernstein.core.plugins_core.plugin_installer import PluginInstallResult
from bernstein.core.skills.catalog import (
    SkillCatalog,
    SkillCatalogAuditor,
    SkillCatalogEntry,
    SkillCatalogService,
    SkillCatalogServiceConfig,
    SkillSourceRef,
    SkillSourceSpec,
    TransparencyLog,
    generate_signer_keypair,
    sign_entry,
)
from bernstein.core.skills.catalog.revocation import RevocationEntry, sign_revocation
from bernstein.core.skills.catalog.signature import attach_signature
from bernstein.core.skills.catalog.transparency import build_catalog_envelope

FIXTURE_DESCRIPTION = "Fixture catalog entry installed from github."


@pytest.fixture(autouse=True)
def isolate_audit_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BERNSTEIN_AUDIT_KEY_PATH", str(tmp_path / "audit.key"))


def _write_skill_dir(root: Path) -> None:
    skill_dir = root / "code-review"
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        textwrap.dedent(
            f"""
            ---
            name: code-review
            description: {FIXTURE_DESCRIPTION}
            ---

            Body.
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


@pytest.fixture
def installer() -> Callable[..., PluginInstallResult]:
    def _installer(source, install_dir):  # type: ignore[no-untyped-def]
        _write_skill_dir(install_dir)
        return PluginInstallResult(success=True, install_path=install_dir / "code-review", source_kind=source.kind)

    return _installer


def _fixture_digest(tmp_path: Path) -> str:
    from bernstein.core.skills.lifecycle import compute_skill_digest

    staging = tmp_path / "_digest_staging"
    staging.mkdir(exist_ok=True)
    _write_skill_dir(staging)
    return compute_skill_digest(staging / "code-review").digest


def _entry(
    priv: str, digest: str, *, version: str = "1.5.0", refs: tuple[SkillSourceRef, ...] = ()
) -> SkillCatalogEntry:
    entry = SkillCatalogEntry(
        id="code-review",
        name="code-review",
        version=version,
        description="code-review catalog entry",
        source=SkillSourceSpec(kind="github", repo="acme/code-review", tag=f"v{version}"),
        content_digest=digest,
        references=refs,
        verified=True,
    )
    return attach_signature(entry, sign_entry(entry, priv))


def _transparent(entry: SkillCatalogEntry, priv: str, pub: str, revocations: tuple[dict, ...] = ()) -> SkillCatalog:
    base = SkillCatalog(version=1, generated_at="2026-05-21T00:00:00Z", entries=(entry,), signer_pubkey=pub)
    log = TransparencyLog.from_states([base.to_dict()])
    envelope = build_catalog_envelope(log, 0, priv)
    return SkillCatalog(
        version=1,
        generated_at="2026-05-21T00:00:00Z",
        entries=(entry,),
        signer_pubkey=pub,
        transparency=envelope,
        revocations=revocations,
    )


def _service(
    tmp_path: Path, catalog: SkillCatalog, installer: Callable[..., PluginInstallResult]
) -> SkillCatalogService:
    return SkillCatalogService(
        config=SkillCatalogServiceConfig(workdir=tmp_path),
        preloaded_catalog=catalog,
        auditor=SkillCatalogAuditor(audit_dir=tmp_path / ".sdd" / "audit"),
        plugin_installer=installer,
    )


def test_verify_passes_after_install(tmp_path: Path, installer: Callable[..., PluginInstallResult]) -> None:
    priv, pub = generate_signer_keypair()
    ref = SkillSourceRef(source=SkillSourceSpec(kind="npm", package="left-pad", version="1.3.0"), digest="a" * 64)
    entry = _entry(priv, _fixture_digest(tmp_path), refs=(ref,))
    catalog = _transparent(entry, priv, pub)
    service = _service(tmp_path, catalog, installer)
    service.install("code-review")

    report = service.verify()
    assert report.ok
    assert report.entries_checked == 1
    assert report.results[0].pinned_references == 1
    assert "inclusion proof verified" in report.results[0].detail


def test_verify_fails_when_recorded_state_byte_mutated(
    tmp_path: Path, installer: Callable[..., PluginInstallResult]
) -> None:
    priv, pub = generate_signer_keypair()
    entry = _entry(priv, _fixture_digest(tmp_path))
    catalog = _transparent(entry, priv, pub)
    service = _service(tmp_path, catalog, installer)
    service.install("code-review")  # records the transparency head

    # Mutate one byte of the catalog state but keep the original signed envelope.
    mutated_entry = SkillCatalogEntry(
        id=entry.id,
        name=entry.name,
        version=entry.version,
        description="TAMPERED description",
        source=entry.source,
        content_digest=entry.content_digest,
        signature=entry.signature,
        verified=entry.verified,
    )
    mutated_catalog = SkillCatalog(
        version=1,
        generated_at="2026-05-21T00:00:00Z",
        entries=(mutated_entry,),
        signer_pubkey=pub,
        transparency=catalog.transparency,  # stale envelope over the un-mutated leaves
    )
    verifier = _service(tmp_path, mutated_catalog, installer)
    report = verifier.verify()
    assert not report.ok
    assert "transparency verification failed" in report.results[0].detail


def test_verify_fails_for_revoked_install(tmp_path: Path, installer: Callable[..., PluginInstallResult]) -> None:
    priv, pub = generate_signer_keypair()
    entry = _entry(priv, _fixture_digest(tmp_path))
    catalog = _transparent(entry, priv, pub)
    service = _service(tmp_path, catalog, installer)
    service.install("code-review")

    # Publisher later revokes; a fresh verify (revocation added to the catalog)
    # must flag the installed version.
    revocation = sign_revocation(
        RevocationEntry(
            skill_id="code-review", version_range=">=1.0.0,<2.0.0", reason="CVE", issued_at="2026-07-16T00:00:00Z"
        ),
        priv,
    )
    revoked_catalog = _transparent(entry, priv, pub, revocations=(revocation.to_dict(),))
    verifier = _service(tmp_path, revoked_catalog, installer)
    report = verifier.verify()
    assert not report.ok
    assert report.revoked == ("code-review",)


def test_verify_passes_for_legacy_catalog_without_transparency(
    tmp_path: Path, installer: Callable[..., PluginInstallResult]
) -> None:
    priv, pub = generate_signer_keypair()
    entry = _entry(priv, _fixture_digest(tmp_path))
    catalog = SkillCatalog(version=1, generated_at="2026-05-21T00:00:00Z", entries=(entry,), signer_pubkey=pub)
    service = _service(tmp_path, catalog, installer)
    service.install("code-review")
    report = service.verify()
    assert report.ok
