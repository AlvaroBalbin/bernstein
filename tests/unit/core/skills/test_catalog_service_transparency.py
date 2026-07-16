"""Install-time transparency + revocation enforcement (issue #2527).

Acceptance:
- install with a valid inclusion proof succeeds and yields a verifiable
  receipt {entry digest, inclusion proof, signed head};
- a catalog rewrite (same version tag, different content) is refused via a
  consistency-proof failure against the head recorded in ``skills.lock``, with
  a chain-anchored refusal receipt;
- a signed revocation refuses the install with a refusal receipt;
- ``require_transparency`` refuses a catalog with no log head.
"""

from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from bernstein.core.plugins_core.plugin_installer import PluginInstallResult
from bernstein.core.security.audit import AuditLog
from bernstein.core.skills.catalog import (
    CATALOG_LOCK_FILENAME,
    SkillCatalog,
    SkillCatalogAuditor,
    SkillCatalogEntry,
    SkillCatalogError,
    SkillCatalogService,
    SkillCatalogServiceConfig,
    SkillSourceSpec,
    TransparencyLog,
    generate_signer_keypair,
    read_state,
    sign_entry,
)
from bernstein.core.skills.catalog.revocation import RevocationEntry, sign_revocation
from bernstein.core.skills.catalog.signature import attach_signature
from bernstein.core.skills.catalog.transparency import build_catalog_envelope

FIXTURE_DESCRIPTION = "Fixture catalog entry installed from github."


@pytest.fixture(autouse=True)
def isolate_audit_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BERNSTEIN_AUDIT_KEY_PATH", str(tmp_path / "audit.key"))


def _write_skill_dir(root: Path, *, name: str, description: str) -> Path:
    skill_dir = root / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        textwrap.dedent(
            f"""
            ---
            name: {name}
            description: {description}
            ---

            Body.
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return skill_dir


@pytest.fixture
def github_fixture_installer() -> Callable[..., PluginInstallResult]:
    def _installer(source, install_dir):  # type: ignore[no-untyped-def]
        _write_skill_dir(install_dir, name="code-review", description=FIXTURE_DESCRIPTION)
        return PluginInstallResult(
            success=True,
            install_path=install_dir / "code-review",
            source_kind=source.kind,
        )

    return _installer


def _fixture_digest(tmp_path: Path) -> str:
    from bernstein.core.skills.lifecycle import compute_skill_digest

    staging = tmp_path / "_digest_staging"
    staging.mkdir(exist_ok=True)
    _write_skill_dir(staging, name="code-review", description=FIXTURE_DESCRIPTION)
    return compute_skill_digest(staging / "code-review").digest


def _signed_entry(priv: str, digest: str, *, version: str = "1.0.0") -> SkillCatalogEntry:
    entry = SkillCatalogEntry(
        id="code-review",
        name="code-review",
        version=version,
        description="code-review catalog entry",
        source=SkillSourceSpec(kind="github", repo="acme/code-review", tag=f"v{version}"),
        content_digest=digest,
        tags=("review",),
        verified=True,
    )
    return attach_signature(entry, sign_entry(entry, priv))


def _transparent_catalog(
    entry: SkillCatalogEntry,
    priv: str,
    pub: str,
    *,
    prior_states: tuple[dict[str, object], ...] = (),
    generated_at: str = "2026-05-21T00:00:00Z",
) -> SkillCatalog:
    """Build a signed catalog carrying a transparency envelope over its state."""
    base = SkillCatalog(version=1, generated_at=generated_at, entries=(entry,), signer_pubkey=pub)
    state = base.to_dict()
    log = TransparencyLog.from_states([*prior_states, state])
    leaf_index = len(prior_states)
    envelope = build_catalog_envelope(log, leaf_index, priv)
    return SkillCatalog(
        version=1,
        generated_at=generated_at,
        entries=(entry,),
        signer_pubkey=pub,
        transparency=envelope,
    )


def _service(
    tmp_path: Path,
    catalog: SkillCatalog,
    installer: Callable[..., PluginInstallResult],
    *,
    require_transparency: bool = False,
) -> SkillCatalogService:
    config = SkillCatalogServiceConfig(workdir=tmp_path, require_transparency=require_transparency)
    return SkillCatalogService(
        config=config,
        preloaded_catalog=catalog,
        auditor=SkillCatalogAuditor(audit_dir=tmp_path / ".sdd" / "audit"),
        plugin_installer=installer,
    )


# ---------------------------------------------------------------------------
# Happy path: valid inclusion proof
# ---------------------------------------------------------------------------


def test_install_with_valid_inclusion_proof_succeeds(
    tmp_path: Path,
    github_fixture_installer: Callable[..., PluginInstallResult],
) -> None:
    priv, pub = generate_signer_keypair()
    entry = _signed_entry(priv, _fixture_digest(tmp_path))
    catalog = _transparent_catalog(entry, priv, pub)
    service = _service(tmp_path, catalog, github_fixture_installer)

    outcome = service.install("code-review")

    assert outcome.inclusion_receipt is not None
    receipt = outcome.inclusion_receipt
    assert receipt.entry_digest == entry.content_digest
    assert receipt.head.tree_size == 1
    # The receipt verifies offline against the signer key.
    receipt.verify(pub)

    # The head is recorded in skills.lock for future consistency checks.
    head = read_state(tmp_path / CATALOG_LOCK_FILENAME).find_transparency("code-review")
    assert head is not None
    assert head.root_hash == receipt.head.root_hash
    assert head.tree_size == 1


def test_install_refuses_tampered_inclusion_proof(
    tmp_path: Path,
    github_fixture_installer: Callable[..., PluginInstallResult],
) -> None:
    priv, pub = generate_signer_keypair()
    entry = _signed_entry(priv, _fixture_digest(tmp_path))
    catalog = _transparent_catalog(entry, priv, pub, prior_states=({"s": 0}, {"s": 1}))

    # Tamper: flip the committed leaf so it no longer matches the fetched state.
    envelope = dict(catalog.transparency or {})
    leaves = list(envelope["leaves"])
    leaves[envelope["leaf_index"]] = "f" * 64
    envelope["leaves"] = leaves
    tampered = SkillCatalog(
        version=1,
        generated_at=catalog.generated_at,
        entries=catalog.entries,
        signer_pubkey=pub,
        transparency=envelope,
    )
    service = _service(tmp_path, tampered, github_fixture_installer)

    with pytest.raises(SkillCatalogError, match="transparency verification failed"):
        service.install("code-review")


# ---------------------------------------------------------------------------
# Rewrite / split-view detection via consistency proof
# ---------------------------------------------------------------------------


def test_catalog_rewrite_refused_by_consistency_proof(
    tmp_path: Path,
    github_fixture_installer: Callable[..., PluginInstallResult],
) -> None:
    priv, pub = generate_signer_keypair()
    digest = _fixture_digest(tmp_path)
    entry = _signed_entry(priv, digest)

    # First install: honest state A at leaf 0. Records head {size=1, root=leaf_A}.
    catalog_a = _transparent_catalog(entry, priv, pub, generated_at="2026-05-21T00:00:00Z")
    service_a = _service(tmp_path, catalog_a, github_fixture_installer)
    service_a.install("code-review")

    # Second fetch: publisher rewrote the state at index 0 (different bytes,
    # same version tag) and appended state B at index 1.
    rewritten_prior_state = SkillCatalog(
        version=1,
        generated_at="REWRITTEN",  # one byte different -> different leaf 0
        entries=(entry,),
        signer_pubkey=pub,
    ).to_dict()
    catalog_b = _transparent_catalog(
        entry,
        priv,
        pub,
        prior_states=(rewritten_prior_state,),
        generated_at="2026-05-22T00:00:00Z",
    )
    service_b = _service(tmp_path, catalog_b, github_fixture_installer)

    with pytest.raises(SkillCatalogError, match="consistency"):
        service_b.install("code-review")

    # A chain-anchored refusal receipt was recorded.
    log = AuditLog(tmp_path / ".sdd" / "audit")
    refusals = log.query(event_type="skill.verification_refusal")
    assert len(refusals) == 1
    assert refusals[0].details["reason_code"] == "consistency_proof_failed"
    ok, _errors = log.verify()
    assert ok


# ---------------------------------------------------------------------------
# require_transparency
# ---------------------------------------------------------------------------


def test_require_transparency_refuses_catalog_without_head(
    tmp_path: Path,
    github_fixture_installer: Callable[..., PluginInstallResult],
) -> None:
    priv, pub = generate_signer_keypair()
    entry = _signed_entry(priv, _fixture_digest(tmp_path))
    catalog = SkillCatalog(version=1, generated_at="2026-05-21T00:00:00Z", entries=(entry,), signer_pubkey=pub)
    service = _service(tmp_path, catalog, github_fixture_installer, require_transparency=True)

    with pytest.raises(SkillCatalogError, match="no transparency log head"):
        service.install("code-review")


def test_legacy_catalog_without_transparency_still_installs(
    tmp_path: Path,
    github_fixture_installer: Callable[..., PluginInstallResult],
) -> None:
    priv, pub = generate_signer_keypair()
    entry = _signed_entry(priv, _fixture_digest(tmp_path))
    catalog = SkillCatalog(version=1, generated_at="2026-05-21T00:00:00Z", entries=(entry,), signer_pubkey=pub)
    service = _service(tmp_path, catalog, github_fixture_installer)

    outcome = service.install("code-review")
    assert outcome.inclusion_receipt is None
    assert outcome.entry_id == "code-review"


# ---------------------------------------------------------------------------
# Revocation refusal at install time
# ---------------------------------------------------------------------------


def test_install_refuses_revoked_version_with_receipt(
    tmp_path: Path,
    github_fixture_installer: Callable[..., PluginInstallResult],
) -> None:
    priv, pub = generate_signer_keypair()
    entry = _signed_entry(priv, _fixture_digest(tmp_path), version="1.5.0")
    revocation = sign_revocation(
        RevocationEntry(
            skill_id="code-review",
            version_range=">=1.0.0,<2.0.0",
            reason="CVE-2026-1234",
            issued_at="2026-07-16T00:00:00Z",
        ),
        priv,
    )
    catalog = SkillCatalog(
        version=1,
        generated_at="2026-05-21T00:00:00Z",
        entries=(entry,),
        signer_pubkey=pub,
        revocations=(revocation.to_dict(),),
    )
    service = _service(tmp_path, catalog, github_fixture_installer)

    with pytest.raises(SkillCatalogError, match="revoked"):
        service.install("code-review")

    log = AuditLog(tmp_path / ".sdd" / "audit")
    refusals = log.query(event_type="skill.verification_refusal")
    assert len(refusals) == 1
    assert refusals[0].details["reason_code"] == "revoked"


def test_install_allows_version_outside_revoked_range(
    tmp_path: Path,
    github_fixture_installer: Callable[..., PluginInstallResult],
) -> None:
    priv, pub = generate_signer_keypair()
    entry = _signed_entry(priv, _fixture_digest(tmp_path), version="2.0.0")
    revocation = sign_revocation(
        RevocationEntry(
            skill_id="code-review",
            version_range=">=1.0.0,<2.0.0",
            reason="CVE-2026-1234",
            issued_at="2026-07-16T00:00:00Z",
        ),
        priv,
    )
    catalog = SkillCatalog(
        version=1,
        generated_at="2026-05-21T00:00:00Z",
        entries=(entry,),
        signer_pubkey=pub,
        revocations=(revocation.to_dict(),),
    )
    service = _service(tmp_path, catalog, github_fixture_installer)

    outcome = service.install("code-review")  # 2.0.0 is outside [1.0.0, 2.0.0)
    assert outcome.entry_id == "code-review"
