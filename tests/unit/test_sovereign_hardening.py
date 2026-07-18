"""Sovereign-profile hardening regression suite (issue #2638).

The headline invariant is empirical, not documentary: whatever egress posture
the signed attestation claims must equal the egress posture the runtime network
policy actually enforces. Everything else in this module guards the paths that
could let the two diverge -- a half-set marker pair that skips the gate, an
unreadable config that silently resolves to a permissive default, an
under-validated signed record that is trusted on its own say-so, and a resume
spawn that never re-checks the posture.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from bernstein.core.agents.spawner_core import AgentSpawner
from bernstein.core.security.audit_chain import AuditChainStore
from bernstein.core.security.deployment_profile import (
    SOVEREIGN_PROFILE,
    PostureAttestation,
    PostureDriftRefusal,
    SovereignConfigError,
    attestation_path,
    build_posture_attestation,
    egress_attestation_mismatch,
    enforced_egress_posture,
    evaluate_posture_drift,
    load_config_snapshot,
    read_posture_attestation,
    resolve_effective_policy,
    sovereign_egress_allowlist,
)
from bernstein.core.security.network_policy import (
    ENV_NETWORK_POLICY,
    ENV_PROFILE_MODE,
    ENV_SOVEREIGN_MODE,
    PROFILE_AIRGAP,
    NetworkPolicy,
    SovereignMarkerError,
    is_sovereign_profile,
    policy_from_env,
)

_SOVEREIGN_ENV = (ENV_PROFILE_MODE, ENV_NETWORK_POLICY, ENV_SOVEREIGN_MODE)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test from a process with no profile markers installed.

    ``install_policy`` writes ``os.environ`` directly, so a bare
    ``monkeypatch.delenv(..., raising=False)`` on an already-absent variable
    would record nothing and leave the marker set for the next module. Touching
    each variable with ``setenv`` first registers the pre-test state (including
    "absent") so teardown always restores it.
    """
    for var in _SOVEREIGN_ENV:
        monkeypatch.setenv(var, "")
        monkeypatch.delenv(var, raising=False)


def _write_config(workdir: Path, body: str) -> None:
    (workdir / ".sdd" / "audit").mkdir(parents=True, exist_ok=True)
    (workdir / "bernstein.yaml").write_text(body, encoding="utf-8")


def _activate(workdir: Path, allow_network: tuple[str, ...] = ()) -> None:
    """Run the real CLI activation path (network policy + attestation)."""
    from bernstein.cli.run_bootstrap import _activate_sovereign_profile, _install_profile_network_policy

    _install_profile_network_policy(run_profile=SOVEREIGN_PROFILE, allow_network=allow_network, workdir=workdir)
    _activate_sovereign_profile(run_profile=SOVEREIGN_PROFILE, workdir=workdir)


@pytest.fixture(autouse=True)
def _restore_socket_guard() -> Any:
    """Restore ``socket.socket`` exactly as this test found it.

    The activation path installs the runtime socket guard, which patches
    ``socket.socket.connect`` on the class and stashes the pre-patch callable in
    a class attribute. Calling ``uninstall_runtime_socket_guard()`` blindly is
    not safe here: if a stale install flag is left over from an earlier module,
    uninstall restores *that* module's captured connect over the one currently
    installed, permanently swapping in a foreign patch. Snapshotting and
    restoring the three pieces of state is exact and cannot leak either way.
    """
    import socket

    from bernstein.core.security.socket_guard import _INSTALLED_FLAG, _ORIGINAL_FLAG

    sentinel = object()
    prior_connect = socket.socket.connect
    prior_installed = getattr(socket.socket, _INSTALLED_FLAG, sentinel)
    prior_original = getattr(socket.socket, _ORIGINAL_FLAG, sentinel)
    try:
        yield
    finally:
        socket.socket.connect = prior_connect  # type: ignore[method-assign]
        for flag, value in ((_INSTALLED_FLAG, prior_installed), (_ORIGINAL_FLAG, prior_original)):
            if value is sentinel:
                if hasattr(socket.socket, flag):
                    delattr(socket.socket, flag)
            else:
                setattr(socket.socket, flag, value)


def _preflight(workdir: Path) -> None:
    AgentSpawner._preflight_posture_drift(SimpleNamespace(_workdir=workdir))  # type: ignore[arg-type]


def _spawner_shim(workdir: Path) -> SimpleNamespace:
    """A spawner stand-in exposing only what the gate touches.

    ``spawn_for_resume`` calls ``self._preflight_posture_drift()``, so the shim
    binds the real unbound method to itself. Any refusal therefore comes from
    the production gate, not from the shim running out of attributes.
    """
    shim = SimpleNamespace(_workdir=workdir)
    shim._preflight_posture_drift = lambda: AgentSpawner._preflight_posture_drift(shim)  # type: ignore[arg-type]
    return shim


# ---------------------------------------------------------------------------
# Headline invariant: attested posture == enforced posture
# ---------------------------------------------------------------------------

_COMPLIANT_DENY_ALL = "goal: x\nstorage:\n  backend: memory\n"
_COMPLIANT_ALLOW_LIST = (
    "goal: x\nstorage:\n  backend: memory\nsovereign:\n  enabled: true\n  allowed_egress:\n    - '10.0.0.5:11434'\n"
)


def _attested_egress(workdir: Path) -> tuple[str, tuple[str, ...]]:
    """Read the signed attestation from disk and project its egress claim."""
    raw = json.loads(attestation_path(workdir).read_text(encoding="utf-8"))
    document = raw["effective_policy"]
    return str(document["network_egress"]), tuple(document["egress_allowlist"])


@pytest.mark.usefixtures("clean_env")
def test_attested_posture_equals_enforced_posture_deny_all(tmp_path: Path) -> None:
    """A config declaring no egress attests deny-all and enforces deny-all."""
    _write_config(tmp_path, _COMPLIANT_DENY_ALL)
    _activate(tmp_path)

    assert _attested_egress(tmp_path) == ("deny-all", ())
    assert _attested_egress(tmp_path) == enforced_egress_posture(policy_from_env())
    assert policy_from_env().is_allowed("10.0.0.5", 11434) is False


@pytest.mark.usefixtures("clean_env")
def test_attested_posture_equals_enforced_posture_allow_list(tmp_path: Path) -> None:
    """The core defect: a policy that allows a destination must NOT attest deny-all.

    The runtime genuinely reaches ``10.0.0.5:11434``; the signed attestation must
    say so, byte-for-byte, instead of claiming a deny-all posture it does not
    enforce.
    """
    _write_config(tmp_path, _COMPLIANT_ALLOW_LIST)
    _activate(tmp_path)

    attested = _attested_egress(tmp_path)
    assert attested != ("deny-all", ()), "attestation claims deny-all while the runtime allows a destination"
    assert attested == ("allow-list", ("10.0.0.5:11434",))
    # Empirical equality: the attested claim equals what the live policy enforces.
    assert attested == enforced_egress_posture(policy_from_env())
    assert policy_from_env().is_allowed("10.0.0.5", 11434) is True
    assert policy_from_env().is_allowed("api.example.com", 443) is False


@pytest.mark.usefixtures("clean_env")
def test_attested_allowlist_tokens_are_exactly_the_enforced_rules(tmp_path: Path) -> None:
    """Token normalisation must not let the attested list drift from the rules."""
    _write_config(
        tmp_path,
        "goal: x\nstorage:\n  backend: memory\nsovereign:\n"
        "  allowed_egress: ['none', '10.0.0.0/8', ' 10.0.0.5:11434 ', '10.0.0.0/8']\n",
    )
    _activate(tmp_path)

    attested_mode, attested_tokens = _attested_egress(tmp_path)
    runtime = policy_from_env()
    assert attested_mode == "allow-list"
    assert attested_tokens == tuple(runtime.rules)
    assert (attested_mode, attested_tokens) == enforced_egress_posture(runtime)


def test_egress_mismatch_is_detected() -> None:
    """The invariant check itself must catch a deny-all claim over an open runtime."""
    policy = resolve_effective_policy(SOVEREIGN_PROFILE, {"storage": {"backend": "memory"}})
    assert policy.network_egress == "deny-all"
    assert egress_attestation_mismatch(policy, NetworkPolicy.deny_all()) is None
    assert egress_attestation_mismatch(policy, NetworkPolicy.allow_all()) is not None
    assert egress_attestation_mismatch(policy, NetworkPolicy.from_specs(("10.0.0.5",))) is not None


def test_sovereign_egress_allowlist_normalises_tokens() -> None:
    """Normalisation is deterministic: sorted, de-duplicated, ``none`` dropped."""
    config = {"sovereign": {"allowed_egress": [" 10.0.0.5:11434 ", "NONE", "10.0.0.0/8", "10.0.0.0/8"]}}
    assert sovereign_egress_allowlist(config) == ("10.0.0.0/8", "10.0.0.5:11434")
    assert sovereign_egress_allowlist({"sovereign": {"allowed_egress": ["none"]}}) == ()


# ---------------------------------------------------------------------------
# Enforcement before attestation
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_env")
def test_activation_refuses_to_attest_a_non_compliant_posture(tmp_path: Path) -> None:
    """A violating posture must never be sealed as a sovereign attestation."""
    _write_config(tmp_path, "goal: x\nstorage:\n  backend: postgres\n")
    with pytest.raises(SystemExit):
        _activate(tmp_path)
    assert not attestation_path(tmp_path).is_file(), "a non-compliant posture was attested"


@pytest.mark.usefixtures("clean_env")
def test_activation_refusal_is_anchored_as_a_signed_record(tmp_path: Path) -> None:
    """The refusal is evidence on the chain, not just a console message."""
    from bernstein.core.security.audit import AuditLog
    from bernstein.core.security.audit_chain import EVENT_SOVEREIGN_DRIFT
    from bernstein.core.security.deployment_profile import verify_sovereign_attestations

    _write_config(tmp_path, "goal: x\nstorage:\n  backend: postgres\n")
    with pytest.raises(SystemExit):
        _activate(tmp_path)
    audit_dir = tmp_path / ".sdd" / "audit"
    assert AuditLog(audit_dir=audit_dir).query(event_type=EVENT_SOVEREIGN_DRIFT), (
        "no signed refusal record was anchored"
    )
    # The refusal must survive the same offline verification an auditor runs.
    result = verify_sovereign_attestations(audit_dir)
    assert result.ok is True, result.errors
    assert result.attestation_count == 0, "a refused activation must not attest a posture"
    assert result.drift_count == 1


@pytest.mark.usefixtures("clean_env")
def test_activation_refuses_a_public_egress_destination(tmp_path: Path) -> None:
    """Egress to a non-local destination is refused before anything is attested."""
    _write_config(
        tmp_path,
        "goal: x\nstorage:\n  backend: memory\nsovereign:\n  allowed_egress: ['api.example.com:443']\n",
    )
    with pytest.raises(SystemExit):
        _activate(tmp_path)
    assert not attestation_path(tmp_path).is_file()


# ---------------------------------------------------------------------------
# Fail-closed source configuration
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_env")
def test_missing_config_fails_closed_on_activation(tmp_path: Path) -> None:
    (tmp_path / ".sdd" / "audit").mkdir(parents=True, exist_ok=True)
    with pytest.raises(SystemExit):
        _activate(tmp_path)
    assert not attestation_path(tmp_path).is_file()


@pytest.mark.usefixtures("clean_env")
def test_unreadable_config_fails_closed_on_activation(tmp_path: Path) -> None:
    _write_config(tmp_path, "goal: x\nstorage: [unbalanced\n")
    with pytest.raises(SystemExit):
        _activate(tmp_path)
    assert not attestation_path(tmp_path).is_file()


def test_load_config_snapshot_require_raises(tmp_path: Path) -> None:
    with pytest.raises(SovereignConfigError):
        load_config_snapshot(tmp_path, require=True)
    (tmp_path / "bernstein.yaml").write_text("goal: x\nstorage: [unbalanced\n", encoding="utf-8")
    with pytest.raises(SovereignConfigError):
        load_config_snapshot(tmp_path, require=True)
    (tmp_path / "bernstein.yaml").write_text("- not-a-mapping\n", encoding="utf-8")
    with pytest.raises(SovereignConfigError):
        load_config_snapshot(tmp_path, require=True)


def test_unreadable_config_refuses_the_spawn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate must refuse rather than fall back to a permissive default posture."""
    monkeypatch.setenv(ENV_SOVEREIGN_MODE, "1")
    monkeypatch.setenv(ENV_PROFILE_MODE, PROFILE_AIRGAP)
    _write_config(tmp_path, _COMPLIANT_DENY_ALL)
    policy = resolve_effective_policy(SOVEREIGN_PROFILE, load_config_snapshot(tmp_path))
    build_posture_attestation(
        workdir=tmp_path, policy=policy, timestamp=1, chain=AuditChainStore(tmp_path / ".sdd" / "audit")
    )
    _preflight(tmp_path)  # baseline: clean posture spawns fine

    (tmp_path / "bernstein.yaml").write_text("goal: x\nstorage: [unbalanced\n", encoding="utf-8")
    with pytest.raises(PostureDriftRefusal) as excinfo:
        _preflight(tmp_path)
    assert any("unreadable" in v or "missing" in v for v in excinfo.value.record["violations"])


# ---------------------------------------------------------------------------
# Signed-record contract validation
# ---------------------------------------------------------------------------


def _seal(tmp_path: Path) -> PostureAttestation:
    _write_config(tmp_path, _COMPLIANT_DENY_ALL)
    policy = resolve_effective_policy(SOVEREIGN_PROFILE, load_config_snapshot(tmp_path))
    return build_posture_attestation(
        workdir=tmp_path, policy=policy, timestamp=1, chain=AuditChainStore(tmp_path / ".sdd" / "audit")
    )


_SEAL_FIELDS = ("signature", "signer_public_key_pem", "journal_entry_hash")


def _resign_body(raw: dict[str, Any], private_pem: str) -> None:
    """Re-sign *raw* in place so its signature matches its mutated body.

    Without this a test that mutates authenticated content is rejected by the
    signature check and never reaches the validator it claims to exercise - it
    would pass even if the required-field, schema, profile, or posture-hash
    checks were deleted. Re-signing makes the signature valid so the *only*
    thing left that can reject the record is the contract check under test.
    """
    from bernstein.core.security.deployment_profile import _canonical_bytes
    from bernstein.core.skills.catalog.signature import sign_payload

    body = {k: v for k, v in raw.items() if k not in _SEAL_FIELDS}
    raw["signature"] = sign_payload(_canonical_bytes(body), private_pem)


def _install_private_key(tmp_path: Path) -> str:
    """Return the install's sovereign private key PEM (created by ``_seal``)."""
    from bernstein.core.security.deployment_profile import load_or_create_sovereign_identity

    private_pem, _ = load_or_create_sovereign_identity(tmp_path / ".sdd" / "sovereign")
    return private_pem


def _rewrite_attestation(tmp_path: Path, mutate: Any, *, resign: bool = False) -> None:
    raw = json.loads(attestation_path(tmp_path).read_text(encoding="utf-8"))
    mutate(raw)
    if resign:
        _resign_body(raw, _install_private_key(tmp_path))
    attestation_path(tmp_path).write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")


@pytest.mark.parametrize(
    "field",
    [
        "record_kind",
        "profile",
        "schema_version",
        "posture_hash",
        "effective_policy",
        "timestamp",
        "signature",
        "signer_public_key_pem",
    ],
)
def test_incomplete_signed_record_is_rejected(tmp_path: Path, field: str) -> None:
    """Every field of the signed-record contract is required before we trust it.

    The record is re-signed after the field is dropped, so the signature is
    valid and only the required-field check can reject it.
    """
    _seal(tmp_path)
    resign = field not in _SEAL_FIELDS
    _rewrite_attestation(tmp_path, lambda raw: raw.pop(field), resign=resign)
    assert read_posture_attestation(tmp_path) is None


def test_unsigned_signed_record_is_rejected(tmp_path: Path) -> None:
    """An attestation whose seal fields are blank is not a signed record."""
    _seal(tmp_path)
    _rewrite_attestation(tmp_path, lambda raw: raw.update({"signature": "", "signer_public_key_pem": ""}))
    assert read_posture_attestation(tmp_path) is None


def test_forged_signed_record_is_rejected(tmp_path: Path) -> None:
    """A hand-edited posture with a stale signature must not be trusted."""
    _seal(tmp_path)
    _rewrite_attestation(tmp_path, lambda raw: raw["effective_policy"].update({"storage_backend": "postgres"}))
    assert read_posture_attestation(tmp_path) is None


def test_resigned_forgery_is_rejected_by_the_posture_hash(tmp_path: Path) -> None:
    """Editing the document and re-signing still fails: the hash no longer matches."""
    _seal(tmp_path)
    _rewrite_attestation(
        tmp_path,
        lambda raw: raw["effective_policy"].update({"storage_backend": "postgres"}),
        resign=True,
    )
    assert read_posture_attestation(tmp_path) is None


def test_record_signed_by_a_foreign_key_is_rejected(tmp_path: Path) -> None:
    """A fully self-consistent record signed by someone else is not our posture.

    Rewriting the document, generating a fresh keypair, signing with it and
    embedding its public key produces a record that verifies perfectly against
    itself. It must still be refused, because the signer is not this install's
    sovereign identity.
    """
    from bernstein.core.security.deployment_profile import _canonical_bytes, _sha256_of
    from bernstein.core.skills.catalog.signature import generate_signer_keypair, sign_payload, verify_payload

    _seal(tmp_path)
    foreign_private, foreign_public = generate_signer_keypair()
    raw = json.loads(attestation_path(tmp_path).read_text(encoding="utf-8"))
    raw["effective_policy"]["storage_backend"] = "postgres"
    raw["posture_hash"] = _sha256_of(raw["effective_policy"])
    body = {k: v for k, v in raw.items() if k not in _SEAL_FIELDS}
    raw["signature"] = sign_payload(_canonical_bytes(body), foreign_private)
    raw["signer_public_key_pem"] = foreign_public
    attestation_path(tmp_path).write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")

    # Premise: the forged record really is internally consistent.
    assert verify_payload(_canonical_bytes(body), raw["signature"], foreign_public, allow_unverified=True).verified
    # It is still refused, because the key is not the install's identity.
    assert read_posture_attestation(tmp_path) is None


def test_wrong_schema_version_is_rejected(tmp_path: Path) -> None:
    _seal(tmp_path)
    _rewrite_attestation(tmp_path, lambda raw: raw.update({"schema_version": 99}), resign=True)
    assert read_posture_attestation(tmp_path) is None


def test_wrong_record_kind_is_rejected(tmp_path: Path) -> None:
    """A drift record renamed into an attestation must not be reinterpreted."""
    _seal(tmp_path)
    _rewrite_attestation(tmp_path, lambda raw: raw.update({"record_kind": "sovereign_drift"}), resign=True)
    assert read_posture_attestation(tmp_path) is None


def test_posture_hash_must_match_the_recorded_document(tmp_path: Path) -> None:
    _seal(tmp_path)
    _rewrite_attestation(tmp_path, lambda raw: raw.update({"posture_hash": "sha256:" + "0" * 64}), resign=True)
    assert read_posture_attestation(tmp_path) is None


def test_untrusted_record_refuses_the_spawn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rejecting a record must fail closed at the gate, not silently pass."""
    monkeypatch.setenv(ENV_SOVEREIGN_MODE, "1")
    monkeypatch.setenv(ENV_PROFILE_MODE, PROFILE_AIRGAP)
    _seal(tmp_path)
    _preflight(tmp_path)  # baseline
    _rewrite_attestation(tmp_path, lambda raw: raw.update({"signature": ""}))
    with pytest.raises(PostureDriftRefusal):
        _preflight(tmp_path)


def test_verify_rejects_a_record_with_no_effective_policy(tmp_path: Path) -> None:
    """``audit verify`` must not skip the hash check when the document is absent.

    The mutated body is re-signed so its signature is valid; the only thing
    that can reject it is the required-field check under test.
    """
    from bernstein.core.security.deployment_profile import _canonical_bytes, verify_sovereign_attestations
    from bernstein.core.skills.catalog.signature import sign_payload

    _seal(tmp_path)
    audit_dir = tmp_path / ".sdd" / "audit"
    assert verify_sovereign_attestations(audit_dir).ok is True

    private_pem = _install_private_key(tmp_path)
    entries = sorted(audit_dir.glob("*.jsonl"))
    assert entries, "no audit chain file was written"
    target = entries[0]
    mutated = False
    patched: list[str] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        details = row.get("details", {})
        body = details.get("signed_body")
        if isinstance(body, dict) and "effective_policy" in body:
            body.pop("effective_policy")
            details["signature"] = sign_payload(_canonical_bytes(body), private_pem)
            mutated = True
        patched.append(json.dumps(row))
    assert mutated, "no sovereign record found to mutate"
    target.write_text("\n".join(patched) + "\n", encoding="utf-8")

    result = verify_sovereign_attestations(audit_dir)
    assert result.ok is False
    assert any("effective_policy" in err or "missing required field" in err for err in result.errors), result.errors


# ---------------------------------------------------------------------------
# Marker pair consistency
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("clean_env")
def test_complete_marker_pair_is_sovereign(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_SOVEREIGN_MODE, "1")
    monkeypatch.setenv(ENV_PROFILE_MODE, PROFILE_AIRGAP)
    assert is_sovereign_profile() is True


@pytest.mark.usefixtures("clean_env")
def test_absent_markers_are_not_sovereign() -> None:
    assert is_sovereign_profile() is False


@pytest.mark.usefixtures("clean_env")
def test_half_set_marker_pair_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sovereign claimed without the airgap network posture must not be believed."""
    monkeypatch.setenv(ENV_SOVEREIGN_MODE, "1")
    with pytest.raises(SovereignMarkerError):
        is_sovereign_profile()


@pytest.mark.usefixtures("clean_env")
def test_unrecognised_marker_value_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo in the marker must fail closed, not silently disable the gate."""
    monkeypatch.setenv(ENV_SOVEREIGN_MODE, "yes")
    monkeypatch.setenv(ENV_PROFILE_MODE, PROFILE_AIRGAP)
    with pytest.raises(SovereignMarkerError):
        is_sovereign_profile()


@pytest.mark.usefixtures("clean_env")
def test_half_set_markers_do_not_bypass_the_spawn_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The bypass this closes: drop one marker, keep the other, spawn anyway."""
    _seal(tmp_path)
    (tmp_path / "bernstein.yaml").write_text("goal: x\nstorage:\n  backend: postgres\n", encoding="utf-8")
    monkeypatch.setenv(ENV_SOVEREIGN_MODE, "1")
    monkeypatch.delenv(ENV_PROFILE_MODE, raising=False)
    with pytest.raises(PostureDriftRefusal):
        _preflight(tmp_path)


@pytest.mark.usefixtures("clean_env")
def test_dropping_the_sovereign_marker_does_not_bypass_an_attested_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A workspace carrying a signed attestation stays gated even with no markers."""
    _seal(tmp_path)
    (tmp_path / "bernstein.yaml").write_text("goal: x\nstorage:\n  backend: postgres\n", encoding="utf-8")
    for var in _SOVEREIGN_ENV:
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(PostureDriftRefusal):
        _preflight(tmp_path)


@pytest.mark.usefixtures("clean_env")
def test_policy_from_env_fails_closed_under_a_network_locked_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stripped policy variable must not reopen egress under a locked profile."""
    monkeypatch.setenv(ENV_PROFILE_MODE, PROFILE_AIRGAP)
    monkeypatch.delenv(ENV_NETWORK_POLICY, raising=False)
    assert policy_from_env().allow_any is False
    monkeypatch.setenv(ENV_NETWORK_POLICY, "")
    assert policy_from_env().allow_any is False


@pytest.mark.usefixtures("clean_env")
def test_policy_from_env_keeps_back_compat_outside_locked_profiles() -> None:
    assert policy_from_env().allow_any is True


@pytest.mark.usefixtures("clean_env")
def test_install_policy_clears_markers_it_does_not_assert() -> None:
    """A second install must not inherit the first one's markers.

    Leaving a stale sovereign or airgap marker behind is how a later
    non-sovereign run in the same process ends up in the half-set state.
    """
    import os

    from bernstein.core.security.network_policy import install_policy

    install_policy(NetworkPolicy.deny_all(), profile=PROFILE_AIRGAP, sovereign=True)
    assert is_sovereign_profile() is True

    install_policy(NetworkPolicy.allow_all())
    assert os.environ.get(ENV_SOVEREIGN_MODE) is None
    assert os.environ.get(ENV_PROFILE_MODE) is None
    assert is_sovereign_profile() is False


@pytest.mark.usefixtures("clean_env")
def test_install_policy_refuses_sovereign_without_the_airgap_profile() -> None:
    from bernstein.core.security.network_policy import install_policy

    with pytest.raises(SovereignMarkerError):
        install_policy(NetworkPolicy.deny_all(), sovereign=True)


def test_attested_workspace_refuses_an_open_runtime_with_markers_stripped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stripping the markers must not skip the egress invariant.

    With no markers the process policy is allow-all, while the workspace still
    carries a signed deny-all attestation. That is the mismatch the gate exists
    to catch, so it must refuse rather than pass on an unchanged config hash.
    """
    _seal(tmp_path)
    for var in _SOVEREIGN_ENV:
        monkeypatch.delenv(var, raising=False)
    assert policy_from_env().allow_any is True  # premise: runtime is wide open
    with pytest.raises(PostureDriftRefusal) as excinfo:
        _preflight(tmp_path)
    assert any("does not equal the enforced runtime policy" in v for v in excinfo.value.record["violations"])


# ---------------------------------------------------------------------------
# Resume-path drift gating
# ---------------------------------------------------------------------------


def test_resume_spawn_is_drift_gated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Behavioural proof (not source inspection) that resume applies the gate."""
    monkeypatch.setenv(ENV_SOVEREIGN_MODE, "1")
    monkeypatch.setenv(ENV_PROFILE_MODE, PROFILE_AIRGAP)
    _seal(tmp_path)
    (tmp_path / "bernstein.yaml").write_text("goal: x\nstorage:\n  backend: postgres\n", encoding="utf-8")
    tasks = [SimpleNamespace(id="t1", role="developer")]
    with pytest.raises(PostureDriftRefusal):
        AgentSpawner.spawn_for_resume(  # type: ignore[arg-type]
            _spawner_shim(tmp_path),
            tasks,  # type: ignore[arg-type]
            worktree_path=tmp_path / "wt",
            changed_files=[],
        )


def test_resume_gate_runs_before_any_worktree_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The refusal must precede adapter/worktree side effects, so a shim suffices."""
    monkeypatch.setenv(ENV_SOVEREIGN_MODE, "1")
    monkeypatch.setenv(ENV_PROFILE_MODE, PROFILE_AIRGAP)
    _write_config(tmp_path, _COMPLIANT_DENY_ALL)  # attested never -> refusal
    tasks = [SimpleNamespace(id="t1", role="developer")]
    with pytest.raises(PostureDriftRefusal):
        AgentSpawner.spawn_for_resume(  # type: ignore[arg-type]
            _spawner_shim(tmp_path),
            tasks,  # type: ignore[arg-type]
            worktree_path=tmp_path / "wt",
            changed_files=[],
        )
    assert not (tmp_path / "wt").exists()


def test_evaluate_posture_drift_folds_in_extra_violations(tmp_path: Path) -> None:
    _write_config(tmp_path, _COMPLIANT_DENY_ALL)
    snapshot = load_config_snapshot(tmp_path)
    policy = resolve_effective_policy(SOVEREIGN_PROFILE, snapshot)
    build_posture_attestation(
        workdir=tmp_path, policy=policy, timestamp=1, chain=AuditChainStore(tmp_path / ".sdd" / "audit")
    )
    clean = evaluate_posture_drift(workdir=tmp_path, config_snapshot=snapshot)
    assert clean.should_refuse is False
    gated = evaluate_posture_drift(
        workdir=tmp_path, config_snapshot=snapshot, extra_violations=("markers are half-set",)
    )
    assert gated.should_refuse is True
    assert "markers are half-set" in gated.violations
