"""``bernstein endpoints`` - certify and verify self-hosted endpoints.

Issue #2889. The local-model worker tier already ships endpoint conformance
and signed certification (issue #2356), previously reachable only through
``bernstein doctor --endpoint``. Self-hosted OpenAI-compatible serving
(vLLM, llama.cpp server, TGI, NVIDIA NIM, LM Studio, Ollama) is now the
default enterprise inference posture, so this group names the capability
directly:

* ``bernstein endpoints certify --base-url ...`` probes an arbitrary
  OpenAI-compatible endpoint and seals the existing signed certification
  receipt (Ed25519-signed, lineage-anchored, mirrored into the HMAC audit
  chain). The receipt is the point: "this endpoint behaved
  contract-correctly at qualification time" becomes a signed, dated claim
  rather than a folklore note.
* ``bernstein endpoints verify --base-url ... --model ...`` re-checks that
  receipt fully offline -- no endpoint contact -- against the stored
  receipt, its signature, and the certification spine anchor.

The certify path reuses the same implementation as ``doctor --endpoint``
so the two surfaces never diverge; only the option spelling differs.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from bernstein.cli.helpers import console

__all__ = [
    "endpoints_certify_cmd",
    "endpoints_group",
    "endpoints_verify_cmd",
    "register",
]


@click.group("endpoints")
def endpoints_group() -> None:
    """Certify and verify self-hosted OpenAI-compatible endpoints.

    \b
      bernstein endpoints certify --base-url http://127.0.0.1:11434/v1
                                        # probe + seal a signed certification receipt
      bernstein endpoints verify  --base-url http://127.0.0.1:11434/v1 --model qwen2.5-coder
                                        # re-check the stored receipt offline
    """


@endpoints_group.command("certify")
@click.option(
    "--base-url",
    "base_url",
    required=True,
    help="OpenAI-compatible base URL to certify (e.g. http://127.0.0.1:11434/v1).",
)
@click.option(
    "--model",
    "model",
    default=None,
    help="Model id to certify; defaults to the first entry of the endpoint's /models listing.",
)
@click.option(
    "--engine",
    "engine",
    default="",
    help="Runtime label recorded in the receipt (e.g. vllm, llamacpp, tgi, nim, lmstudio, ollama).",
)
@click.option(
    "--api-key-env",
    "api_key_env",
    default=None,
    help="NAME of the environment variable holding the endpoint's API key (never the key itself).",
)
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=60.0,
    show_default=True,
    help="Per-probe response budget in seconds; exceeding it fails the probe.",
)
@click.option(
    "--role",
    "roles",
    multiple=True,
    help="Role(s) to evaluate against the endpoint (repeatable). Defaults to the low-stakes local tier.",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output raw JSON.")
def endpoints_certify_cmd(
    base_url: str,
    model: str | None,
    engine: str,
    api_key_env: str | None,
    timeout: float,
    roles: tuple[str, ...],
    as_json: bool,
) -> None:
    """Probe an arbitrary OpenAI-compatible endpoint and seal a signed receipt.

    Runs the deterministic conformance subset (reachability, chat completion,
    tool calling, patch fidelity, timeout behavior, context floor) and binds
    the transcript plus per-role verdicts into an Ed25519-signed receipt
    anchored to the audit chain. Exit code: 0 when every evaluated role
    certified, 1 when at least one was rejected, 2 when no model could be
    resolved.
    """
    from bernstein.cli.commands.doctor_cmd import _run_endpoint_certification

    exit_code = _run_endpoint_certification(
        endpoint=base_url,
        model=model,
        engine=engine,
        api_key_env=api_key_env,
        timeout=timeout,
        roles=roles,
        as_json=as_json,
        model_flag="--model",
    )
    if exit_code:
        raise SystemExit(exit_code)


@endpoints_group.command("verify")
@click.option(
    "--base-url",
    "base_url",
    required=True,
    help="OpenAI-compatible base URL whose stored receipt should be verified.",
)
@click.option(
    "--model",
    "model",
    required=True,
    help="Model id the receipt was sealed for (part of the receipt fingerprint).",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output raw JSON.")
def endpoints_verify_cmd(base_url: str, model: str, as_json: bool) -> None:
    """Re-verify a stored certification receipt fully offline.

    Checks, from the stored receipt alone (no endpoint contact): the
    endpoint identity, the Ed25519 signature over the canonical binding,
    and the certification spine anchor. Exit code: 0 when the receipt
    verifies, 1 otherwise.
    """
    exit_code = _run_endpoint_verification(base_url=base_url, model=model, as_json=as_json)
    if exit_code:
        raise SystemExit(exit_code)


def _run_endpoint_verification(*, base_url: str, model: str, as_json: bool) -> int:
    """Verify the stored receipt for ``(base_url, model)`` offline.

    Returns 0 when the receipt verifies and 1 otherwise, so the surface
    fails closed for an absent, mismatched, or tampered receipt.
    """
    from bernstein.core.endpoints.certification import (
        endpoint_fingerprint,
        verify_endpoint_certification,
    )
    from bernstein.core.endpoints.conformance import normalize_base_url
    from bernstein.core.security.audit import load_or_create_audit_key

    workdir = Path.cwd()
    hmac_key = load_or_create_audit_key()
    result = verify_endpoint_certification(
        workdir=workdir,
        lineage_root=workdir / ".sdd" / "lineage",
        hmac_key=hmac_key,
        base_url=base_url,
        model=model,
    )
    fingerprint = endpoint_fingerprint(base_url, model)
    certified_roles = sorted(result.certification.certified_roles()) if result.certification else []

    if as_json:
        payload = {
            "ok": result.ok,
            "reason": result.reason,
            "base_url": normalize_base_url(base_url),
            "model": model,
            "fingerprint": fingerprint,
            "certified_roles": certified_roles,
        }
        if result.certification is not None:
            payload["journal_entry_hash"] = result.certification.journal_entry_hash
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if result.ok else 1

    console.print()
    console.print(f"[bold]Endpoint verification[/bold] {normalize_base_url(base_url)} model={model}")
    console.print(f"  fingerprint {fingerprint}")
    if result.ok:
        console.print("  status      [green]verified[/green]")
        if certified_roles:
            console.print(f"  roles       {', '.join(certified_roles)}")
    else:
        console.print("  status      [red]not verified[/red]")
        console.print(f"  reason      {result.reason}")
    console.print()
    return 0 if result.ok else 1


def register(group: click.Group) -> None:
    """Attach the endpoints group to the top-level CLI."""
    group.add_command(endpoints_group, "endpoints")
