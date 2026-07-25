"""
bernstein-bench: CLI entry points.

Provides:
    bernstein bench run <suite>   — execute a suite, emit a signed bundle
    bernstein bench verify <bundle> — replay receipts offline, report MATCH / DIVERGED

These are thin wrappers that wire together the library classes.  They are
designed to be registered as console_scripts in pyproject.toml:

    [project.scripts]
    bernstein-bench-run    = "bernstein.eval.bench.bench_cli:cmd_run"
    bernstein-bench-verify = "bernstein.eval.bench.bench_cli:cmd_verify"

Or called from the parent ``bernstein`` CLI dispatcher:

    bernstein bench run golden-v1 --out bundle.json
    bernstein bench verify bundle.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Suite registry
# ---------------------------------------------------------------------------

def _get_suite(name: str):
    """
    Resolve a suite name to a :class:`BenchSuite`.

    Currently supports the built-in ``golden-v1`` suite and any path ending
    in ``.json`` (treated as a serialised suite file).
    """
    from bernstein.eval.bench.suite import BenchSuite
    from bernstein.eval.bench.golden_suite import build_golden_suite_v1

    _BUILTIN = {
        "golden-v1": build_golden_suite_v1,
    }

    if name in _BUILTIN:
        return _BUILTIN[name]()

    path = Path(name)
    if path.suffix == ".json" and path.exists():
        return BenchSuite.load(path)

    raise SystemExit(
        f"Unknown suite {name!r}.\n"
        f"Built-in suites: {', '.join(_BUILTIN)}\n"
        f"Or pass a path to a .json suite file."
    )


# ---------------------------------------------------------------------------
# bernstein bench run
# ---------------------------------------------------------------------------

def cmd_run(argv: list[str] | None = None) -> int:
    """
    Execute a benchmark suite and emit a signed submission bundle.

    Usage: bernstein bench run <suite> [--out <path>] [--scheduler <name>]
    """
    parser = argparse.ArgumentParser(
        prog="bernstein bench run",
        description="Run a bernstein-bench suite and emit a signed submission bundle.",
    )
    parser.add_argument(
        "suite",
        help='Suite name (e.g. "golden-v1") or path to a .json suite file.',
    )
    parser.add_argument(
        "--out",
        default="bundle.json",
        help="Output path for the submission bundle (default: bundle.json).",
    )
    parser.add_argument(
        "--scheduler",
        default="default",
        help='Scheduler name to embed in the bundle (default: "default").',
    )
    parser.add_argument(
        "--stub-signer",
        action="store_true",
        help="Use the stub signer instead of the install identity (for testing).",
    )
    args = parser.parse_args(argv)

    from bernstein.eval.bench.runner import BenchRunner, MockReplayAdapter
    from bernstein.eval.bench.signer import AgentCardSigner, StubSigner

    suite = _get_suite(args.suite)
    print(f"Suite       : {suite.version}")
    print(f"Suite hash  : {suite.suite_hash}")
    print(f"Tasks       : {len(suite.tasks)}")

    # Production: swap MockReplayAdapter for the real scenario_runner adapter.
    # The mock is used here so the CLI works out-of-the-box without a live env.
    adapter = MockReplayAdapter()
    runner = BenchRunner(
        suite=suite,
        adapter=adapter,
        scheduler_config={"scheduler": args.scheduler},
    )

    print("\nRunning tasks…")
    bundle = runner.run()

    signer = StubSigner() if args.stub_signer else AgentCardSigner()
    bundle = signer.sign(bundle)

    out_path = Path(args.out)
    bundle.save(out_path)

    print(f"\nScore       : {bundle.overall_score * 100:.1f}%")
    print(f"Pass rate   : {bundle.pass_rate * 100:.1f}%")
    print(f"Bundle hash : {bundle.bundle_hash()}")
    print(f"Signed by   : {bundle.signer_fingerprint or '(unsigned)'}")
    print(f"\nBundle written to: {out_path}")
    return 0


# ---------------------------------------------------------------------------
# bernstein bench verify
# ---------------------------------------------------------------------------

def cmd_verify(argv: list[str] | None = None) -> int:
    """
    Verify a submission bundle by replaying every task receipt offline.

    Usage: bernstein bench verify <bundle> [--suite <name>]
    """
    parser = argparse.ArgumentParser(
        prog="bernstein bench verify",
        description=(
            "Verify a bernstein-bench submission bundle by replaying "
            "every task receipt offline."
        ),
    )
    parser.add_argument(
        "bundle",
        help="Path to the submission bundle .json file.",
    )
    parser.add_argument(
        "--suite",
        default="golden-v1",
        help='Suite to verify against (default: "golden-v1").',
    )
    args = parser.parse_args(argv)

    from bernstein.eval.bench.bundle import SubmissionBundle
    from bernstein.eval.bench.runner import MockReplayAdapter
    from bernstein.eval.bench.verifier import BenchVerifier, VerificationStatus

    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        print(f"Error: bundle file not found: {bundle_path}", file=sys.stderr)
        return 1

    bundle = SubmissionBundle.load(bundle_path)
    suite = _get_suite(args.suite)

    # Production: swap MockReplayAdapter for the real scenario_runner adapter.
    adapter = MockReplayAdapter()
    verifier = BenchVerifier(suite=suite, adapter=adapter)
    result = verifier.verify(bundle)

    print(result.report())
    return 0 if result.passed else 1


# ---------------------------------------------------------------------------
# Unified dispatcher: bernstein bench <subcommand>
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """
    Top-level dispatcher for ``bernstein bench``.

    Registered as: bernstein-bench = "bernstein.eval.bench.bench_cli:main"
    """
    parser = argparse.ArgumentParser(
        prog="bernstein bench",
        description="bernstein-bench: runnable, reproducibility-gated evaluation harness.",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="Run a suite and emit a signed bundle.")
    sub.add_parser("verify", help="Verify a bundle by replaying its receipts.")

    # Parse only the subcommand name; pass the rest to the subcommand parser.
    args, remaining = parser.parse_known_args(argv)

    if args.command == "run":
        return cmd_run(remaining)
    elif args.command == "verify":
        return cmd_verify(remaining)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
