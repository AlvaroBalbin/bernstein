#!/usr/bin/env python3
"""Fail when ``docs/requirements.txt`` pins a version its ``.in`` file forbids.

Why this exists
---------------
``docs/requirements.in`` is a source of truth that nothing checked the
output against. A compiled artifact could therefore drift from its own
constraints and stay that way until a human read both files side by side,
which is exactly how #3995 surfaced - during review of an unrelated bump,
months after the fact.

The concrete drift: ``docs/requirements.in`` caps ``mkdocs-redirects``
below 1.2.3 with the reason written inline (that release adds a runtime
dependency on a third-party fork of mkdocs 1.x, and we build against
upstream only), while ``docs/requirements.txt`` pinned exactly 1.2.3. The
cap was not advisory - it named a concrete reason - and the compiled file
walked straight past it with nothing to notice.

Every other generated pair in this repo has a gate that regenerates and
fails on a difference (``agents-md verify``, ``readme-l10n verify``,
``scripts/gen_workflow_topology.py``'s output test). The docs pins had no
equivalent. This is it.

What this checks, and what it deliberately does not
---------------------------------------------------
This verifies the committed pins **offline**, against the constraints
declared in the ``.in`` file. It does not recompile.

Checked:
  * every directly-declared requirement resolves to a pin in the ``.txt``
  * every such pin satisfies its declared specifier

NOT checked: whether a fresh resolve would move a *transitive* pin. That
is a staleness question, and answering it means reaching PyPI at gate
time. A gate that can go red because an index hiccuped cannot be a
blocking gate, and a non-blocking gate is the failure mode this script
exists to remove - it becomes another green tick that proves nothing. The
narrower claim is the one worth blocking on.

The distinction that matters: a violated direct cap is a *policy*
failure. Somebody wrote down why a bound exists and the artifact ignored
it. A stale transitive pin is not that, and is better served by a
scheduled job asking "are our pins old" than by a per-PR gate asking
"is this diff correct".

Note for whoever later adds the recompile half: the regeneration command
documented in ``docs/requirements.in`` used to omit ``--strip-extras``,
which the header of ``docs/requirements.txt`` records as having been used,
so a recompile-and-diff gate built on the documented command would have
failed against a correct tree. That header is corrected here and is held
to ``REGEN_COMMAND`` below by a test, so the documented command is now
safe to build on - but check that test still exists before trusting it.

Usage:
    python scripts/check_docs_requirements_pins.py
    python scripts/check_docs_requirements_pins.py --in-file X --txt-file Y

Exit codes:
    0  every direct requirement is present and within its specifier
    1  at least one violation (each named on stdout)
    2  a file could not be read or parsed
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

# The command that regenerates the compiled file. Printed on failure: a drift
# report that says only "files differ" costs the next person a bisect.
REGEN_COMMAND = (
    "uv run --python 3.13 --with pip-tools -- "
    "pip-compile --generate-hashes --strip-extras "
    "--output-file docs/requirements.txt docs/requirements.in"
)

# A pinned line in a --generate-hashes output, e.g. ``babel==2.18.0 \``.
# Hash continuations are indented and never match, which is the point.
_PIN_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s\\;]+)")

# Lines in a .in file that declare something other than a requirement.
_OPTION_PREFIXES = ("-r", "-c", "-e", "--", "-i", "-f")


@dataclass(frozen=True)
class Violation:
    """One requirement whose pin disagrees with its declared constraint."""

    name: str
    specifier: str
    found: str | None

    def render(self) -> str:
        if self.found is None:
            return f"  {self.name}: declared as `{self.name}{self.specifier}` but no pin was found in the compiled file"
        return f"  {self.name}: declared as `{self.name}{self.specifier}` but the compiled file pins {self.found}"


def parse_in_file(text: str) -> list[Requirement]:
    """Direct requirements declared in a pip-compile ``.in`` source."""
    requirements: list[Requirement] = []
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#") or line.startswith(_OPTION_PREFIXES):
            continue
        try:
            requirements.append(Requirement(line))
        except InvalidRequirement as exc:
            raise ValueError(f"cannot parse requirement {line!r}: {exc}") from exc
    return requirements


def parse_pins(text: str) -> dict[str, str]:
    """Canonical package name -> pinned version, from a compiled ``.txt``."""
    pins: dict[str, str] = {}
    for raw in text.splitlines():
        # Only column-0 lines declare a pin; hash continuations are indented.
        if not raw or raw[0].isspace() or raw.lstrip().startswith("#"):
            continue
        match = _PIN_RE.match(raw.strip())
        if match is None:
            continue
        pins[canonicalize_name(match.group("name"))] = match.group("version")
    return pins


def find_violations(requirements: list[Requirement], pins: dict[str, str]) -> list[Violation]:
    """Direct requirements that are missing from, or contradicted by, the pins."""
    violations: list[Violation] = []
    for requirement in requirements:
        # Extras are stripped by --strip-extras, so match on the base name.
        name = canonicalize_name(requirement.name)
        found = pins.get(name)
        if found is None:
            # A marker can legitimately exclude a requirement from the
            # resolution (a Python-version guard, say). Absence is only a
            # finding when the requirement applies unconditionally.
            if requirement.marker is not None:
                continue
            violations.append(Violation(requirement.name, str(requirement.specifier), None))
            continue
        try:
            version = Version(found)
        except InvalidVersion:
            violations.append(Violation(requirement.name, str(requirement.specifier), found))
            continue
        # prereleases=True so an explicitly pinned prerelease is judged against
        # the specifier rather than silently skipped as unsatisfiable.
        if not requirement.specifier.contains(version, prereleases=True):
            violations.append(Violation(requirement.name, str(requirement.specifier), found))
    return violations


def check(in_path: Path, txt_path: Path) -> int:
    """Report drift between a ``.in`` source and its compiled ``.txt``."""
    try:
        in_text = in_path.read_text(encoding="utf-8")
        txt_text = txt_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        requirements = parse_in_file(in_text)
    except ValueError as exc:
        print(f"error: {in_path}: {exc}", file=sys.stderr)
        return 2

    pins = parse_pins(txt_text)
    if not pins:
        print(f"error: {txt_path}: no pinned requirements found", file=sys.stderr)
        return 2

    violations = find_violations(requirements, pins)
    if not violations:
        print(f"OK       {len(requirements)} direct requirement(s) within their declared bounds")
        return 0

    plural = "s" if len(violations) > 1 else ""
    print(f"DRIFT    {txt_path} contradicts {in_path} ({len(violations)} package{plural}):")
    for violation in violations:
        print(violation.render())
    print()
    print("The .in file is the source of truth. Regenerate the compiled file with:")
    print(f"    {REGEN_COMMAND}")
    print()
    print("If the constraint itself is wrong, change it in the .in file (with the")
    print("reason inline, as the existing caps do) and regenerate - do not edit the")
    print("compiled file by hand, which is how this drift happened.")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    repo_root = Path(__file__).resolve().parent.parent
    parser.add_argument("--in-file", type=Path, default=repo_root / "docs" / "requirements.in")
    parser.add_argument("--txt-file", type=Path, default=repo_root / "docs" / "requirements.txt")
    args = parser.parse_args(argv)
    return check(args.in_file, args.txt_file)


if __name__ == "__main__":
    raise SystemExit(main())
