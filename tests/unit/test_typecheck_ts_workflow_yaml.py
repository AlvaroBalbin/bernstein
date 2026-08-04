"""``typecheck-ts.yml`` must actually cover the packages it claims to.

The workflow is a gate whose scope is declared in two independent places
that nothing forces to agree:

*The trigger.* ``on.pull_request.paths`` decides whether the workflow
runs at all. A TypeScript package outside that list gets no job, so a
pull request touching only that package reports zero TypeScript checks -
green, because nothing ran.

*The matrix.* ``strategy.matrix.include`` decides which packages the
workflow that did run typechecks. A package inside the trigger but
outside the matrix is worse than uncovered: the workflow reports success
having never compiled it.

Both are silent by construction, so both are asserted here against the
repository tree rather than against a restated list. A ``package.json``
that declares ``typescript`` is a package whose types CI can break and
whose dependency bumps automation will open pull requests for; from then
on this file requires it in the trigger and in the matrix, and the change
that adds the manifest is the one that has to wire up CI.

The install step is asserted for the same reason. ``npm ci`` aborts when
the package has no lockfile, which turns a newly covered package into a
job that dies before ``tsc`` runs.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - dev env should have pyyaml
    pytest.skip("pyyaml not installed", allow_module_level=True)

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = Path(".github/workflows/typecheck-ts.yml")

# Packages that depend on TypeScript as a build tool but ship no sources
# for ``tsc`` to compile. Each is held to that claim by
# ``test_exempt_packages_still_have_nothing_to_compile`` - the exemption
# lapses the moment the package grows a source tree.
NO_SOURCES_TO_COMPILE = {
    "packages/vscode/webview-ui": (
        "scaffold: the only TypeScript file is vite.config.ts, there is no src/, and .vscodeignore keeps the "
        "directory out of the packaged extension"
    ),
}


def _tracked(*patterns: str) -> list[str]:
    """Tracked paths matching ``patterns``, as the CI checkout sees them.

    Committed state, not working-tree state: a local ``npm install``
    leaves an untracked ``package-lock.json`` and a build leaves a
    ``node_modules`` full of third-party manifests, either of which would
    otherwise flip this file's verdict on a developer machine while CI -
    which checks out only what is committed - kept the opposite one.
    """
    proc = subprocess.run(
        ["git", "ls-files", "-z", "--", *patterns],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:  # pragma: no cover - source export without .git
        pytest.skip("not a git checkout")
    return [p for p in proc.stdout.split("\0") if p]


def _load_yaml(path: Path) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{path} is not a mapping"
    return doc


def _on(doc: dict[str, Any]) -> dict[str, Any]:
    # PyYAML 1.1 parses a bare ``on:`` key as the boolean True.
    on = doc.get(True, doc.get("on"))
    assert isinstance(on, dict), "workflow must declare a mapping of triggers"
    return on


@pytest.fixture(scope="module")
def doc() -> dict[str, Any]:
    return _load_yaml(REPO / WORKFLOW)


@pytest.fixture(scope="module")
def matrix_entries(doc: dict[str, Any]) -> list[dict[str, Any]]:
    jobs = doc.get("jobs")
    assert isinstance(jobs, dict)
    job = jobs.get("typecheck")
    assert isinstance(job, dict), "typecheck-ts.yml must keep its `typecheck` job"
    include = (job.get("strategy") or {}).get("matrix", {}).get("include")
    assert isinstance(include, list) and include, "the `typecheck` job must declare a matrix of packages"
    return include


@pytest.fixture(scope="module")
def typescript_packages() -> list[str]:
    """Every package in the tree that declares a ``typescript`` dependency.

    Read off the checkout so a TypeScript package cannot be added, or
    vendored in under ``templates/``, without this file noticing it.
    """
    found: list[str] = []
    for rel in _tracked("*package.json"):
        pkg = json.loads((REPO / rel).read_text(encoding="utf-8"))
        declared = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
        if "typescript" in declared:
            found.append(Path(rel).parent.as_posix())
    assert found, "no package declares typescript; the discovery walk is broken, not the workflow"
    return sorted(found)


@pytest.fixture(scope="module")
def committed_lockfiles() -> frozenset[str]:
    return frozenset(_tracked("*package-lock.json"))


def _covers(pattern: str, package: str) -> bool:
    """Does a ``paths`` glob select everything under ``package``?"""
    prefix = pattern.removesuffix("/**").removesuffix("/*")
    return package == prefix or package.startswith(f"{prefix}/")


def test_pull_request_and_push_filters_agree(doc: dict[str, Any]) -> None:
    """The two triggers must select the same diffs.

    They are maintained as two literal lists. Extending one and not the
    other yields a gate that runs on the pull request but not on the
    merge to ``main`` (or the reverse), so a package can be covered
    pre-merge and unguarded post-merge without anything reporting red.
    """
    on = _on(doc)
    pr_paths = (on.get("pull_request") or {}).get("paths")
    push_paths = (on.get("push") or {}).get("paths")
    assert pr_paths and push_paths, "both triggers must declare a `paths` filter"
    assert sorted(pr_paths) == sorted(push_paths), (
        f"`pull_request.paths` and `push.paths` have drifted: only on pull_request "
        f"{sorted(set(pr_paths) - set(push_paths))}, only on push {sorted(set(push_paths) - set(pr_paths))}. A "
        "package listed in one filter and not the other is gated on one event and unguarded on the other."
    )


def test_every_typescript_package_is_in_the_matrix(
    matrix_entries: list[dict[str, Any]],
    typescript_packages: list[str],
) -> None:
    """A package that depends on TypeScript must be a matrix cell.

    Missing here is the worse of the two gaps: the workflow runs,
    publishes a green ``typecheck (...)`` for its other cells, and never
    compiles this package at all. It is also the shape a dependency-bump
    pull request arrives in - the manifest changes, no cell owns it, and
    the merge is green on checks that never read the package.
    """
    covered = {str(entry.get("package")) for entry in matrix_entries}
    missing = [pkg for pkg in typescript_packages if pkg not in covered | set(NO_SOURCES_TO_COMPILE)]
    assert not missing, (
        f"{missing} declare a typescript dependency but are not matrix entries in {WORKFLOW}, so their types are "
        f"never compiled by CI. Matrix covers: {sorted(covered)}."
    )


def test_exempt_packages_still_have_nothing_to_compile(typescript_packages: list[str]) -> None:
    """An exemption survives only while the package really is source-free.

    ``NO_SOURCES_TO_COMPILE`` records packages that pull TypeScript in as
    a build tool. That is a claim about the tree, and a source file added
    later silently converts the exemption into the same uncovered-package
    gap it was written to be distinguishable from.
    """
    stale = sorted(set(NO_SOURCES_TO_COMPILE) - set(typescript_packages))
    assert not stale, f"{stale} no longer declare typescript; drop them from NO_SOURCES_TO_COMPILE."

    grown = {
        package: sources
        for package in NO_SOURCES_TO_COMPILE
        if (sources := _tracked(f"{package}/src/*.ts", f"{package}/src/*.tsx"))
    }
    assert not grown, (
        f"{sorted(grown)} are exempt from the typecheck matrix on the grounds that they have no sources, but now "
        f"ship some: {grown}. Add them to the matrix and drop the exemption."
    )


def test_every_matrix_package_is_inside_the_trigger(
    doc: dict[str, Any],
    matrix_entries: list[dict[str, Any]],
) -> None:
    """A matrix cell whose sources are outside ``paths`` never runs.

    The cell reads as coverage in the workflow file, and a diff confined
    to that package starts no run, so the pull request carries no
    TypeScript check at all rather than a failing one.
    """
    patterns = (_on(doc).get("pull_request") or {}).get("paths") or []
    packages = [str(entry.get("package")) for entry in matrix_entries]
    uncovered = [pkg for pkg in packages if not any(_covers(str(p), pkg) for p in patterns)]
    assert not uncovered, (
        f"{uncovered} are matrix entries but no `paths` pattern selects them, so a diff touching only those "
        f"packages starts no run. Patterns: {patterns}."
    )


def test_workflow_retriggers_on_its_own_edits(doc: dict[str, Any]) -> None:
    """Edits to the matrix must be typechecked by the matrix they edit.

    Without a self-reference in ``paths``, a pull request that adds a
    package to the matrix runs nothing, and the first execution of the
    new cell happens on ``main``.
    """
    patterns = (_on(doc).get("pull_request") or {}).get("paths") or []
    assert WORKFLOW.as_posix() in patterns, (
        f"`paths` must list {WORKFLOW.as_posix()} so a change to the matrix is exercised on the pull request that "
        f"makes it. Patterns: {patterns}."
    )


def test_install_command_matches_lockfile_presence(
    matrix_entries: list[dict[str, Any]],
    committed_lockfiles: frozenset[str],
) -> None:
    """``npm ci`` is only usable where a lockfile is committed.

    It exits non-zero rather than resolving the manifest, so a matrix
    cell for a package without ``package-lock.json`` fails on install and
    never reaches ``tsc``. Each cell therefore carries its own install
    command, and this asserts the pairing that makes it work.
    """
    for entry in matrix_entries:
        package = str(entry.get("package"))
        install = str(entry.get("install", "")).strip()
        assert install, f"matrix entry `{package}` must declare an `install` command"
        if f"{package}/package-lock.json" in committed_lockfiles:
            assert install.startswith("npm ci"), (
                f"`{package}` commits a package-lock.json, so its install must be `npm ci` for a reproducible "
                f"tree, not {install!r}."
            )
        else:
            assert not install.startswith("npm ci"), (
                f"`{package}` has no package-lock.json, so `npm ci` aborts before `tsc` ever runs. Use "
                "`npm install` for this cell, or commit a lockfile."
            )
