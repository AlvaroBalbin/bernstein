"""Regression tests for #3017: agent worktrees must locally exclude the
merge guard's full deny list -- plus the orchestrator's own generated
``CLAUDE.md`` -- at creation time.

Bernstein orchestrates agents against arbitrary target repositories, most of
which have no idea ``.sdd/``, ``attestations/``, ``auth/``,
``bernstein.yaml``, ``.env``, or ``.claude/mcp.json`` are orchestrator-owned
runtime/control state. An agent following its own "finish with ``git add -A
&& git commit``" instruction would otherwise stage all of it -- and the
reap-and-merge preflight's forbidden-path guard then refuses the *entire*
commit, diverting real work to the graveyard instead of merging it.

The exclude list is derived directly from the merge guard's own deny list
(``bernstein.core.git.git_pr._MERGE_DENY_PREFIXES`` /
``_MERGE_DENY_EXACT``) so the two can never drift apart, plus ``/CLAUDE.md``
added on top: the orchestrator generates a session-specific ``CLAUDE.md`` at
the root of *every* worktree (``worktree_claude_md.write_claude_md``), so
that exact path is always a duplicate/decoy file, never a genuine
target-repo deliverable.

The exclude rules live in ``.git/info/exclude`` -- local-only, never
staged, committed, or visible in the target repo's history -- rather than a
tracked ``.gitignore``. That is what makes it safe to cover ``CLAUDE.md``
and the guard's full deny list unconditionally: nothing here is imposed on
the target repo, so there is no "our rules vs. their rules" conflict and no
diff shows up in the agent's own commit. A *non-runtime* file elsewhere
under ``.claude/`` (a skill or command the agent was actually tasked to
add) is deliberately left alone.

These tests run against a real git repository (not mocks) so ``git add -A``,
``git status``, and the merge-preflight guard reflect true on-disk/index
behaviour.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from bernstein.core.models import Scope, Task

import bernstein.core.git.git_pr as git_pr
from bernstein.core.git.worktree import WorktreeManager
from bernstein.core.git.worktree_claude_md import write_claude_md


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _git_common_dir(worktree_path: Path) -> Path:
    """Resolve the shared git dir the same way the implementation does."""
    out = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=worktree_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return Path(out)


def _local_exclude_lines(worktree_path: Path) -> set[str]:
    exclude_path = _git_common_dir(worktree_path) / "info" / "exclude"
    if not exclude_path.exists():
        return set()
    return {line.strip() for line in exclude_path.read_text(encoding="utf-8").splitlines()}


def _staged(worktree_path: Path) -> list[str]:
    return [
        line.strip() for line in _git(worktree_path, "diff", "--cached", "--name-only").splitlines() if line.strip()
    ]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A plain target repository with no bernstein-aware ignore rules.

    This mirrors the real-world case: bernstein spawns agents into arbitrary
    client repos that have never heard of ``.sdd/``, ``attestations/``,
    ``auth/``, or ``.claude/``.
    """
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")
    (root / "README.md").write_text("# repo\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-q", "-m", "initial")
    return root


def _drop_full_deny_list_runtime_state(worktree_path: Path, session_id: str) -> None:
    """Write one artefact per entry in the merge guard's deny list
    (``.sdd/``, ``attestations/``, ``auth/``, ``bernstein.yaml``, ``.env``,
    ``.claude/mcp.json``), mirroring the real e2e evidence in #3017 plus the
    other deny-listed prefixes the original fix missed."""
    runtime_dir = worktree_path / ".sdd" / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    (runtime_dir / f"{session_id}.log").write_text("agent log line\n", encoding="utf-8")

    attestations_dir = worktree_path / "attestations"
    attestations_dir.mkdir(parents=True, exist_ok=True)
    (attestations_dir / "ed25519-signing-key.pem").write_text("KEY\n", encoding="utf-8")

    auth_dir = worktree_path / "auth"
    auth_dir.mkdir(parents=True, exist_ok=True)
    (auth_dir / "agent_identity_jwt_secret").write_text("SECRET\n", encoding="utf-8")

    (worktree_path / "bernstein.yaml").write_text("token: x\n", encoding="utf-8")
    (worktree_path / ".env").write_text("SECRET=1\n", encoding="utf-8")

    claude_dir = worktree_path / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "mcp.json").write_text("{}\n", encoding="utf-8")


def _make_task() -> Task:
    return Task(
        id="T-001",
        title="Implement feature",
        description="Write the code.",
        role="backend",
        scope=Scope.MEDIUM,
        priority=2,
        owned_files=[],
    )


def test_create_writes_local_excludes_not_a_tracked_gitignore(tmp_path: Path, repo: Path) -> None:
    """``WorktreeManager.create`` must inject the full deny-list-derived
    exclude set into ``.git/info/exclude`` (local-only) -- and must NOT
    create or modify a tracked ``.gitignore`` in the worktree's working
    tree, since that would itself be staged and committed into the target
    repo."""
    mgr = WorktreeManager(repo_root=repo)

    worktree_path = mgr.create("sess-excludes")

    # No tracked .gitignore was created -- the target repo had none, and
    # this fix must never introduce one.
    assert not (worktree_path / ".gitignore").exists()

    lines = _local_exclude_lines(worktree_path)
    assert "/.sdd/" in lines
    assert "/attestations/" in lines
    assert "/auth/" in lines
    assert "/bernstein.yaml" in lines
    assert "/.env" in lines
    assert "/.claude/mcp.json" in lines
    assert "/CLAUDE.md" in lines

    # Must not blanket-ignore the whole .claude/ tree -- that would drop a
    # legitimate .claude/ deliverable (e.g. a skill or command).
    assert ".claude/" not in lines
    assert "/.claude/" not in lines


def test_create_leaves_target_repo_tracked_tree_unchanged(tmp_path: Path, repo: Path) -> None:
    """The whole point of using ``.git/info/exclude`` instead of a tracked
    ``.gitignore``: worktree creation must not stage, modify, or introduce
    any file in the target repo's working tree / index. ``git status`` right
    after ``create()`` must be completely clean."""
    mgr = WorktreeManager(repo_root=repo)

    worktree_path = mgr.create("sess-clean-tree")

    status = _git(worktree_path, "status", "--porcelain")
    assert status == "", f"worktree creation must leave the tracked tree untouched, got: {status!r}"


def test_git_add_dash_a_does_not_stage_full_deny_list_paths(tmp_path: Path, repo: Path) -> None:
    """The actual bug, now covering the guard's *full* deny list: an agent
    running ``git add -A`` in its worktree must never stage ``.sdd/*``,
    ``attestations/*``, ``auth/*``, ``bernstein.yaml``, ``.env``, or
    ``.claude/mcp.json`` -- only its real work."""
    mgr = WorktreeManager(repo_root=repo)
    session_id = "sess-add-a"
    worktree_path = mgr.create(session_id)

    # The agent's actual deliverable.
    src_dir = worktree_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "feature.py").write_text("def feature():\n    return 42\n", encoding="utf-8")

    _drop_full_deny_list_runtime_state(worktree_path, session_id)

    _git(worktree_path, "add", "-A")
    staged = _staged(worktree_path)

    denied_staged = [p for p in staged if git_pr._is_forbidden_for_merge(p)]
    assert denied_staged == [], f"deny-listed paths must never be staged, got: {denied_staged}"
    assert "src/feature.py" in staged, "the agent's real work must still be staged"


def test_generated_session_claude_md_is_not_staged(tmp_path: Path, repo: Path) -> None:
    """Regression for the blocker this review caught: the orchestrator
    itself generates a session ``CLAUDE.md`` at the worktree root via
    ``write_claude_md`` (real header: "This file was auto-generated by
    Bernstein for this agent session."). That file must never be staged by
    ``git add -A`` -- it is never a target-repo deliverable, it's always
    bernstein's own control file at that exact path."""
    mgr = WorktreeManager(repo_root=repo)
    session_id = "sess-claude-md"
    worktree_path = mgr.create(session_id)

    # Exercise the real production code path, not a hand-rolled stand-in.
    write_claude_md(
        worktree_path,
        [_make_task()],
        session_id=session_id,
        role="backend",
        workdir=repo,
    )
    generated = (worktree_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert "auto-generated by Bernstein" in generated

    src_dir = worktree_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "feature.py").write_text("def feature():\n    return 42\n", encoding="utf-8")

    _git(worktree_path, "add", "-A")
    staged = _staged(worktree_path)

    assert "CLAUDE.md" not in staged, "the orchestrator-generated session CLAUDE.md must not be staged"
    assert "src/feature.py" in staged


def test_git_add_dash_a_still_stages_non_runtime_claude_dir_deliverable(tmp_path: Path, repo: Path) -> None:
    """A non-runtime file elsewhere under ``.claude/`` (a skill or command
    the agent was actually tasked to add) must still be staged -- only
    ``.claude/mcp.json`` specifically is excluded."""
    mgr = WorktreeManager(repo_root=repo)
    session_id = "sess-claude-dir-deliverable"
    worktree_path = mgr.create(session_id)

    _drop_full_deny_list_runtime_state(worktree_path, session_id)

    commands_dir = worktree_path / ".claude" / "commands"
    commands_dir.mkdir(parents=True, exist_ok=True)
    (commands_dir / "deploy.md").write_text("# /deploy command\n", encoding="utf-8")

    _git(worktree_path, "add", "-A")
    staged = _staged(worktree_path)

    assert ".claude/commands/deploy.md" in staged, "a .claude/ deliverable must not be silently dropped"
    assert ".claude/mcp.json" not in staged


def test_normal_work_commit_passes_merge_preflight_forbidden_path_guard(tmp_path: Path, repo: Path) -> None:
    """End-to-end regression for #3017: with the full deny-list of runtime
    state on disk but correctly excluded, the staged set that reaches the
    reap-and-merge preflight's forbidden-path guard (defect 28) must be
    clean -- the guard must not refuse a legitimately-finishing agent's
    commit."""
    mgr = WorktreeManager(repo_root=repo)
    session_id = "sess-preflight"
    worktree_path = mgr.create(session_id)

    src_dir = worktree_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "feature.py").write_text("def feature():\n    return 42\n", encoding="utf-8")

    _drop_full_deny_list_runtime_state(worktree_path, session_id)

    _git(worktree_path, "add", "-A")

    # This is the exact guard invoked by the reap-and-merge preflight
    # (bernstein.core.git.git_pr._verify_merge_staging_is_safe) against the
    # staged set. Empty list == safe to commit/merge.
    forbidden = git_pr._verify_merge_staging_is_safe(worktree_path, f"agent/{session_id}")
    assert forbidden == [], f"merge-preflight forbidden-path guard must not trip on runtime paths, got: {forbidden}"
