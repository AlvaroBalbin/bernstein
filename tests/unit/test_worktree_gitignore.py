"""Regression tests for #3017: agent worktrees must gitignore ``.sdd/``,
``.claude/``, and ``CLAUDE.md`` at creation time.

Bernstein orchestrates agents against arbitrary target repositories, most of
which have no idea these paths are bernstein-internal runtime/agent-control
state. An agent following its own "finish with ``git add -A && git commit``"
instruction therefore stages ``.sdd/runtime/*`` logs, heartbeats,
``.sdd/skills/activations.jsonl``, ``.claude/*`` config, and ``CLAUDE.md`` --
and the reap-and-merge preflight's forbidden-path guard then refuses the
*entire* commit, diverting real work to the graveyard instead of merging it.

These tests run against a real git repository (not mocks) so ``git add -A``
and the merge-preflight guard reflect true on-disk/index behaviour.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import bernstein.core.git.git_pr as git_pr
from bernstein.core.git.worktree import WorktreeManager


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A plain target repository with no bernstein-aware ``.gitignore``.

    This mirrors the real-world case: bernstein spawns agents into arbitrary
    client repos that have never heard of ``.sdd/`` or ``.claude/``.
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


def _drop_runtime_state(worktree_path: Path, session_id: str) -> None:
    """Write the exact kind of runtime/control files a live agent session
    leaves behind, per the real e2e evidence in #3017."""
    runtime_dir = worktree_path / ".sdd" / "runtime"
    (runtime_dir / "heartbeats").mkdir(parents=True, exist_ok=True)
    (runtime_dir / f"{session_id}.log").write_text("agent log line\n", encoding="utf-8")
    (runtime_dir / "heartbeats" / session_id).write_text("hb\n", encoding="utf-8")

    skills_dir = worktree_path / ".sdd" / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)
    (skills_dir / "activations.jsonl").write_text('{"skill": "x"}\n', encoding="utf-8")

    claude_dir = worktree_path / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    (claude_dir / "scheduled_tasks.json").write_text("{}\n", encoding="utf-8")

    (worktree_path / "CLAUDE.md").write_text("# task-specific instructions\n", encoding="utf-8")


def test_create_injects_gitignore_for_agent_control_state(tmp_path: Path, repo: Path) -> None:
    """``WorktreeManager.create`` must write/augment a root ``.gitignore``
    in the new worktree that excludes ``.sdd/``, ``.claude/``, and
    ``CLAUDE.md`` -- even though the target repo's own tracked
    ``.gitignore`` (none, here) knows nothing about them."""
    mgr = WorktreeManager(repo_root=repo)

    worktree_path = mgr.create("sess-gitignore")

    gitignore_path = worktree_path / ".gitignore"
    assert gitignore_path.exists(), "worktree must have a .gitignore after create()"
    content = gitignore_path.read_text(encoding="utf-8")
    assert ".sdd/" in content
    assert ".claude/" in content
    assert "CLAUDE.md" in content


def test_git_add_dash_a_does_not_stage_runtime_or_control_paths(tmp_path: Path, repo: Path) -> None:
    """The actual bug: an agent running ``git add -A`` in its worktree must
    never stage ``.sdd/*``, ``.claude/*``, or ``CLAUDE.md`` -- only its real
    work."""
    mgr = WorktreeManager(repo_root=repo)
    session_id = "sess-add-a"
    worktree_path = mgr.create(session_id)

    # The agent's actual deliverable.
    src_dir = worktree_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "feature.py").write_text("def feature():\n    return 42\n", encoding="utf-8")

    _drop_runtime_state(worktree_path, session_id)

    _git(worktree_path, "add", "-A")
    staged = [
        line.strip() for line in _git(worktree_path, "diff", "--cached", "--name-only").splitlines() if line.strip()
    ]

    forbidden_staged = [p for p in staged if p.startswith(".sdd/") or p.startswith(".claude/") or p == "CLAUDE.md"]
    assert forbidden_staged == [], f"runtime/control paths must never be staged, got: {forbidden_staged}"
    assert "src/feature.py" in staged, "the agent's real work must still be staged"


def test_normal_work_commit_passes_merge_preflight_forbidden_path_guard(tmp_path: Path, repo: Path) -> None:
    """End-to-end regression for #3017: with runtime state on disk but
    correctly gitignored, the staged set that reaches the reap-and-merge
    preflight's forbidden-path guard (defect 28) must be clean -- the guard
    must not refuse a legitimately-finishing agent's commit."""
    mgr = WorktreeManager(repo_root=repo)
    session_id = "sess-preflight"
    worktree_path = mgr.create(session_id)

    src_dir = worktree_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "feature.py").write_text("def feature():\n    return 42\n", encoding="utf-8")

    _drop_runtime_state(worktree_path, session_id)

    _git(worktree_path, "add", "-A")

    # This is the exact guard invoked by the reap-and-merge preflight
    # (bernstein.core.git.git_pr._verify_merge_staging_is_safe) against the
    # staged set. Empty list == safe to commit/merge.
    forbidden = git_pr._verify_merge_staging_is_safe(worktree_path, f"agent/{session_id}")
    assert forbidden == [], f"merge-preflight forbidden-path guard must not trip on runtime paths, got: {forbidden}"
