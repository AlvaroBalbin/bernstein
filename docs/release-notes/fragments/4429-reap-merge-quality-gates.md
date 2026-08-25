## Quality gates run before an agent branch is merged

Reap-and-merge landed an agent's branch without running the configured
quality gates, so a run could merge work the gates would have blocked. They
now run on the still-alive worktree before the merge commit: a blocking
failure, or a gate runner that errors, leaves the branch unmerged and records
the refusal (#4393).
