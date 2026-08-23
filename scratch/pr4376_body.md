Fixes #4376

### Problem
When a dependency fails, dependent tasks are transitioned to `BLOCKED_BY_FAILED_DEP`. If the failed dependency is subsequently retried or completes successfully, downstream tasks were stranded in `BLOCKED_BY_FAILED_DEP` forever and never recovered.

### Changes
1. Added `_unblock_task` and `_cascade_unblock_dependency` in `src/bernstein/core/tasks/task_store_core.py` to recursively inspect and unblock dependent tasks back to `OPEN` when a dependency succeeds or is retried.
2. Updated `blocking_dependency` in `src/bernstein/core/tasks/unreachable.py` so retrying or succeeded tasks are not treated as blocking failures.
3. Added `tests/unit/core/tasks/test_dependency_unblock_cascade.py` (3 unit tests covering direct recovery, transitive cascade, and multi-dependency satisfaction).
