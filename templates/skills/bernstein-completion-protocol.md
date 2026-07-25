---
name: bernstein-completion-protocol
description: Report task completion to the Bernstein orchestrator
whenToUse: When you have finished all assigned tasks and are ready to report completion
---

Mark each task complete using the Bernstein CLI - it resolves the task-server
URL and your session's auth token for you, and retries automatically if the
server is mid-restart:

{{COMPLETE_CMDS}}

Then commit your changes and exit:

```bash
git add -A && git commit -m "feat: <brief summary of what you did>"
exit 0
```
