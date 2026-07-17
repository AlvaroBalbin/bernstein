---
title: Operations
description: Running Bernstein in production - deployment, day-to-day supervision, reliability, cost, and compliance.
search:
  boost: 2
---

# Operations

The operator surface: deploying Bernstein, running it day to day, and
keeping it healthy, cheap, secure, and auditable.

- **Deploy and scale** - Docker Compose, Helm, cluster mode, fleet, air-gap installs. [Deployment guide](deployment-guide.md).
- **Run and supervise** - Run, schedule, resume, replay, fork, and review agent work. [Commands overview](commands.md).
- **Reliability** - Troubleshooting, retries, auto-heal, stall escalation, disaster recovery. [Troubleshooting](TROUBLESHOOTING.md).
- **Cost and performance** - Budgets, cost-aware scheduling, performance tuning. [Cost optimization](cost-optimization.md).
- **Observability** - Instrumentation, deterministic replay, telemetry, trends. [Observability overview](observability-overview.md).
- **Merge and review automation** - Merge queue, autofix daemon, review responder, coverage ratchet. [Merge queue](merge-queue.md).
- **Evaluation and calibration** - Incident-to-eval synthesis, A/B runner, calibration. [Incident-to-eval synthesis](../eval/incident-synthesis.md).
- **Security and identity** - Credential scoping, secrets, hardening, capability matrix. [Security and identity stack](security-and-identity.md).
- **Compliance and audit** - EU AI Act, SOC 2, audit log, lineage export. [Compliance overview](compliance.md).
