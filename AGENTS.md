# Hermes Security Workbench — Agent Contract

## Scope
Work only in this plugin repository. Read the local Hermes source/docs when needed to verify plugin API conventions, but do not modify Hermes core or other plugins. This phase is reporting/export only.

## Safety
Do not run active scans, call external security APIs, use API keys, or contact arbitrary targets. Use temporary `WORKBENCH_DIR` paths for tests. Preserve the existing scope gate and soft-delete semantics. Never touch the live `~/.hermes/hermes-security-workbench/workbench.db`.

## Required command
Run from `dashboard/`:

```bash
WORKBENCH_DIR=$(mktemp -d) python3 -m pytest tests/test_workbench.py -q
```

Add behavior tests for every report endpoint and content contract. A function import alone is insufficient.

## Current Phase 3 job
See `WORKFLOW-PHASE3-REPORTING.md`. Commit scoped changes; do not push.
