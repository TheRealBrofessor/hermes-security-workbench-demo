# Codex Task — Security Workbench Phase 3 Reporting

## Goal
Turn the existing `dashboard/reporting.py` helpers into a usable, safe report/export surface in the Hermes plugin.

## Required implementation
1. Inspect this plugin plus the local Hermes plugin/dashboard contract under `/home/professor/.hermes/hermes-agent`; determine the smallest compatible surface. Do not invent or modify core APIs.
2. Add report/export API endpoints for JSON, CSV, and Markdown, supporting optional `case_id`. Return correct media types and safe `Content-Disposition` filenames where downloads are appropriate.
3. Reject an unknown/archived case rather than silently returning an empty report. Exports must exclude soft-deleted cases/jobs/findings and never expose log paths or credentials.
4. Add a useful report summary contract (case/job/finding counts and status/severity breakdowns) for the UI. If the documented local plugin contract supports plugin-owned UI assets, add minimal export controls; otherwise expose clean API metadata and document the verified limitation rather than modifying Hermes core.
5. Isolate tests with a temporary `WORKBENCH_DIR` set **before importing `plugin_api`**. Cover all formats, filtering, soft-delete exclusion, filenames/media types, and invalid case behavior. Preserve existing eight tests.
6. Update manifest/version/docs only where required by actual behavior.

## Acceptance
- Baseline 8 tests plus new tests pass against a temp workbench directory.
- Generated content includes seeded records and excludes records from another case when filtered.
- Soft-deleted records are absent.
- Invalid case gets an explicit 404 (or equivalent clear 4xx).
- No live DB changes, no active network/security calls, no changes outside this repo.
- Commit changes with a concise message. Do not push.

## Report
At completion print: verified plugin contract, files changed, endpoints, exact test command/result, commit hash, and remaining limitations. Never claim tests you did not run.
