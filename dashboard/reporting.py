"""Hermes Security Workbench reporting/export helpers.

The helpers in this module are deliberately independent of ``plugin_api`` so
they can be reused without starting the workbench job engine. Report rows are
selected through explicit allowlists: job parameters/output and raw finding
evidence are operational data and are never part of an export.
"""
from __future__ import annotations

import csv
import html
import io
import json
import re
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


CASE_FIELDS = ("id", "name", "created", "lab_mode")
JOB_FIELDS = (
    "id", "case_id", "module", "target", "status", "created", "started",
    "finished",
)
FINDING_FIELDS = (
    "id", "job_id", "case_id", "module", "target", "finding_type", "value",
    "confidence", "severity", "source", "ts",
)


class ReportCaseNotFound(LookupError):
    """Raised when a case-scoped report names no active case."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(db_path: str) -> sqlite3.Connection:
    if not Path(db_path).exists():
        raise FileNotFoundError(f"workbench database not found: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _select_fields(alias: str, fields: Sequence[str]) -> str:
    return ", ".join(f"{alias}.{field}" for field in fields)


def _validate_case(conn: sqlite3.Connection, case_id: Optional[str]) -> None:
    if case_id is None:
        return
    row = conn.execute(
        "SELECT id FROM cases WHERE id=? AND deleted_at IS NULL",
        (case_id,),
    ).fetchone()
    if row is None:
        raise ReportCaseNotFound(case_id)


def _report_rows(
    conn: sqlite3.Connection,
    case_id: Optional[str],
) -> Dict[str, List[Dict[str, Any]]]:
    """Load active report rows using the public report field allowlists.

    Besides checking each row's own ``deleted_at``, child rows require an
    active parent. This prevents partially archived or legacy data from
    leaking through a global export even if an old cascade did not mark every
    child row.
    """
    _validate_case(conn, case_id)

    case_sql = (
        f"SELECT {_select_fields('c', CASE_FIELDS)} "
        "FROM cases c WHERE c.deleted_at IS NULL"
    )
    case_params: tuple[Any, ...] = ()
    if case_id is not None:
        case_sql += " AND c.id=?"
        case_params = (case_id,)
    case_sql += " ORDER BY c.created DESC, c.id"

    job_sql = (
        f"SELECT {_select_fields('j', JOB_FIELDS)} "
        "FROM jobs j WHERE j.deleted_at IS NULL "
        "AND (j.case_id IS NULL OR EXISTS ("
        "SELECT 1 FROM cases parent_case "
        "WHERE parent_case.id=j.case_id AND parent_case.deleted_at IS NULL))"
    )
    job_params: tuple[Any, ...] = ()
    if case_id is not None:
        job_sql += " AND j.case_id=?"
        job_params = (case_id,)
    job_sql += " ORDER BY j.created DESC, j.id"

    finding_sql = (
        f"SELECT {_select_fields('f', FINDING_FIELDS)} "
        "FROM findings f WHERE f.deleted_at IS NULL "
        "AND (f.case_id IS NULL OR EXISTS ("
        "SELECT 1 FROM cases finding_case "
        "WHERE finding_case.id=f.case_id "
        "AND finding_case.deleted_at IS NULL)) "
        "AND (f.job_id IS NULL OR EXISTS ("
        "SELECT 1 FROM jobs parent_job "
        "WHERE parent_job.id=f.job_id AND parent_job.deleted_at IS NULL "
        "AND (parent_job.case_id IS NULL OR EXISTS ("
        "SELECT 1 FROM cases job_case "
        "WHERE job_case.id=parent_job.case_id "
        "AND job_case.deleted_at IS NULL))))"
    )
    finding_params: tuple[Any, ...] = ()
    if case_id is not None:
        finding_sql += " AND f.case_id=?"
        finding_params = (case_id,)
    finding_sql += " ORDER BY f.ts DESC, f.id"

    cases = [dict(row) for row in conn.execute(case_sql, case_params)]
    for case in cases:
        case["lab_mode"] = bool(case["lab_mode"])

    return {
        "cases": cases,
        "jobs": [dict(row) for row in conn.execute(job_sql, job_params)],
        "findings": [
            dict(row) for row in conn.execute(finding_sql, finding_params)
        ],
    }


def _breakdown(rows: Sequence[Dict[str, Any]], field: str) -> Dict[str, int]:
    counts = Counter(str(row.get(field) or "unknown") for row in rows)
    return dict(sorted(counts.items()))


def _summary(
    rows: Dict[str, List[Dict[str, Any]]],
    case_id: Optional[str],
    generated: str,
) -> Dict[str, Any]:
    return {
        "report": "summary",
        "generated": generated,
        "case_id": case_id,
        "counts": {
            "cases": len(rows["cases"]),
            "jobs": len(rows["jobs"]),
            "findings": len(rows["findings"]),
        },
        "jobs_by_status": _breakdown(rows["jobs"], "status"),
        "findings_by_severity": _breakdown(rows["findings"], "severity"),
    }


def report_summary(db_path: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    conn = _connect(db_path)
    try:
        rows = _report_rows(conn, case_id)
    finally:
        conn.close()
    return _summary(rows, case_id, _utcnow())


def _write_or_return(text: str, out_path: Optional[str]) -> str:
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
        return out_path
    return text


def export_json(
    db_path: str,
    case_id: Optional[str] = None,
    out_path: Optional[str] = None,
) -> str:
    conn = _connect(db_path)
    try:
        rows = _report_rows(conn, case_id)
    finally:
        conn.close()
    generated = _utcnow()
    report = {
        "report": "json",
        "generated": generated,
        "case_id": case_id,
        "summary": _summary(rows, case_id, generated),
        **rows,
    }
    return _write_or_return(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        out_path,
    )


def _csv_cell(value: Any) -> Any:
    """Neutralize formulas when a CSV is opened in a spreadsheet."""
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value
    return value


def export_csv(
    db_path: str,
    case_id: Optional[str] = None,
    out_path: Optional[str] = None,
) -> str:
    conn = _connect(db_path)
    try:
        rows = _report_rows(conn, case_id)
    finally:
        conn.close()

    fields = (
        "ts", "module", "target", "finding_type", "value", "confidence",
        "severity", "source",
    )
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(fields)
    for finding in rows["findings"]:
        writer.writerow([_csv_cell(finding[field]) for field in fields])
    return _write_or_return(buf.getvalue(), out_path)


def _markdown_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = html.escape(text, quote=False).replace("|", "\\|").replace("`", "\\`")
    return text.replace("\r\n", "<br>").replace("\r", "<br>").replace("\n", "<br>")


def _append_breakdown(
    lines: List[str],
    title: str,
    values: Dict[str, int],
) -> None:
    lines.extend((f"### {title}", "", "| Value | Count |", "|-------|------:|"))
    if values:
        for value, count in values.items():
            lines.append(f"| {_markdown_cell(value)} | {count} |")
    else:
        lines.append("| None | 0 |")
    lines.append("")


def export_markdown(
    db_path: str,
    case_id: Optional[str] = None,
    out_path: Optional[str] = None,
) -> str:
    conn = _connect(db_path)
    try:
        rows = _report_rows(conn, case_id)
    finally:
        conn.close()
    generated = _utcnow()
    summary = _summary(rows, case_id, generated)

    lines: List[str] = [
        "# Hermes Security Workbench Report",
        "",
        f"**Generated:** {_markdown_cell(generated)}",
    ]
    if case_id is not None:
        lines.append(f"**Case:** `{_markdown_cell(case_id)}`")
    lines.extend((
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|--------|------:|",
        f"| Cases | {summary['counts']['cases']} |",
        f"| Jobs | {summary['counts']['jobs']} |",
        f"| Findings | {summary['counts']['findings']} |",
        "",
    ))
    _append_breakdown(lines, "Jobs by status", summary["jobs_by_status"])
    _append_breakdown(
        lines,
        "Findings by severity",
        summary["findings_by_severity"],
    )

    lines.extend((
        "## Cases",
        "",
        "| ID | Name | Created | Lab mode |",
        "|----|------|---------|----------|",
    ))
    for case in rows["cases"]:
        lines.append(
            "| {id} | {name} | {created} | {lab_mode} |".format(
                **{key: _markdown_cell(value) for key, value in case.items()}
            )
        )
    lines.extend((
        "",
        "## Jobs",
        "",
        "| ID | Module | Target | Status | Created | Started | Finished |",
        "|----|--------|--------|--------|---------|---------|----------|",
    ))
    for job in rows["jobs"]:
        safe = {key: _markdown_cell(value) for key, value in job.items()}
        lines.append(
            "| {id} | {module} | {target} | {status} | {created} | "
            "{started} | {finished} |".format(**safe)
        )
    lines.extend((
        "",
        "## Findings",
        "",
        "| Timestamp | Module | Target | Type | Value | Confidence | Severity | Source |",
        "|-----------|--------|--------|------|-------|------------|----------|--------|",
    ))
    for finding in rows["findings"]:
        safe = {key: _markdown_cell(value) for key, value in finding.items()}
        lines.append(
            "| {ts} | {module} | {target} | {finding_type} | {value} | "
            "{confidence} | {severity} | {source} |".format(**safe)
        )
    lines.append("")
    return _write_or_return("\n".join(lines), out_path)


def report_filename(report_format: str, case_id: Optional[str] = None) -> str:
    extensions = {"json": "json", "csv": "csv", "markdown": "md"}
    if report_format not in extensions:
        raise ValueError(f"unknown report format: {report_format}")
    scope = case_id or "all-cases"
    safe_scope = re.sub(r"[^A-Za-z0-9_-]+", "-", scope)[:80].strip("-_")
    if not safe_scope:
        safe_scope = "case"
    return f"hermes-security-workbench-{safe_scope}.{extensions[report_format]}"
