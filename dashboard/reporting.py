"""Hermes Security Workbench — reporting/export.

Self-contained export helpers (stdlib only) producing JSON, CSV, and Markdown
from the workbench SQLite database. Does not import plugin_api.
"""
from __future__ import annotations

import csv
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(db_path: str) -> sqlite3.Connection:
    if not Path(db_path).exists():
        raise FileNotFoundError(f"workbench database not found: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _filtered(conn: sqlite3.Connection, table: str, case_id: Optional[str], limit: int = 1000):
    # Each table has its own timestamp column: cases->created, jobs->created, findings->ts
    ts_col = "ts" if table == "findings" else "created"
    if case_id:
        if table == "cases":
            # cases are keyed by id, not case_id
            return conn.execute(
                "SELECT * FROM cases WHERE id=? AND deleted_at IS NULL LIMIT ?",
                (case_id, limit),
            ).fetchall()
        return conn.execute(
            f"SELECT * FROM {table} WHERE case_id=? AND deleted_at IS NULL ORDER BY {ts_col} DESC LIMIT ?",
            (case_id, limit),
        ).fetchall()
    return conn.execute(
        f"SELECT * FROM {table} WHERE deleted_at IS NULL ORDER BY {ts_col} DESC LIMIT ?",
        (limit,),
    ).fetchall()


def export_json(db_path: str, case_id: Optional[str] = None, out_path: Optional[str] = None) -> str:
    conn = _connect(db_path)
    try:
        cases = _filtered(conn, "cases", case_id)
        jobs = _filtered(conn, "jobs", case_id)
        findings = _filtered(conn, "findings", case_id)

        def _ev(f: sqlite3.Row) -> Any:
            try:
                return json.loads(f["evidence"]) if f["evidence"] else {}
            except (TypeError, ValueError):
                return {}

        report = {
            "report": "json",
            "generated": _utcnow(),
            "cases": [dict(c) for c in cases],
            "jobs": [dict(j) for j in jobs],
            "findings": [{**dict(f), "evidence": _ev(f)} for f in findings],
        }
    finally:
        conn.close()
    text = json.dumps(report, indent=2, default=str)
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
        return out_path
    return text


def export_csv(db_path: str, case_id: Optional[str] = None, out_path: Optional[str] = None) -> str:
    conn = _connect(db_path)
    try:
        findings = _filtered(conn, "findings", case_id)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ts", "module", "target", "finding_type", "value", "confidence", "severity", "source"])
        for f in findings:
            writer.writerow([
                f["ts"], f["module"], f["target"], f["finding_type"],
                f["value"], f["confidence"], f["severity"], f["source"],
            ])
    finally:
        conn.close()
    text = buf.getvalue()
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
        return out_path
    return text


def export_markdown(db_path: str, case_id: Optional[str] = None, out_path: Optional[str] = None) -> str:
    conn = _connect(db_path)
    try:
        cases = _filtered(conn, "cases", case_id)
        jobs = _filtered(conn, "jobs", case_id)
        findings = _filtered(conn, "findings", case_id)

        lines: List[str] = []
        lines.append("# Hermes Security Workbench Report")
        lines.append("")
        lines.append(f"**Generated:** {_utcnow()}")
        if case_id:
            lines.append(f"**Case:** `{case_id}`")
        lines.append("")

        lines.append("## Cases")
        lines.append("")
        lines.append("| Name | Created | Notes |")
        lines.append("|------|---------|-------|")
        for c in cases:
            notes = (c["notes"] or "").replace("|", "\\|")
            lines.append(f"| {c['name']} | {c['created']} | {notes} |")
        lines.append("")

        lines.append("## Jobs")
        lines.append("")
        lines.append("| Module | Target | Status | Created |")
        lines.append("|--------|--------|--------|---------|")
        for j in jobs:
            lines.append(f"| {j['module']} | {j['target']} | {j['status']} | {j['created']} |")
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        lines.append("| ts | module | target | type | value | severity | source |")
        lines.append("|----|--------|--------|------|-------|----------|--------|")
        for f in findings:
            val = (f["value"] or "").replace("|", "\\|")
            lines.append(
                f"| {f['ts']} | {f['module']} | {f['target']} | {f['finding_type']} "
                f"| {val} | {f['severity']} | {f['source']} |"
            )
        lines.append("")
    finally:
        conn.close()
    text = "\n".join(lines)
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
        return out_path
    return text
