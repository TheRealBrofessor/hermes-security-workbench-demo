"""Read-only views over the authorized pipeline's canonical SQLite store."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query


router = APIRouter(prefix="/pipeline", tags=["authorized-pipeline"])
_DEFAULT_DB = Path(
    "/home/professor/Projects/bounty-recon/.worktrees/authorized-bounty-campaign/state/security-pipeline.db"
)
_PIPELINE_DB = Path(os.environ.get("SECURITY_PIPELINE_DB", str(_DEFAULT_DB)))


def _connect() -> sqlite3.Connection:
    if not _PIPELINE_DB.is_file():
        raise HTTPException(status_code=503, detail="authorized pipeline database is not initialized")
    connection = sqlite3.connect(f"file:{_PIPELINE_DB}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def _has_table(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _rows(query: str, params: tuple = ()) -> list[dict[str, Any]]:
    connection = _connect()
    try:
        return [dict(row) for row in connection.execute(query, params).fetchall()]
    finally:
        connection.close()


@router.get("/health")
def pipeline_health() -> dict[str, Any]:
    return {"ok": _PIPELINE_DB.is_file(), "db": str(_PIPELINE_DB), "read_only": True}


@router.get("/summary")
def pipeline_summary() -> dict[str, Any]:
    connection = _connect()
    try:
        tables = {
            row["name"]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        counts = {}
        for table in (
            "runs",
            "assets",
            "asset_changes",
            "routes",
            "findings",
            "validations",
            "manual_reviews",
            "notifications",
            "activity_events",
        ):
            counts[table] = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] if table in tables else 0
        return {"db": str(_PIPELINE_DB), "read_only": True, "counts": counts}
    finally:
        connection.close()


@router.get("/runs")
def pipeline_runs(limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
    return _rows("SELECT * FROM runs ORDER BY observed_at DESC LIMIT ?", (limit,))


@router.get("/assets")
def pipeline_assets(limit: int = Query(200, ge=1, le=500)) -> list[dict[str, Any]]:
    return _rows("SELECT * FROM assets ORDER BY last_seen DESC LIMIT ?", (limit,))


@router.get("/changes")
def pipeline_changes(limit: int = Query(200, ge=1, le=500)) -> list[dict[str, Any]]:
    return _rows("SELECT * FROM asset_changes ORDER BY rowid DESC LIMIT ?", (limit,))


@router.get("/routes")
def pipeline_routes(limit: int = Query(200, ge=1, le=500)) -> list[dict[str, Any]]:
    return _rows("SELECT * FROM routes ORDER BY rowid DESC LIMIT ?", (limit,))


@router.get("/findings")
def pipeline_findings(status: str | None = None, limit: int = Query(200, ge=1, le=500)) -> list[dict[str, Any]]:
    if status:
        return _rows("SELECT * FROM findings WHERE status=? ORDER BY updated_at DESC LIMIT ?", (status, limit))
    return _rows("SELECT * FROM findings ORDER BY updated_at DESC LIMIT ?", (limit,))


@router.get("/validation-failures")
def pipeline_validation_failures(limit: int = Query(200, ge=1, le=500)) -> list[dict[str, Any]]:
    return _rows(
        "SELECT * FROM validations WHERE verdict IN ('FALSE_POSITIVE','INSUFFICIENT_EVIDENCE') ORDER BY created_at DESC LIMIT ?",
        (limit,),
    )


@router.get("/manual-review")
def pipeline_manual_review(limit: int = Query(200, ge=1, le=500)) -> list[dict[str, Any]]:
    return _rows("SELECT * FROM manual_reviews ORDER BY updated_at DESC LIMIT ?", (limit,))


@router.get("/scope-violations")
def pipeline_scope_violations(limit: int = Query(200, ge=1, le=500)) -> list[dict[str, Any]]:
    return _rows(
        "SELECT * FROM activity_events WHERE event_type='SCOPE_REJECTED' ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    )


@router.get("/errors")
def pipeline_errors(limit: int = Query(200, ge=1, le=500)) -> list[dict[str, Any]]:
    return _rows(
        "SELECT * FROM activity_events WHERE event_type LIKE '%ERROR%' OR event_type LIKE '%FAILED%' ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    )
