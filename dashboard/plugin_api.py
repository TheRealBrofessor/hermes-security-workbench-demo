"""Hermes Security Workbench — core backend.

A modular security research workbench served as a Hermes plugin API. Provides:
  * Case management (workspaces with scope entries)
  * A job engine (QUEUED -> RUNNING -> COMPLETED/FAILED/CANCELLED)
  * A module registry with safety/risk metadata
  * A first vertical-slice module: TCP port scanner (SAFE ACTIVE)
  * Normalized findings + evidence, SQLite persistence, multi-channel logging

Safety model:
  * Every module declares a risk_level (PASSIVE / SAFE ACTIVE / AUTHORIZED
    ACTIVE / LAB ONLY) and lab_only flag.
  * SAFE ACTIVE and above require the target to be inside an active case's
    authorized scope before a job will start.
  * LAB ONLY modules are disabled by default and refuse to run unless the
    case explicitly enables lab mode.

No destructive capability is implemented in this Phase-1 slice. This is a
controlled scaffold: extend the registry, not this file.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field


def _load_sibling_module(name: str):
    """Load a dashboard sibling under Hermes's file-based plugin contract."""
    module_name = f"_hermes_security_workbench_dashboard_{name}"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    path = Path(__file__).resolve().with_name(f"{name}.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load dashboard module: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


_reporting = _load_sibling_module("reporting")
ReportCaseNotFound = _reporting.ReportCaseNotFound
export_csv = _reporting.export_csv
export_json = _reporting.export_json
export_markdown = _reporting.export_markdown
report_filename = _reporting.report_filename
report_summary = _reporting.report_summary

router = APIRouter()

# ---------------------------------------------------------------------------
# Paths / logging
# ---------------------------------------------------------------------------
_HOME = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
_WB_DIR = Path(os.environ.get("WORKBENCH_DIR", _HOME / "hermes-security-workbench"))
_WB_DIR.mkdir(parents=True, exist_ok=True)
_DB_PATH = _WB_DIR / "workbench.db"
_LOG_DIR = _WB_DIR / "logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)


def _channel(name: str) -> logging.Logger:
    logger = logging.getLogger(f"workbench.{name}")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(_LOG_DIR / f"{name}.log", encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(fh)
        logger.propagate = False
    return logger


LOG_APP = _channel("application")
LOG_JOBS = _channel("jobs")
LOG_SEC = _channel("security")
LOG_ERR = _channel("errors")
LOG_AUDIT = _channel("audit")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created TEXT NOT NULL,
  notes TEXT DEFAULT '',
  lab_mode INTEGER DEFAULT 0,
  deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS scope_entries (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id),
  kind TEXT NOT NULL,        -- ip | cidr | domain | url | file
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  case_id TEXT,
  module TEXT NOT NULL,
  target TEXT NOT NULL,
  params TEXT DEFAULT '{}',
  status TEXT NOT NULL,      -- QUEUED RUNNING COMPLETED FAILED CANCELLED
  created TEXT NOT NULL,
  started TEXT,
  finished TEXT,
  error TEXT,
  stdout TEXT,
  stderr TEXT,
  deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  job_id TEXT,
  case_id TEXT,
  module TEXT,
  target TEXT,
  finding_type TEXT,
  value TEXT,
  confidence REAL,
  severity TEXT,
  source TEXT,
  evidence TEXT,
  raw TEXT,
  ts TEXT,
  deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,        -- HOST IP DOMAIN PORT SERVICE FILE HASH ...
  value TEXT NOT NULL,
  meta TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  job_id TEXT,
  case_id TEXT,
  ref TEXT,
  note TEXT,
  sha256 TEXT,
  ts TEXT
);
"""

_conn_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _conn_lock:
        conn = _connect()
        try:
            conn.executescript(_SCHEMA)
            # Lightweight migration: ensure deleted_at exists on pre-existing tables.
            for table in ("cases", "jobs", "findings"):
                cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
                if "deleted_at" not in cols:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN deleted_at TEXT")
            conn.commit()
        finally:
            conn.close()


_init_db()


# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------
# metadata: name, category, description, risk_level, requires_root,
# network_activity, dependencies, input_types, output_types, supports_cancel,
# lab_only, enabled_by_default, runner (coroutine).
_MODULES: Dict[str, Dict[str, Any]] = {}


def _register(meta: Dict[str, Any]):
    name = meta["name"]
    meta.setdefault("category", "general")
    meta.setdefault("risk_level", "SAFE ACTIVE")
    meta.setdefault("requires_root", False)
    meta.setdefault("network_activity", False)
    meta.setdefault("dependencies", [])
    meta.setdefault("input_types", [])
    meta.setdefault("output_types", ["finding"])
    meta.setdefault("supports_cancel", False)
    meta.setdefault("lab_only", False)
    meta.setdefault("enabled_by_default", True)
    _MODULES[name] = meta


def _validate_scope(case_id: Optional[str], target: str, meta: Dict[str, Any]) -> None:
    """Enforce safety controls before a job may run."""
    if meta.get("lab_only") and not meta.get("enabled_by_default"):
        # Lab modules are off unless the case explicitly opts in.
        enabled = False
        if case_id:
            conn = _connect()
            try:
                row = conn.execute("SELECT lab_mode FROM cases WHERE id=?", (case_id,)).fetchone()
                enabled = bool(row and row["lab_mode"])
            finally:
                conn.close()
        if not enabled:
            raise HTTPException(status_code=403, detail=f"LAB ONLY module '{meta['name']}' disabled; enable lab mode on the case.")

    if meta.get("risk_level") == "PASSIVE":
        return  # passive research needs no scope gate

    if not case_id:
        raise HTTPException(status_code=403, detail="A scope/authorization acknowledgement is required. Select an active case with an authorized target.")

    # target must be inside the case scope
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT kind, value FROM scope_entries WHERE case_id=?", (case_id,)
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        raise HTTPException(status_code=403, detail="Case has no authorized scope entries.")

    for r in rows:
        if _in_scope(target, r["kind"], r["value"]):
            return
    raise HTTPException(status_code=403, detail=f"Target '{target}' is outside the case's authorized scope.")


def _in_scope(target: str, kind: str, value: str) -> bool:
    t = target.strip().lower()
    v = value.strip().lower()
    try:
        if kind == "ip":
            return ipaddress.ip_address(t) == ipaddress.ip_address(v)
        if kind == "cidr":
            return ipaddress.ip_address(t) in ipaddress.ip_network(v, strict=False)
    except ValueError:
        return False
    if kind == "domain":
        return t == v or t.endswith("." + v)
    if kind == "url":
        # Target may be a full URL or a bare hostname. Match if the target
        # starts with the scope URL, or if the scope URL's host matches/contains
        # the target host.
        if t.startswith(v):
            return True
        from urllib.parse import urlparse
        try:
            scope_host = (urlparse(v).hostname or "").lower()
        except ValueError:
            scope_host = ""
        if scope_host and (t == scope_host or t.endswith("." + scope_host)):
            return True
        return False
    return False


# ---------------------------------------------------------------------------
# Port scan vertical slice
# ---------------------------------------------------------------------------
async def _run_portscan(target: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    ports = params.get("ports", "22,80,443,8080")
    timeout = float(params.get("timeout", 1.0))
    port_list = [int(p) for p in str(ports).split(",") if p.strip().isdigit()]
    results: List[Dict[str, Any]] = []
    loop = asyncio.get_event_loop()

    def _check(port: int) -> Optional[Dict[str, Any]]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((target, port)) == 0:
                return {
                    "finding_type": "open_port",
                    "value": str(port),
                    "confidence": 0.95,
                    "severity": "info",
                    "source": "tcp-connect",
                    "evidence": {"port": port, "state": "open"},
                }
        except Exception:
            return None
        finally:
            s.close()
        return None

    for port in port_list:
        res = await loop.run_in_executor(None, _check, port)
        if res:
            results.append(res)
    return results


_register({
    "name": "port_scan",
    "category": "recon",
    "description": "TCP connect port scan against a single host (IP/hostname).",
    "risk_level": "SAFE ACTIVE",
    "network_activity": True,
    "input_types": ["ip", "hostname"],
    "output_types": ["finding"],
    "supports_cancel": True,
    "runner": _run_portscan,
})


# ---------------------------------------------------------------------------
# Job engine
# ---------------------------------------------------------------------------
def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _save_job(job: Dict[str, Any]) -> None:
    with _conn_lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO jobs (id, case_id, module, target, params, status, created, started, finished, error, stdout, stderr)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (job["id"], job.get("case_id"), job["module"], job["target"],
                 json.dumps(job.get("params", {})), job["status"], job["created"],
                 job.get("started"), job.get("finished"), job.get("error"),
                 job.get("stdout"), job.get("stderr")),
            )
            conn.commit()
        finally:
            conn.close()


def _update_job(job_id: str, **fields) -> None:
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [job_id]
    with _conn_lock:
        conn = _connect()
        try:
            conn.execute(f"UPDATE jobs SET {cols} WHERE id=?", vals)
            conn.commit()
        finally:
            conn.close()


def _record_findings(case_id: Optional[str], job_id: str, module: str, target: str, findings: List[Dict[str, Any]]) -> None:
    with _conn_lock:
        conn = _connect()
        try:
            for f in findings:
                fid = _new_id("fnd")
                conn.execute(
                    """INSERT INTO findings (id, job_id, case_id, module, target, finding_type, value,
                       confidence, severity, source, evidence, raw, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (fid, job_id, case_id, module, target, f.get("finding_type"),
                     f.get("value"), f.get("confidence"), f.get("severity"),
                     f.get("source"), json.dumps(f.get("evidence", {})),
                     json.dumps(f.get("raw", {})), _utcnow()),
                )
            conn.commit()
        finally:
            conn.close()


def _run_job_sync(job: Dict[str, Any]) -> None:
    """Execute one job on a worker thread. Pure synchronous body."""
    meta = _MODULES.get(job["module"])
    LOG_JOBS.info("job %s started module=%s target=%s", job["id"], job["module"], job["target"])
    LOG_SEC.info("job %s target=%s module=%s (risk=%s)", job["id"], job["target"], job["module"], meta.get("risk_level"))
    LOG_AUDIT.info("JOB_START id=%s module=%s target=%s case=%s", job["id"], job["module"], job["target"], job.get("case_id"))
    _update_job(job["id"], status="RUNNING", started=_utcnow())
    try:
        runner = meta["runner"]
        # runner is a coroutine; run it on this thread via asyncio if not already running.
        try:
            loop = asyncio.get_running_loop()
            findings = asyncio.run_coroutine_threadsafe(runner(job["target"], job.get("params", {})), loop).result()
        except RuntimeError:
            findings = asyncio.run(runner(job["target"], job.get("params", {})))
        _record_findings(job.get("case_id"), job["id"], job["module"], job["target"], findings)
        _update_job(job["id"], status="COMPLETED", finished=_utcnow(), stdout=json.dumps({"findings": len(findings)}))
        LOG_JOBS.info("job %s completed with %d findings", job["id"], len(findings))
        LOG_AUDIT.info("JOB_END id=%s status=COMPLETED findings=%d", job["id"], len(findings))
    except Exception as exc:  # noqa: BLE001
        LOG_ERR.exception("job %s failed", job["id"])
        _update_job(job["id"], status="FAILED", finished=_utcnow(), error=str(exc))
        LOG_AUDIT.info("JOB_END id=%s status=FAILED error=%s", job["id"], exc)


async def _queue_job(job: Dict[str, Any]) -> str:
    _save_job(job)
    # run on a worker thread to keep the API responsive
    await asyncio.get_event_loop().run_in_executor(None, _run_job_sync, job)
    return job["id"]


# ---------------------------------------------------------------------------
# API models
# ---------------------------------------------------------------------------
class CaseCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    notes: str = ""
    lab_mode: bool = False
    scope: List[Dict[str, str]] = Field(default_factory=list)  # [{kind, value}]


class JobCreate(BaseModel):
    case_id: Optional[str] = None
    module: str
    target: str = Field(..., min_length=1, max_length=300)
    params: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "service": "hermes-security-workbench",
        "db": str(_DB_PATH),
        "modules": len(_MODULES),
        "ts": _utcnow(),
    }


@router.get("/modules")
def list_modules() -> List[Dict[str, Any]]:
    out = []
    for m in _MODULES.values():
        row = {k: v for k, v in m.items() if k != "runner"}
        out.append(row)
    return sorted(out, key=lambda x: x["name"])


@router.post("/cases")
def create_case(body: CaseCreate) -> Dict[str, Any]:
    cid = _new_id("case")
    with _conn_lock:
        conn = _connect()
        try:
            conn.execute("INSERT INTO cases (id, name, created, notes, lab_mode) VALUES (?,?,?,?,?)",
                         (cid, body.name, _utcnow(), body.notes, 1 if body.lab_mode else 0))
            for s in body.scope:
                kind, value = s.get("kind"), s.get("value")
                if kind and value:
                    conn.execute("INSERT INTO scope_entries (id, case_id, kind, value) VALUES (?,?,?,?)",
                                 (_new_id("scp"), cid, kind, value))
            conn.commit()
        finally:
            conn.close()
    LOG_APP.info("case created id=%s name=%s", cid, body.name)
    LOG_AUDIT.info("CASE_CREATE id=%s name=%s scope=%s", cid, body.name, body.scope)
    return {"id": cid, "name": body.name}


@router.get("/cases")
def list_cases() -> List[Dict[str, Any]]:
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM cases WHERE deleted_at IS NULL ORDER BY created DESC").fetchall()
        cases = []
        for r in rows:
            scope = conn.execute("SELECT kind, value FROM scope_entries WHERE case_id=?", (r["id"],)).fetchall()
            cases.append({
                "id": r["id"], "name": r["name"], "created": r["created"],
                "notes": r["notes"], "lab_mode": bool(r["lab_mode"]),
                "scope": [{"kind": s["kind"], "value": s["value"]} for s in scope],
            })
        return cases
    finally:
        conn.close()


@router.delete("/cases/{case_id}")
def delete_case(case_id: str) -> Dict[str, Any]:
    """Scoped soft-delete: archive the case and its jobs/findings (deleted_at),
    preserving the rows for audit/evidence. Returns count of affected rows."""
    with _conn_lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT id FROM cases WHERE id=? AND deleted_at IS NULL", (case_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="case not found")
            now = _utcnow()
            c = conn.execute("UPDATE cases SET deleted_at=? WHERE id=?", (now, case_id)).rowcount
            j = conn.execute("UPDATE jobs SET deleted_at=? WHERE case_id=?", (now, case_id)).rowcount
            f = conn.execute("UPDATE findings SET deleted_at=? WHERE case_id=?", (now, case_id)).rowcount
            conn.commit()
            LOG_AUDIT.info("CASE_ARCHIVE id=%s cases=%d jobs=%d findings=%d", case_id, c, j, f)
            return {"id": case_id, "archived": True, "jobs_archived": j, "findings_archived": f}
        finally:
            conn.close()


@router.post("/jobs")
async def create_job(body: JobCreate) -> Dict[str, Any]:
    if body.module not in _MODULES:
        raise HTTPException(status_code=404, detail=f"Unknown module '{body.module}'")
    meta = _MODULES[body.module]
    _validate_scope(body.case_id, body.target, meta)
    job = {
        "id": _new_id("job"),
        "case_id": body.case_id,
        "module": body.module,
        "target": body.target,
        "params": body.params,
        "status": "QUEUED",
        "created": _utcnow(),
    }
    jid = await _queue_job(job)
    return {"id": jid, "status": "QUEUED"}


@router.get("/jobs")
def list_jobs(case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = _connect()
    try:
        if case_id:
            rows = conn.execute("SELECT * FROM jobs WHERE case_id=? AND deleted_at IS NULL ORDER BY created DESC", (case_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM jobs WHERE deleted_at IS NULL ORDER BY created DESC LIMIT 100").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/jobs/{job_id}")
def get_job(job_id: str) -> Dict[str, Any]:
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="job not found")
        job = dict(row)
        job["findings"] = [dict(f) for f in conn.execute(
            "SELECT * FROM findings WHERE job_id=?", (job_id,)).fetchall()]
        return job
    finally:
        conn.close()


@router.get("/findings")
def list_findings(case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = _connect()
    try:
        if case_id:
            rows = conn.execute("SELECT * FROM findings WHERE case_id=? AND deleted_at IS NULL ORDER BY ts DESC", (case_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM findings WHERE deleted_at IS NULL ORDER BY ts DESC LIMIT 100").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Reports / exports
# ---------------------------------------------------------------------------
def _report_or_404(builder, case_id: Optional[str]):
    try:
        return builder(str(_DB_PATH), case_id=case_id)
    except ReportCaseNotFound as exc:
        raise HTTPException(status_code=404, detail="case not found") from exc


@router.get("/reports/summary")
async def get_report_summary(case_id: Optional[str] = None) -> Dict[str, Any]:
    """Return active case/job/finding totals and report breakdowns."""
    return _report_or_404(report_summary, case_id)


def _export_response(
    report_format: str,
    case_id: Optional[str],
    media_type: str,
) -> Response:
    builders = {
        "json": export_json,
        "csv": export_csv,
        "markdown": export_markdown,
    }
    content = _report_or_404(builders[report_format], case_id)
    filename = report_filename(report_format, case_id)
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/reports/json")
async def export_report_json(case_id: Optional[str] = None) -> Response:
    return _export_response("json", case_id, "application/json")


@router.get("/reports/csv")
async def export_report_csv(case_id: Optional[str] = None) -> Response:
    return _export_response("csv", case_id, "text/csv")


@router.get("/reports/markdown")
async def export_report_markdown(case_id: Optional[str] = None) -> Response:
    return _export_response("markdown", case_id, "text/markdown")


# ---------------------------------------------------------------------------
# Load extension modules (must come after _register is defined)
# ---------------------------------------------------------------------------
def _load_extension_modules() -> None:
    module_names = (
        "modules_recon", "modules_osint", "modules_web", "modules_files",
    )
    extension_modules = (
        _load_sibling_module(name).MODULES for name in module_names
    )
    for modules in extension_modules:
        for meta in modules:
            _register(meta)


_load_extension_modules()
