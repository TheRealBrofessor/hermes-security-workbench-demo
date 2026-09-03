"""Hermes Security Workbench behavior tests.

Run from ``dashboard/`` with a temporary workbench directory:

    WORKBENCH_DIR=$(mktemp -d) python3 -m pytest tests/test_workbench.py -q

The module also creates its own temporary directory before importing
``plugin_api``. This keeps ad-hoc pytest invocations away from the live
workbench database as well.
"""
from __future__ import annotations

import asyncio
import csv
import importlib.util
import io
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest
import httpx
from fastapi import FastAPI


_TEST_WORKBENCH = tempfile.TemporaryDirectory(prefix="hermes-workbench-tests-")
os.environ["WORKBENCH_DIR"] = _TEST_WORKBENCH.name
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import plugin_api as api  # noqa: E402


API_PREFIX = "/api/plugins/hermes-security-workbench"
DELETED_AT = "2026-01-03T00:00:00+00:00"
SENSITIVE_MARKERS = (
    "SECRET_NOTES",
    "SECRET_PARAMS",
    "SECRET_LOG_PATH",
    "SECRET_STDERR",
    "SECRET_ERROR",
    "SECRET_EVIDENCE",
    "SECRET_RAW",
)


@pytest.fixture(autouse=True)
def clean_database():
    """Give every test a clean schema inside the temporary workbench."""
    conn = api._connect()
    try:
        for table in (
            "evidence", "findings", "jobs", "scope_entries", "entities", "cases",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(api.router, prefix=API_PREFIX)

    class ASGITestClient:
        def get(self, path, **kwargs):
            async def request():
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="http://workbench.test",
                ) as test_client:
                    return await test_client.get(path, **kwargs)

            return asyncio.run(request())

    return ASGITestClient()


def _seed_report_data() -> None:
    """Seed two active cases plus directly and transitively archived rows."""
    conn = api._connect()
    try:
        conn.executemany(
            """INSERT INTO cases
               (id, name, created, notes, lab_mode, deleted_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                (
                    "case-alpha", "Alpha Case", "2026-01-01T00:00:00+00:00",
                    "SECRET_NOTES", 0, None,
                ),
                (
                    "case-beta", "Beta Case", "2026-01-02T00:00:00+00:00",
                    "", 1, None,
                ),
                (
                    "case-archived", "Archived Case",
                    "2025-12-01T00:00:00+00:00", "", 0, DELETED_AT,
                ),
            ),
        )
        conn.executemany(
            """INSERT INTO jobs
               (id, case_id, module, target, params, status, created, started,
                finished, error, stdout, stderr, deleted_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                (
                    "job-alpha", "case-alpha", "seed_module", "alpha-target",
                    '{"api_key":"SECRET_PARAMS"}', "COMPLETED",
                    "2026-01-01T01:00:00+00:00",
                    "2026-01-01T01:01:00+00:00",
                    "2026-01-01T01:02:00+00:00", "SECRET_ERROR",
                    "/tmp/SECRET_LOG_PATH", "SECRET_STDERR", None,
                ),
                (
                    "job-alpha-deleted", "case-alpha", "deleted_module",
                    "alpha-soft-deleted-job", "{}", "FAILED",
                    "2026-01-01T02:00:00+00:00", None, None, None, None, None,
                    DELETED_AT,
                ),
                (
                    "job-beta", "case-beta", "seed_module", "beta-target", "{}",
                    "RUNNING", "2026-01-02T01:00:00+00:00",
                    "2026-01-02T01:01:00+00:00", None, None, None, None, None,
                ),
                (
                    "job-archived", "case-archived", "archived_module",
                    "archived-target", "{}", "FAILED",
                    "2025-12-01T01:00:00+00:00", None, None, None, None, None,
                    None,
                ),
            ),
        )
        conn.executemany(
            """INSERT INTO findings
               (id, job_id, case_id, module, target, finding_type, value,
                confidence, severity, source, evidence, raw, ts, deleted_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                (
                    "finding-alpha", "job-alpha", "case-alpha", "seed_module",
                    "alpha-target", "seed_type", "alpha-visible", 0.9, "high",
                    "seed", '{"path":"SECRET_EVIDENCE"}',
                    '{"token":"SECRET_RAW"}', "2026-01-01T01:02:00+00:00", None,
                ),
                (
                    "finding-alpha-deleted", "job-alpha", "case-alpha",
                    "seed_module", "alpha-target", "seed_type",
                    "alpha-soft-deleted-finding", 0.5, "medium", "seed", "{}",
                    "{}", "2026-01-01T01:03:00+00:00", DELETED_AT,
                ),
                (
                    "finding-deleted-job", "job-alpha-deleted", "case-alpha",
                    "deleted_module", "alpha-target", "seed_type",
                    "alpha-deleted-job-child", 0.5, "medium", "seed", "{}",
                    "{}", "2026-01-01T02:01:00+00:00", None,
                ),
                (
                    "finding-beta", "job-beta", "case-beta", "seed_module",
                    "beta-target", "seed_type", "beta-visible", 0.7, "low",
                    "seed", "{}", "{}", "2026-01-02T01:02:00+00:00", None,
                ),
                (
                    "finding-archived", "job-archived", "case-archived",
                    "archived_module", "archived-target", "seed_type",
                    "archived-visible", 1.0, "critical", "seed", "{}", "{}",
                    "2025-12-01T01:02:00+00:00", None,
                ),
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ---- preserved baseline tests ---------------------------------------------
def test_health():
    health = api.health()
    assert health["ok"] is True
    assert "modules" in health
    assert Path(health["db"]).is_relative_to(Path(_TEST_WORKBENCH.name))


def test_modules_registered():
    assert "port_scan" in api._MODULES
    assert api._MODULES["port_scan"]["risk_level"] == "SAFE ACTIVE"


def test_scope_ip():
    assert api._in_scope("192.168.56.10", "ip", "192.168.56.10") is True
    assert api._in_scope("192.168.56.11", "ip", "192.168.56.10") is False


def test_scope_cidr():
    assert api._in_scope("192.168.56.11", "cidr", "192.168.56.0/24") is True
    assert api._in_scope("10.0.0.1", "cidr", "192.168.56.0/24") is False


def test_validate_scope_blocks_out_of_scope():
    with pytest.raises(Exception):
        api._validate_scope(None, "8.8.8.8", api._MODULES["port_scan"])


def test_create_case():
    case = api.create_case(api.CaseCreate(
        name="test_wb_scope",
        scope=[{"kind": "ip", "value": "127.0.0.1"}],
    ))
    assert "id" in case


def test_job_portscan_localhost(monkeypatch):
    async def fake_portscan(_target, _params):
        return []

    monkeypatch.setitem(api._MODULES["port_scan"], "runner", fake_portscan)
    case = api.create_case(api.CaseCreate(
        name="test_wb_job",
        scope=[{"kind": "ip", "value": "127.0.0.1"}],
    ))
    job = {
        "id": api._new_id("job"),
        "case_id": case["id"],
        "module": "port_scan",
        "target": "127.0.0.1",
        "params": {"ports": "22,80"},
        "status": "QUEUED",
        "created": api._utcnow(),
    }
    api._save_job(job)
    api._run_job_sync(job)
    job_id = job["id"]
    job = api.get_job(job_id)
    assert job["status"] == "COMPLETED", f"job failed: {job.get('error')}"
    assert "findings" in job


def test_portscan_findings(monkeypatch):
    async def fake_portscan(_target, _params):
        return [{
            "finding_type": "open_port",
            "value": "443",
            "confidence": 0.95,
            "severity": "info",
            "source": "test-double",
            "evidence": {"port": 443, "state": "open"},
        }]

    monkeypatch.setitem(api._MODULES["port_scan"], "runner", fake_portscan)
    case = api.create_case(api.CaseCreate(
        name="test_wb_findings",
        scope=[{"kind": "ip", "value": "127.0.0.1"}],
    ))
    job = {
        "id": api._new_id("job"),
        "case_id": case["id"],
        "module": "port_scan",
        "target": "127.0.0.1",
        "params": {"ports": "22,80"},
        "status": "QUEUED",
        "created": api._utcnow(),
    }
    api._save_job(job)
    api._run_job_sync(job)
    job_id = job["id"]
    findings = api.get_job(job_id)["findings"]
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "open_port"
    assert findings[0]["value"] == "443"


# ---- report endpoint behavior ---------------------------------------------
def test_report_summary_contract_and_soft_delete_exclusion(client):
    _seed_report_data()

    response = client.get(f"{API_PREFIX}/reports/summary")
    assert response.status_code == 200
    assert "content-disposition" not in response.headers
    assert response.json() == {
        "report": "summary",
        "generated": response.json()["generated"],
        "case_id": None,
        "counts": {"cases": 2, "jobs": 2, "findings": 2},
        "jobs_by_status": {"COMPLETED": 1, "RUNNING": 1},
        "findings_by_severity": {"high": 1, "low": 1},
    }

    scoped = client.get(
        f"{API_PREFIX}/reports/summary", params={"case_id": "case-alpha"}
    )
    assert scoped.status_code == 200
    assert scoped.json()["case_id"] == "case-alpha"
    assert scoped.json()["counts"] == {"cases": 1, "jobs": 1, "findings": 1}
    assert scoped.json()["jobs_by_status"] == {"COMPLETED": 1}
    assert scoped.json()["findings_by_severity"] == {"high": 1}


@pytest.mark.parametrize(
    ("report_format", "content_type", "extension"),
    (
        ("json", "application/json", "json"),
        ("csv", "text/csv; charset=utf-8", "csv"),
        ("markdown", "text/markdown; charset=utf-8", "md"),
    ),
)
def test_report_export_media_types_and_safe_filenames(
    client, report_format, content_type, extension,
):
    _seed_report_data()
    response = client.get(
        f"{API_PREFIX}/reports/{report_format}",
        params={"case_id": "case-alpha"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == content_type
    assert response.headers["content-disposition"] == (
        "attachment; filename=\"hermes-security-workbench-case-alpha."
        f"{extension}\""
    )
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"

    unscoped = client.get(f"{API_PREFIX}/reports/{report_format}")
    assert unscoped.headers["content-disposition"] == (
        "attachment; filename=\"hermes-security-workbench-all-cases."
        f"{extension}\""
    )


def test_report_filename_removes_header_control_and_path_characters(client):
    unsafe_case_id = "case\r\n../../evil"
    conn = api._connect()
    try:
        conn.execute(
            "INSERT INTO cases (id, name, created) VALUES (?, ?, ?)",
            (unsafe_case_id, "Unsafe identifier", "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()
    finally:
        conn.close()

    response = client.get(
        f"{API_PREFIX}/reports/json", params={"case_id": unsafe_case_id}
    )
    assert response.status_code == 200
    assert response.headers["content-disposition"] == (
        'attachment; filename="hermes-security-workbench-case-evil.json"'
    )


@pytest.mark.parametrize("report_format", ("json", "csv", "markdown"))
def test_all_report_formats_filter_and_exclude_archived_or_sensitive_data(
    client, report_format,
):
    _seed_report_data()
    response = client.get(
        f"{API_PREFIX}/reports/{report_format}",
        params={"case_id": "case-alpha"},
    )
    assert response.status_code == 200

    text = response.text
    assert "alpha-visible" in text
    assert "beta-visible" not in text
    assert "archived-visible" not in text
    assert "alpha-soft-deleted" not in text
    assert "alpha-deleted-job-child" not in text
    for marker in SENSITIVE_MARKERS:
        assert marker not in text


def test_json_report_field_allowlists_and_summary(client):
    _seed_report_data()
    report = client.get(f"{API_PREFIX}/reports/json").json()

    assert report["report"] == "json"
    assert report["case_id"] is None
    assert report["summary"]["counts"] == {
        "cases": 2,
        "jobs": 2,
        "findings": 2,
    }
    assert set(report["cases"][0]) == {"id", "name", "created", "lab_mode"}
    assert all(isinstance(case["lab_mode"], bool) for case in report["cases"])
    assert set(report["jobs"][0]) == {
        "id", "case_id", "module", "target", "status", "created", "started",
        "finished",
    }
    assert set(report["findings"][0]) == {
        "id", "job_id", "case_id", "module", "target", "finding_type",
        "value", "confidence", "severity", "source", "ts",
    }


def test_csv_report_content_contract_and_formula_safety(client):
    _seed_report_data()
    conn = api._connect()
    try:
        conn.execute(
            "UPDATE findings SET value=? WHERE id='finding-alpha'",
            ("=HYPERLINK(\"https://invalid.example\")",),
        )
        conn.commit()
    finally:
        conn.close()

    response = client.get(
        f"{API_PREFIX}/reports/csv", params={"case_id": "case-alpha"}
    )
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert list(rows[0]) == [
        "ts", "module", "target", "finding_type", "value", "confidence",
        "severity", "source",
    ]
    assert len(rows) == 1
    assert rows[0]["value"].startswith("'=HYPERLINK")
    assert rows[0]["severity"] == "high"


def test_markdown_report_content_contract_and_escaping(client):
    _seed_report_data()
    conn = api._connect()
    try:
        conn.execute(
            "UPDATE cases SET name=? WHERE id='case-alpha'",
            ("Alpha | <script>",),
        )
        conn.commit()
    finally:
        conn.close()

    response = client.get(
        f"{API_PREFIX}/reports/markdown", params={"case_id": "case-alpha"}
    )
    assert response.text.startswith("# Hermes Security Workbench Report")
    assert "## Summary" in response.text
    assert "### Jobs by status" in response.text
    assert "### Findings by severity" in response.text
    assert "## Cases" in response.text
    assert "## Jobs" in response.text
    assert "## Findings" in response.text
    assert "Alpha \\| &lt;script&gt;" in response.text


@pytest.mark.parametrize(
    "path", ("reports/summary", "reports/json", "reports/csv", "reports/markdown")
)
@pytest.mark.parametrize("case_id", ("case-unknown", "case-archived"))
def test_every_report_endpoint_rejects_unknown_or_archived_case(
    client, path, case_id,
):
    _seed_report_data()
    response = client.get(f"{API_PREFIX}/{path}", params={"case_id": case_id})
    assert response.status_code == 404
    assert response.json() == {"detail": "case not found"}


def test_dashboard_manifest_declares_report_controls():
    dashboard_dir = Path(__file__).resolve().parents[1]
    manifest = json.loads((dashboard_dir / "manifest.json").read_text("utf-8"))
    bundle = (dashboard_dir / manifest["entry"]).read_text("utf-8")

    assert manifest["version"] == "0.2.0"
    assert manifest["tab"]["path"] == "/security-workbench"
    assert (dashboard_dir / manifest["css"]).is_file()
    assert "SDK.authedFetch" in bundle
    assert 'window.__HERMES_PLUGINS__.register(' in bundle
    assert '"hermes-security-workbench"' in bundle


def test_plugin_loads_through_hermes_file_contract():
    """Hermes imports plugin_api by file path, without adding it to sys.path."""
    plugin_path = Path(api.__file__).resolve()
    module_name = "hermes_dashboard_plugin_contract_test"
    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        paths = {route.path for route in module.router.routes}
        assert "/reports/summary" in paths
        assert "/reports/json" in paths
        assert "/reports/csv" in paths
        assert "/reports/markdown" in paths
    finally:
        sys.modules.pop(module_name, None)
