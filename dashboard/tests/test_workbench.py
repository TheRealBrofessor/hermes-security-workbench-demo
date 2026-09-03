"""Hermes Security Workbench — unit tests.

Run: python3 -m pytest tests/test_workbench.py -q   (or `python3 tests/test_workbench.py`)
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import plugin_api as api  # noqa: E402


# ---- tests -----------------------------------------------------------------
def test_health():
    h = api.health()
    assert h["ok"] is True
    assert "modules" in h


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
    raised = False
    try:
        api._validate_scope(None, "8.8.8.8", api._MODULES["port_scan"])
    except Exception:
        raised = True
    assert raised, "expected an exception for out-of-scope / no-case active job"


def test_create_case():
    case = api.create_case(api.CaseCreate(name="test_wb_scope", scope=[{"kind": "ip", "value": "127.0.0.1"}]))
    assert "id" in case


def test_job_portscan_localhost():
    case = api.create_case(api.CaseCreate(name="test_wb_job", scope=[{"kind": "ip", "value": "127.0.0.1"}]))
    cid = case["id"]
    jid = asyncio.run(api._queue_job({
        "id": api._new_id("job"), "case_id": cid, "module": "port_scan",
        "target": "127.0.0.1", "params": {"ports": "22,80"}, "status": "QUEUED",
        "created": api._utcnow(),
    }))
    job = api.get_job(jid)
    assert job["status"] == "COMPLETED", f"job failed: {job.get('error')}"
    assert "findings" in job


def test_portscan_findings():
    case = api.create_case(api.CaseCreate(name="test_wb_findings", scope=[{"kind": "ip", "value": "127.0.0.1"}]))
    cid = case["id"]
    jid = asyncio.run(api._queue_job({
        "id": api._new_id("job"), "case_id": cid, "module": "port_scan",
        "target": "127.0.0.1", "params": {"ports": "22,80"}, "status": "QUEUED",
        "created": api._utcnow(),
    }))
    findings = api.get_job(jid)["findings"]
    assert isinstance(findings, list)
    for f in findings:
        assert "finding_type" in f
        assert "value" in f


# ---- runner ----------------------------------------------------------------
if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {t.__name__}: {exc}")
    total = len(tests)
    print(f"\n{passed}/{total} tests passed")
    sys.exit(0 if passed == total else 1)
