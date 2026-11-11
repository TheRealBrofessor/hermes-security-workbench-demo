"""Hermes Security Workbench — agent tool registration.

The dashboard backend is imported lazily when a tool is called so optional
FastAPI/dashboard dependencies cannot break Hermes plugin discovery.
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any


_TOOLSET = "plugin_hermes_security_workbench"
_API = None


def _api():
    global _API
    if _API is not None:
        return _API
    module_name = "_hermes_security_workbench_tool_api"
    path = Path(__file__).resolve().parent / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Security Workbench backend")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    _API = module
    return module


def _health(_args: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
    api = _api()
    result = api.health()
    result["modules_available"] = [module["name"] for module in api.list_modules()]
    return result


def _case(args: dict[str, Any], **_kwargs: Any) -> Any:
    api = _api()
    action = args.get("action")
    if action == "list":
        return api.list_cases()
    if action == "create":
        if not args.get("name"):
            raise ValueError("name is required when action=create")
        body = api.CaseCreate(
            name=args["name"],
            notes=args.get("notes", ""),
            lab_mode=args.get("lab_mode", False),
            scope=args.get("scope", []),
        )
        return api.create_case(body)
    raise ValueError(f"unsupported case action: {action!r}")


def _job(args: dict[str, Any], **_kwargs: Any) -> Any:
    api = _api()
    action = args.get("action")
    if action == "list":
        return api.list_jobs(args.get("case_id"))
    if action == "get":
        if not args.get("job_id"):
            raise ValueError("job_id is required when action=get")
        return api.get_job(args["job_id"])
    raise ValueError(f"unsupported job action: {action!r}")


async def _portscan(args: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
    api = _api()
    body = api.JobCreate(
        case_id=args["case_id"],
        module="port_scan",
        target=args["target"],
        params={"ports": args.get("ports", "22,80,443")},
    )
    created = await api.create_job(body)
    job_id = created["id"]
    for _ in range(300):
        job = api.get_job(job_id)
        if job["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
            return job
        await asyncio.sleep(0.1)
    return {"id": job_id, "status": "RUNNING", "note": "job continues in the Workbench queue"}


async def _demo(args: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
    """Run the fast, local-only hackathon demonstration workflow.

    This intentionally accepts loopback targets only.  It gives the model one
    useful tool call that proves the complete Workbench path: health, an
    explicit scope case, a real TCP scan, normalized findings, and a denied
    out-of-scope attempt.
    """
    api = _api()
    target = str(args.get("target", "127.0.0.1")).strip()
    if target not in {"127.0.0.1", "::1"}:
        return {
            "ok": False,
            "status": "rejected",
            "error": "workbench_demo is local-only; target must be 127.0.0.1 or ::1",
        }

    ports = str(args.get("ports", "22,80,8765,9999"))
    health = _health({})
    case = api.create_case(api.CaseCreate(
        name="Hermes Hackathon Demo",
        notes="Local-only demonstration case",
        lab_mode=True,
        scope=[{"kind": "ip", "value": target}],
    ))

    scan = await _portscan({
        "case_id": case["id"],
        "target": target,
        "ports": ports,
    })

    # This is a policy proof, not a network request: scope validation rejects
    # the target before the job can be queued or executed.
    blocked: dict[str, Any]
    try:
        await api.create_job(api.JobCreate(
            case_id=case["id"],
            module="port_scan",
            target="192.0.2.1",
            params={"ports": "80"},
        ))
        blocked = {"status": "unexpectedly_allowed", "target": "192.0.2.1"}
    except Exception as exc:  # FastAPI HTTPException keeps the detail field.
        blocked = {
            "status": "blocked",
            "target": "192.0.2.1",
            "reason": getattr(exc, "detail", str(exc)),
        }

    return {
        "ok": True,
        "demo": "hermes-security-workbench",
        "health": health,
        "case": {**case, "scope": [{"kind": "ip", "value": target}]},
        "scan": scan,
        "out_of_scope_proof": blocked,
        "proof": {
            "real_local_scan": scan.get("status") == "COMPLETED",
            "scope_enforced": blocked.get("status") == "blocked",
        },
    }


def register(ctx) -> None:
    """Register the tools declared by ``plugin.yaml``."""
    ctx.register_tool(
        name="workbench_health",
        toolset=_TOOLSET,
        schema={
            "name": "workbench_health",
            "description": "Check Security Workbench health and list available modules.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        handler=_health,
        description="Check Security Workbench health and available modules.",
    )
    ctx.register_tool(
        name="workbench_case",
        toolset=_TOOLSET,
        schema={
            "name": "workbench_case",
            "description": "List cases or create one with an explicit authorized scope.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["list", "create"]},
                    "name": {"type": "string"},
                    "notes": {"type": "string", "default": ""},
                    "lab_mode": {"type": "boolean", "default": False},
                    "scope": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": {
                                    "type": "string",
                                    "enum": ["ip", "cidr", "hostname", "domain"],
                                },
                                "value": {"type": "string"},
                            },
                            "required": ["kind", "value"],
                            "additionalProperties": False,
                        },
                        "default": [],
                    },
                },
                "required": ["action"],
                "additionalProperties": False,
            },
        },
        handler=_case,
        description="List or create scoped Security Workbench cases.",
    )
    ctx.register_tool(
        name="workbench_job",
        toolset=_TOOLSET,
        schema={
            "name": "workbench_job",
            "description": "List workbench jobs or inspect one job and its findings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["list", "get"]},
                    "case_id": {"type": "string"},
                    "job_id": {"type": "string"},
                },
                "required": ["action"],
                "additionalProperties": False,
            },
        },
        handler=_job,
        description="List or inspect Security Workbench jobs.",
    )
    ctx.register_tool(
        name="workbench_portscan",
        toolset=_TOOLSET,
        schema={
            "name": "workbench_portscan",
            "description": (
                "ACTIVE port scan of one target inside an existing authorized "
                "Workbench case scope. Never use without authorization."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "target": {"type": "string"},
                    "ports": {
                        "type": "string",
                        "description": "Comma-separated ports or ranges.",
                        "default": "22,80,443",
                    },
                },
                "required": ["case_id", "target"],
                "additionalProperties": False,
            },
        },
        handler=_portscan,
        is_async=True,
        description="Run an authorized, scope-enforced active port scan.",
    )
    ctx.register_tool(
        name="workbench_demo",
        toolset=_TOOLSET,
        schema={
            "name": "workbench_demo",
            "description": (
                "Run the fast local-only hackathon demonstration: create a "
                "scoped loopback case, scan it, return normalized findings, "
                "and prove an out-of-scope target is denied."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "enum": ["127.0.0.1", "::1"],
                        "default": "127.0.0.1",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Comma-separated loopback ports.",
                        "default": "22,80,8765,9999",
                    },
                },
                "additionalProperties": False,
            },
        },
        handler=_demo,
        is_async=True,
        description="Run the complete local-only Workbench demo in one tool call.",
    )
