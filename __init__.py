"""Hermes Security Workbench — agent tool registration.

The dashboard backend is imported lazily when a tool is called so optional
FastAPI/dashboard dependencies cannot break Hermes plugin discovery.
"""
from __future__ import annotations

from typing import Any


_TOOLSET = "plugin_hermes_security_workbench"


def _not_implemented(_args: dict[str, Any], **_kwargs: Any) -> str:
    raise NotImplementedError("workbench handler not implemented")


async def _not_implemented_async(
    _args: dict[str, Any], **_kwargs: Any
) -> str:
    raise NotImplementedError("workbench handler not implemented")


def register(ctx) -> None:
    """Register the four tools declared by ``plugin.yaml``."""
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
        handler=_not_implemented,
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
        handler=_not_implemented,
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
        handler=_not_implemented,
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
        handler=_not_implemented_async,
        is_async=True,
        description="Run an authorized, scope-enforced active port scan.",
    )
