"""Root plugin registration contract tests."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[2]


class RecordingContext:
    def __init__(self) -> None:
        self.tools: list[dict] = []

    def register_tool(self, **kwargs) -> None:
        self.tools.append(kwargs)


def _load_root_plugin():
    module_name = "hermes_plugins.hermes_security_workbench_registration_test"
    spec = importlib.util.spec_from_file_location(
        module_name,
        PLUGIN_ROOT / "__init__.py",
        submodule_search_locations=[str(PLUGIN_ROOT)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = module_name
    module.__path__ = [str(PLUGIN_ROOT)]
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop(module_name, None)


def test_registers_declared_tools_and_marks_only_portscan_async():
    plugin = _load_root_plugin()
    context = RecordingContext()

    plugin.register(context)

    by_name = {tool["name"]: tool for tool in context.tools}
    assert set(by_name) == {
        "workbench_health",
        "workbench_case",
        "workbench_job",
        "workbench_portscan",
    }
    assert by_name["workbench_portscan"]["is_async"] is True
    assert all(
        tool.get("is_async", False) is False
        for name, tool in by_name.items()
        if name != "workbench_portscan"
    )
