"""Protocol-agnostic carving abstractions.

A :class:`CarvingServer` is an ordered set of :class:`CarvingTool` over a shared
:class:`~tool_risk_topology.carvings.backend.CapabilityBackend`. Each tool
declares typed params plus the ``In``/``Out`` capability labels that must match
its E1 schema (``data/interfaces/{A,B,C}.yaml``). The abstraction is transport-
neutral: the same tools are exercised in-process (tests, the benign battery),
served over MCP (``mcp_server``), or wrapped as inspect tools (E4/E6).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Tuple


@dataclass
class ToolResult:
    ok: bool
    output: str = ""
    error: str = ""
    data: Any = None

    def to_dict(self) -> dict:
        return {"ok": self.ok, "output": self.output, "error": self.error, "data": self.data}


@dataclass
class ToolParam:
    name: str
    type: str = "string"  # JSON-schema-ish: string | integer | number | boolean
    description: str = ""
    required: bool = True


@dataclass
class CarvingTool:
    name: str
    description: str
    params: List[ToolParam]
    handler: Callable[..., ToolResult]
    in_labels: Tuple[str, ...]
    out_labels: Tuple[str, ...]
    chokepoint: bool = False

    def json_schema(self) -> dict:
        props = {}
        required = []
        for p in self.params:
            props[p.name] = {"type": p.type, "description": p.description}
            if p.required:
                required.append(p.name)
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {"type": "object", "properties": props, "required": required},
        }


class CarvingServer:
    def __init__(self, carving_id: str, label: str, tools: List[CarvingTool]):
        self.id = carving_id
        self.label = label
        self.tools = tools
        self._by_name = {t.name: t for t in tools}

    def tool(self, name: str) -> CarvingTool:
        if name not in self._by_name:
            raise KeyError(f"{self.id}: no such tool {name!r}")
        return self._by_name[name]

    def call(self, tool_name: str, **kwargs) -> ToolResult:
        return self.tool(tool_name).handler(**kwargs)

    def list_tools(self) -> List[dict]:
        return [t.json_schema() for t in self.tools]

    @property
    def chokepoint_tools(self) -> List[CarvingTool]:
        return [t for t in self.tools if t.chokepoint]

    def capability_schema(self) -> dict:
        """The In/Out topology, for cross-checking against the E1 YAML schema."""
        return {
            "id": self.id,
            "tools": [
                {
                    "name": t.name,
                    "in": list(t.in_labels),
                    "out": list(t.out_labels),
                    "chokepoint": t.chokepoint,
                }
                for t in self.tools
            ],
        }
