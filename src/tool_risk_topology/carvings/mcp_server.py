"""Expose a carving as a runnable MCP server (stdio transport).

    python -m tool_risk_topology.carvings.mcp_server --carving C

Each carving's tools are advertised with their JSON-schema parameters; a
``call_tool`` request dispatches to the shared backend. ``smoke`` starts the
server as a subprocess and does an MCP handshake + ``list_tools`` round-trip to
prove it runs (no services required — listing tools never touches the backend).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import List

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from .backend import CapabilityBackend
from .base import CarvingServer
from .registry import CARVING_IDS, build_carving


def tool_specs(carving: CarvingServer) -> List[types.Tool]:
    return [
        types.Tool(
            name=t.name,
            description=t.description,
            inputSchema=t.json_schema()["parameters"],
        )
        for t in carving.tools
    ]


def build_server(carving_id: str, backend: CapabilityBackend = None) -> Server:
    carving = build_carving(carving_id, backend or CapabilityBackend())
    server = Server(f"trt-carving-{carving_id}")

    @server.list_tools()
    async def list_tools() -> List[types.Tool]:
        return tool_specs(carving)

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> List[types.TextContent]:
        res = carving.call(name, **(arguments or {}))
        text = res.output if res.ok else f"ERROR: {res.error}"
        return [types.TextContent(type="text", text=text)]

    return server


async def _serve(carving_id: str) -> None:
    server = build_server(carving_id)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


async def smoke(carving_id: str = "C") -> List[str]:
    """Spawn this module as an MCP server and list its tools over stdio."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "tool_risk_topology.carvings.mcp_server", "--carving", carving_id],
        # inherit env (PYTHONPATH, service config) — the SDK default is minimal
        env=dict(os.environ),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            resp = await session.list_tools()
            return [t.name for t in resp.tools]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="trt-carving-mcp")
    p.add_argument("--carving", choices=CARVING_IDS, default="C")
    p.add_argument("--smoke", action="store_true", help="handshake + list_tools, then exit")
    args = p.parse_args(argv)

    if args.smoke:
        names = asyncio.run(smoke(args.carving))
        print(f"carving {args.carving} MCP server tools: {names}")
        return 0

    asyncio.run(_serve(args.carving))
    return 0


if __name__ == "__main__":
    sys.exit(main())
