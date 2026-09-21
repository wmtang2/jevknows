"""Smoke test: call the jev-guard MCP server with any MCP client.

Runs three sessions against mcp/scripts/mcp_server.py -- mock-malicious,
mock-clean, and live (needs TYPESAFE_API_KEY) -- and prints each verdict.

Run from the repo root:
    <venv python> mcp/tests/mcp_smoke.py
"""

import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVER = os.path.join(REPO, "mcp", "scripts", "mcp_server.py")


async def run_case(name, mock, calls):
    env = dict(os.environ)
    if mock:
        env["JEV_GUARD_MOCK"] = mock
    params = StdioServerParameters(command=sys.executable, args=[SERVER], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(f"[{name}] tools: {sorted(t.name for t in tools.tools)}")
            for tool_name, args in calls:
                res = await session.call_tool(tool_name, args)
                text = res.content[0].text if res.content else "(empty)"
                print(f"[{name}] {tool_name} -> is_error={res.is_error}")
                print(f"   {text[:200]}")


async def main():
    inj = os.path.join(REPO, "mcp", "tests", "injected.md")
    ben = os.path.join(REPO, "mcp", "tests", "benign.md")
    await run_case("mock-malicious", "malicious", [
        ("check_file", {"path": inj}),
    ])
    await run_case("mock-clean", "clean", [
        ("check_text", {"text": "Install deps with pip install -r requirements.txt"}),
        ("check_file", {"path": ben}),
    ])
    await run_case("live", None, [
        ("check_file", {"path": inj}),
        ("check_url", {"url": "https://example.com"}),
    ])


asyncio.run(main())
