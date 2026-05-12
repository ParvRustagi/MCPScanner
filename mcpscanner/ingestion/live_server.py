"""Ingest tools from a live HTTP/SSE MCP server."""
from __future__ import annotations
import json

import httpx

from .base import BaseIngester
from ..models import ParameterSchema, ToolSchema


class LiveServerIngester(BaseIngester):
    def __init__(self, url: str, server_name: str = "live") -> None:
        self.url = url.rstrip("/")
        self.server_name = server_name

    async def ingest(self) -> list[ToolSchema]:
        raw_tools = await self._fetch_tools()
        return [_tool_from_raw(t, self.server_name) for t in raw_tools]

    async def _fetch_tools(self) -> list[dict]:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Try streamable HTTP transport first (MCP 2025-03-26)
            resp = await client.post(
                self.url,
                json=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    return data["result"].get("tools", [])

            # Fall back to /tools endpoint if present
            resp2 = await client.get(f"{self.url}/tools")
            if resp2.status_code == 200:
                data2 = resp2.json()
                if isinstance(data2, list):
                    return data2
                return data2.get("tools", [])

        raise RuntimeError(f"Could not retrieve tools from {self.url}")


def _tool_from_raw(raw: dict, server: str) -> ToolSchema:
    schema = raw.get("inputSchema", {})
    props = schema.get("properties", {})
    required_set = set(schema.get("required", []))

    params = []
    for param_name, prop in props.items():
        params.append(ParameterSchema(
            name=param_name,
            type=prop.get("type", "string"),
            description=prop.get("description", ""),
            enum=prop.get("enum", []),
            required=param_name in required_set,
            raw=prop,
        ))

    return ToolSchema(
        name=raw.get("name", ""),
        server=server,
        description=raw.get("description", ""),
        parameters=params,
        raw=raw,
    )
