"""Ingest MCP servers from Claude Desktop / Cursor / Windsurf config JSON files."""
from __future__ import annotations
import asyncio
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .base import BaseIngester
from ..models import ParameterSchema, ToolSchema


class ConfigFileIngester(BaseIngester):
    def __init__(self, config_path: str) -> None:
        self.config_path = Path(config_path).expanduser().resolve()

    async def ingest(self) -> list[ToolSchema]:
        raw = json.loads(self.config_path.read_text())
        servers: dict[str, Any] = (
            raw.get("mcpServers") or raw.get("mcp", {}).get("servers", {})
        )
        if not servers:
            raise ValueError(f"No MCP servers found in {self.config_path}")

        tasks = [self._ingest_server(name, cfg) for name, cfg in servers.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        tools: list[ToolSchema] = []
        for name, result in zip(servers, results):
            if isinstance(result, Exception):
                print(f"  [warn] Could not connect to server '{name}': {result}")
            else:
                tools.extend(result)
        return tools

    async def _ingest_server(self, server_name: str, cfg: dict) -> list[ToolSchema]:
        command = cfg.get("command", "")
        args = cfg.get("args", [])
        env_extra = cfg.get("env", {})

        env = {**os.environ, **env_extra}
        cmd = [command, *args]

        # Infer declared permissions from env vars present
        permissions = _infer_permissions(env_extra)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )

        try:
            raw_tools = await asyncio.wait_for(
                _mcp_list_tools(proc), timeout=15.0
            )
        finally:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except Exception:
                proc.kill()

        return [_tool_from_raw(t, server_name, permissions) for t in raw_tools]


async def _mcp_list_tools(proc: asyncio.subprocess.Process) -> list[dict]:
    assert proc.stdin and proc.stdout

    async def send(msg: dict) -> None:
        line = json.dumps(msg) + "\n"
        proc.stdin.write(line.encode())
        await proc.stdin.drain()

    async def recv() -> dict:
        while True:
            line = await proc.stdout.readline()
            if not line:
                raise ConnectionError("Server closed stdout")
            line = line.strip()
            if not line:
                continue
            return json.loads(line)

    await send({
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcpscanner", "version": "0.1.0"},
        },
    })

    resp = await recv()
    if "error" in resp:
        raise RuntimeError(f"initialize error: {resp['error']}")

    await send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    await send({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    resp = await recv()
    if "error" in resp:
        raise RuntimeError(f"tools/list error: {resp['error']}")

    return resp.get("result", {}).get("tools", [])


def _tool_from_raw(raw: dict, server: str, permissions: list[str]) -> ToolSchema:
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
        permissions=permissions,
        raw=raw,
    )


_PERMISSION_ENV_MAP = {
    "GITHUB_TOKEN": "github",
    "GITHUB_PERSONAL_ACCESS_TOKEN": "github",
    "AWS_ACCESS_KEY_ID": "aws",
    "AWS_SECRET_ACCESS_KEY": "aws",
    "GOOGLE_API_KEY": "google",
    "OPENAI_API_KEY": "openai",
    "SLACK_TOKEN": "slack",
    "SLACK_BOT_TOKEN": "slack",
    "DATABASE_URL": "database",
    "POSTGRES_URL": "database",
    "MYSQL_URL": "database",
    "SMTP_HOST": "email",
    "SENDGRID_API_KEY": "email",
    "TWILIO_AUTH_TOKEN": "sms",
    "STRIPE_SECRET_KEY": "payments",
    "DOCKER_HOST": "docker",
}


def _infer_permissions(env: dict) -> list[str]:
    perms = set()
    for key in env:
        perm = _PERMISSION_ENV_MAP.get(key.upper())
        if perm:
            perms.add(perm)
    return sorted(perms)
