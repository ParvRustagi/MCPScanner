"""Persistent MCP client sessions that support tools/call.

The ingesters do a one-shot tools/list and close. Live execution needs a session
that stays open across the whole agent loop so the agent can actually call tools.

Synchronous on purpose: the agent loop is synchronous, and MCP stdio is just
line-delimited JSON-RPC, so a blocking client is simpler and more robust than
threading an event loop through everything.
"""
from __future__ import annotations
import json
import os
import queue
import subprocess
import threading
from pathlib import Path
from typing import Any, Protocol

import httpx

from ..models import ToolResult

_PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "mcpscanner", "version": "0.1.0"}


class MCPClient(Protocol):
    def call_tool(self, name: str, args: dict) -> ToolResult:
        ...

    def close(self) -> None:
        ...


# ── stdio transport ────────────────────────────────────────────────────────────

class StdioMCPClient:
    """Talks to a stdio MCP server over a persistent subprocess."""

    def __init__(self, command: str, args: list[str], env: dict | None = None, timeout: float = 20.0) -> None:
        self.timeout = timeout
        self._id = 0
        self._proc = subprocess.Popen(
            [command, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={**os.environ, **(env or {})},
            text=True,
            bufsize=1,
        )
        self._inbox: "queue.Queue[dict]" = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._initialize()

    def _read_loop(self) -> None:
        assert self._proc.stdout
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._inbox.put(json.loads(line))
            except json.JSONDecodeError:
                continue

    def _send(self, msg: dict) -> None:
        assert self._proc.stdin
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()

    def _request(self, method: str, params: dict) -> dict:
        self._id += 1
        req_id = self._id
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        # Drain until we see the response with our id (skip notifications/others).
        while True:
            try:
                msg = self._inbox.get(timeout=self.timeout)
            except queue.Empty as e:
                raise TimeoutError(f"MCP server did not respond to {method} within {self.timeout}s") from e
            if msg.get("id") == req_id:
                return msg

    def _initialize(self) -> None:
        resp = self._request("initialize", {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": _CLIENT_INFO,
        })
        if "error" in resp:
            raise RuntimeError(f"initialize error: {resp['error']}")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def call_tool(self, name: str, args: dict) -> ToolResult:
        try:
            resp = self._request("tools/call", {"name": name, "arguments": args})
        except Exception as e:
            return ToolResult(tool=name, content=f"[transport error: {e}]", is_error=True)
        if "error" in resp:
            return ToolResult(tool=name, content=f"[server error: {resp['error']}]", is_error=True)
        result = resp.get("result", {})
        return ToolResult(
            tool=name,
            content=_flatten_content(result.get("content", [])),
            is_error=bool(result.get("isError", False)),
        )

    def close(self) -> None:
        try:
            self._proc.terminate()
            self._proc.wait(timeout=3.0)
        except Exception:
            self._proc.kill()


# ── HTTP transport ───────────────────────────────────────────────────────────

class HttpMCPClient:
    """Talks to an HTTP/streamable MCP server via JSON-RPC POSTs."""

    def __init__(self, url: str, timeout: float = 20.0) -> None:
        self.url = url.rstrip("/")
        self._id = 1
        self._client = httpx.Client(timeout=timeout)

    def call_tool(self, name: str, args: dict) -> ToolResult:
        self._id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        }
        try:
            resp = self._client.post(
                self.url,
                json=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
        except Exception as e:
            return ToolResult(tool=name, content=f"[transport error: {e}]", is_error=True)
        if resp.status_code != 200:
            return ToolResult(tool=name, content=f"[http {resp.status_code}]", is_error=True)
        data = resp.json()
        if "error" in data:
            return ToolResult(tool=name, content=f"[server error: {data['error']}]", is_error=True)
        result = data.get("result", {})
        return ToolResult(
            tool=name,
            content=_flatten_content(result.get("content", [])),
            is_error=bool(result.get("isError", False)),
        )

    def close(self) -> None:
        self._client.close()


def _flatten_content(content: Any) -> str:
    """MCP tool results return a list of content blocks; flatten text blocks to a string."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content)
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict):
            parts.append(block.get("text", "") or json.dumps(block))
        else:
            parts.append(str(block))
    return "\n".join(p for p in parts if p) or "[empty result]"


# ── Connectors ─────────────────────────────────────────────────────────────────

class MCPConnector(Protocol):
    def connect(self, server: str) -> MCPClient:
        ...


class HttpConnector:
    def __init__(self, url: str) -> None:
        self.url = url

    def connect(self, server: str) -> MCPClient:
        return HttpMCPClient(self.url)


class StdioConnector:
    """Spawns a stdio server from launch specs keyed by server name."""

    def __init__(self, specs: dict[str, dict]) -> None:
        self.specs = specs

    def connect(self, server: str) -> MCPClient:
        spec = self.specs.get(server)
        if not spec:
            raise ValueError(f"No launch spec for server '{server}'")
        return StdioMCPClient(spec["command"], spec.get("args", []), spec.get("env", {}))


def build_connector(target: str) -> MCPConnector:
    """Build the right connector for a scan target (HTTP URL or config file)."""
    if target.startswith("http://") or target.startswith("https://"):
        return HttpConnector(target)
    return StdioConnector(read_server_specs(target))


def read_server_specs(config_path: str) -> dict[str, dict]:
    """Read {server_name: {command, args, env}} launch specs from a config file."""
    raw = json.loads(Path(config_path).expanduser().resolve().read_text())
    servers = raw.get("mcpServers") or raw.get("mcp", {}).get("servers", {})
    specs: dict[str, dict] = {}
    for name, cfg in servers.items():
        if cfg.get("command"):
            specs[name] = {
                "command": cfg["command"],
                "args": cfg.get("args", []),
                "env": cfg.get("env", {}),
            }
    return specs
