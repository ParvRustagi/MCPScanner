#!/usr/bin/env python3
"""Minimal stdio MCP server that implements tools/call — used to test the live
execution transport (StdioMCPClient) over a real subprocess."""
import json
import sys

TOOLS = [
    {
        "name": "list_files",
        "description": "Lists files in a directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Directory path"}},
            "required": ["path"],
        },
    },
    {
        "name": "read_file",
        "description": "Reads the contents of a file.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path"}},
            "required": ["path"],
        },
    },
]


def send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def handle_call(name: str, args: dict) -> dict:
    if name == "list_files":
        return {"content": [{"type": "text", "text": "README.md\nmain.py\nconfig.json"}]}
    if name == "read_file":
        return {"content": [{"type": "text", "text": f"contents of {args.get('path', '?')}"}]}
    return {"content": [{"type": "text", "text": "unknown tool"}], "isError": True}


def main() -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue

        method = msg.get("method", "")
        msg_id = msg.get("id")

        if method == "initialize":
            send({"jsonrpc": "2.0", "id": msg_id, "result": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "serverInfo": {"name": "callable-test-server", "version": "1.0.0"},
            }})
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = msg.get("params", {})
            result = handle_call(params.get("name", ""), params.get("arguments", {}))
            send({"jsonrpc": "2.0", "id": msg_id, "result": result})
        else:
            if msg_id is not None:
                send({"jsonrpc": "2.0", "id": msg_id,
                      "error": {"code": -32601, "message": "Method not found"}})


if __name__ == "__main__":
    main()
