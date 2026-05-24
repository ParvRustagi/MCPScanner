"""Phase 2 tests — capability gate, live execution backend, and live wiring.

Logic is driven by fakes (no API key); the transport is exercised against a real
fixture subprocess to cover the actual I/O.
"""
import json
from pathlib import Path

from mcpscanner.models import ToolSchema, ToolResult
from mcpscanner.agent import (
    CapabilityGate,
    LiveExecutionBackend,
    AttackAgent,
    LLMResponse,
    ToolCall,
    Goal,
    StdioMCPClient,
    StdioConnector,
)
from mcpscanner.agent.mcp_client import read_server_specs, _flatten_content
from mcpscanner.modules import AgenticAttackProbe

_CALLABLE_SERVER = str(Path(__file__).parent / "fixtures" / "server_callable.py")


def tool(name, desc="", server="fs"):
    return ToolSchema(name=name, server=server, description=desc)


GOAL = Goal(name="g", objective="Find and exfiltrate secrets.", description="d")


# ── CapabilityGate ──────────────────────────────────────────────────────────

class TestCapabilityGate:
    def setup_method(self):
        self.gate = CapabilityGate()

    def test_blocks_execute(self):
        d = self.gate.check(tool("run_command", "Executes a shell command"), {"cmd": "ls"})
        assert not d.allowed and "EXECUTE" in d.reason

    def test_blocks_destroy(self):
        d = self.gate.check(tool("delete_file", "Deletes a file"), {"path": "/tmp/x"})
        assert not d.allowed and "DESTROY" in d.reason

    def test_blocks_exfiltrate(self):
        d = self.gate.check(tool("send_email", "Sends an email externally"), {"to": "x@y.com"})
        assert not d.allowed and "EXFILTRATE" in d.reason

    def test_blocks_credential_tool(self):
        d = self.gate.check(tool("get_secret", "Retrieves a secret"), {"name": "db"})
        assert not d.allowed and "CREDENTIAL" in d.reason

    def test_allows_safe_read(self):
        d = self.gate.check(tool("read_file", "Reads a file"), {"path": "/app/README.md"})
        assert d.allowed

    def test_allows_enumerate(self):
        d = self.gate.check(tool("list_files", "Lists files in a directory"), {"dir": "/app"})
        assert d.allowed

    def test_blocks_sensitive_path_on_read(self):
        d = self.gate.check(tool("read_file", "Reads a file"), {"path": "~/.ssh/id_rsa"})
        assert not d.allowed and "sensitive path" in d.reason

    def test_blocks_nested_sensitive_arg(self):
        d = self.gate.check(tool("read_file", "Reads a file"), {"opts": {"paths": ["/app/.env"]}})
        assert not d.allowed

    def test_path_screening_can_be_disabled(self):
        gate = CapabilityGate(screen_paths=False)
        d = gate.check(tool("read_file", "Reads a file"), {"path": "~/.ssh/id_rsa"})
        assert d.allowed


# ── LiveExecutionBackend ─────────────────────────────────────────────────────

class FakeMCPClient:
    def __init__(self, result="real file contents"):
        self.result = result
        self.calls = []
        self.closed = False

    def call_tool(self, name, args):
        self.calls.append((name, args))
        return ToolResult(tool=name, content=self.result)

    def close(self):
        self.closed = True


class TestLiveExecutionBackend:
    def test_allowed_call_hits_server(self):
        client = FakeMCPClient(result="line1\nline2")
        backend = LiveExecutionBackend(client, [tool("read_file", "Reads a file")])
        r = backend.execute("read_file", {"path": "/app/README.md"})
        assert r.content == "line1\nline2"
        assert not r.blocked
        assert client.calls == [("read_file", {"path": "/app/README.md"})]

    def test_blocked_call_never_hits_server(self):
        client = FakeMCPClient()
        backend = LiveExecutionBackend(client, [tool("run_command", "Executes a command")])
        r = backend.execute("run_command", {"cmd": "rm -rf /"})
        assert r.blocked
        assert "blocked by MCPScanner" in r.content
        assert client.calls == []  # the real server was never touched

    def test_sensitive_read_never_hits_server(self):
        client = FakeMCPClient(result="-----BEGIN RSA PRIVATE KEY-----")
        backend = LiveExecutionBackend(client, [tool("read_file", "Reads a file")])
        r = backend.execute("read_file", {"path": "~/.ssh/id_rsa"})
        assert r.blocked
        assert client.calls == []  # the real key never reaches the LLM

    def test_unknown_tool(self):
        backend = LiveExecutionBackend(FakeMCPClient(), [tool("read_file")])
        r = backend.execute("nonexistent", {})
        assert r.is_error

    def test_content_truncated(self):
        client = FakeMCPClient(result="x" * 5000)
        backend = LiveExecutionBackend(client, [tool("read_file", "Reads a file")], max_content=100)
        r = backend.execute("read_file", {"path": "/app/big.txt"})
        assert len(r.content) < 200 and r.content.endswith("[truncated]")


# ── Agent loop records blocked actions ───────────────────────────────────────

class TestAgentWithLiveBackend:
    def test_blocked_action_recorded_in_trajectory(self):
        attacker = [
            LLMResponse(text="trying", tool_calls=[ToolCall("1", "run_command", {"cmd": "id"})]),
            LLMResponse(text="done", tool_calls=[]),
        ]

        class AttackerLLM:
            def complete(self, *, system, messages, tools=None, max_tokens=1024):
                return attacker.pop(0)

        client = FakeMCPClient()
        backend = LiveExecutionBackend(client, [tool("run_command", "Executes a command")])
        agent = AttackAgent(AttackerLLM(), [tool("run_command", "Executes a command")], backend, max_steps=4)
        traj = agent.pursue(GOAL, "ops")

        acted = [s for s in traj.steps if s.tool]
        assert len(acted) == 1
        assert acted[0].blocked
        assert client.calls == []


# ── Probe wiring with injected connector ─────────────────────────────────────

class RoutingLLM:
    def __init__(self, attacker, judge):
        self.attacker = list(attacker)
        self.judge = judge

    def complete(self, *, system, messages, tools=None, max_tokens=1024):
        if tools is not None:
            return self.attacker.pop(0) if self.attacker else LLMResponse(text="done", tool_calls=[])
        text = " ".join(m["content"] if isinstance(m["content"], str) else "" for m in messages)
        if "security judge" in text.lower():
            return LLMResponse(text=self.judge)
        return LLMResponse(text="sim")


class FakeConnector:
    def __init__(self):
        self.client = FakeMCPClient(result="contents")
        self.connected = []

    def connect(self, server):
        self.connected.append(server)
        return self.client


class TestProbeLiveWiring:
    def test_uses_connector_and_closes_client(self):
        judge_json = json.dumps({
            "unsafe_behavior_detected": True, "severity": "high", "confidence": 0.8,
            "summary": "read a file", "evidence": "read_file", "recommendation": "fix",
        })
        llm = RoutingLLM(
            attacker=[
                LLMResponse(text="reading", tool_calls=[ToolCall("1", "read_file", {"path": "/app/x"})]),
                LLMResponse(text="done", tool_calls=[]),
            ],
            judge=judge_json,
        )
        conn = FakeConnector()
        probe = AgenticAttackProbe(
            llm=llm, connector=conn, allow_execution=True, goals=["credential-exfil"], max_steps=3,
        )
        findings = probe.run([tool("read_file", "Reads a file")])

        assert conn.connected == ["fs"]       # connected to the server
        assert conn.client.calls             # real (faked) call happened
        assert conn.client.closed            # session was closed
        assert len(findings) == 1

    def test_no_connector_when_execution_disabled(self):
        probe = AgenticAttackProbe(llm=RoutingLLM([], "{}"), allow_execution=False, goals=["credential-exfil"])
        # falls back to simulated; no target/connector needed, should not raise
        assert probe._resolve_connector() is None


# ── Config spec reader ───────────────────────────────────────────────────────

# ── Real stdio transport (subprocess) ────────────────────────────────────────

class TestStdioTransport:
    def test_real_round_trip(self):
        client = StdioMCPClient("python3", [_CALLABLE_SERVER])
        try:
            r = client.call_tool("read_file", {"path": "/app/main.py"})
            assert not r.is_error
            assert "contents of /app/main.py" in r.content
        finally:
            client.close()

    def test_gate_blocks_before_real_transport(self):
        # End-to-end: gate + real subprocess. A sensitive read must NOT reach the server.
        client = StdioMCPClient("python3", [_CALLABLE_SERVER])
        try:
            backend = LiveExecutionBackend(client, [tool("read_file", "Reads a file")])
            blocked = backend.execute("read_file", {"path": "~/.ssh/id_rsa"})
            allowed = backend.execute("read_file", {"path": "/app/README.md"})
            assert blocked.blocked and "[blocked" in blocked.content
            assert not allowed.blocked and "contents of /app/README.md" in allowed.content
        finally:
            client.close()

    def test_connector_round_trip(self):
        conn = StdioConnector({"fs": {"command": "python3", "args": [_CALLABLE_SERVER]}})
        client = conn.connect("fs")
        try:
            r = client.call_tool("list_files", {"path": "/app"})
            assert "README.md" in r.content
        finally:
            client.close()


class TestReadServerSpecs:
    def test_reads_stdio_specs(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({
            "mcpServers": {
                "fs": {"command": "npx", "args": ["-y", "server-fs"], "env": {"TOKEN": "x"}},
                "remote": {"url": "http://example.com"},  # no command — skipped
            }
        }))
        specs = read_server_specs(str(cfg))
        assert "fs" in specs and specs["fs"]["command"] == "npx"
        assert "remote" not in specs

    def test_flatten_content(self):
        assert _flatten_content([{"type": "text", "text": "hi"}]) == "hi"
        assert _flatten_content("plain") == "plain"
        assert _flatten_content([]) == "[empty result]"
