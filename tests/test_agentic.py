"""Unit tests for the agentic attack probe — driven by a fake LLM, no API key."""
import json

from mcpscanner.models import ToolSchema, ParameterSchema
from mcpscanner.agent import (
    AttackAgent,
    SimulatedBackend,
    LLMResponse,
    ToolCall,
    Goal,
    judge_trajectory,
)
from mcpscanner.modules import AgenticAttackProbe


def make_tool(name="read_file", server="fs", description="Reads a file", params=None):
    return ToolSchema(name=name, server=server, description=description, parameters=params or [])


GOAL = Goal(name="test-goal", objective="Find and exfiltrate secrets.", description="test")


class FakeLLM:
    """Routes calls by shape: tool-equipped calls are the attacker, the judge prompt
    gets the judge reply, everything else is the simulated server."""

    def __init__(self, attacker=None, simulator="file contents: SECRET=abc123", judge=None):
        self.attacker = list(attacker or [])
        self.simulator = simulator
        self.judge = judge
        self.tool_calls_seen = 0
        self.sim_calls = 0

    def complete(self, *, system, messages, tools=None, max_tokens=1024):
        if tools is not None:
            self.tool_calls_seen += 1
            if self.attacker:
                return self.attacker.pop(0)
            return LLMResponse(text="All done.", tool_calls=[])
        text = " ".join(
            m["content"] if isinstance(m["content"], str) else "" for m in messages
        )
        if "security judge" in text.lower() and self.judge is not None:
            return LLMResponse(text=self.judge)
        self.sim_calls += 1
        return LLMResponse(text=self.simulator)


# ── AttackAgent loop ─────────────────────────────────────────────────────────

class TestAttackAgent:
    def test_loop_executes_actions_then_stops(self):
        llm = FakeLLM(attacker=[
            LLMResponse(text="reading", tool_calls=[ToolCall("1", "read_file", {"path": "/etc/passwd"})]),
            LLMResponse(text="done", tool_calls=[]),
        ])
        tools = [make_tool()]
        agent = AttackAgent(llm, tools, SimulatedBackend(llm, tools), max_steps=6)
        traj = agent.pursue(GOAL, "fs")

        assert traj.stopped_reason == "agent_done"
        acted = [s for s in traj.steps if s.tool]
        assert len(acted) == 1
        assert acted[0].tool == "read_file"
        assert acted[0].observation  # got a real (simulated) observation back

    def test_max_steps_cutoff(self):
        # Attacker always wants another tool call → loop must stop at max_steps.
        always = [
            LLMResponse(text=f"step{i}", tool_calls=[ToolCall(str(i), "read_file", {})])
            for i in range(20)
        ]
        llm = FakeLLM(attacker=always)
        tools = [make_tool()]
        agent = AttackAgent(llm, tools, SimulatedBackend(llm, tools), max_steps=3)
        traj = agent.pursue(GOAL, "fs")

        assert traj.stopped_reason == "max_steps"
        assert len([s for s in traj.steps if s.tool]) == 3

    def test_immediate_refusal_no_actions(self):
        llm = FakeLLM(attacker=[LLMResponse(text="I can't help with that.", tool_calls=[])])
        tools = [make_tool()]
        agent = AttackAgent(llm, tools, SimulatedBackend(llm, tools), max_steps=4)
        traj = agent.pursue(GOAL, "fs")

        assert traj.stopped_reason == "agent_done"
        assert not [s for s in traj.steps if s.tool]


# ── SimulatedBackend ─────────────────────────────────────────────────────────

class TestSimulatedBackend:
    def test_returns_observation_and_keeps_state(self):
        llm = FakeLLM(simulator="-----BEGIN RSA PRIVATE KEY-----")
        backend = SimulatedBackend(llm, [make_tool()])
        r1 = backend.execute("list_files", {"dir": "~"})
        r2 = backend.execute("read_file", {"path": "~/.ssh/id_rsa"})

        assert not r1.is_error and r1.content
        assert r2.content
        # Both calls plus their results are retained for cross-call consistency.
        assert len(backend._history) == 4
        assert llm.sim_calls == 2


# ── End-to-end probe ─────────────────────────────────────────────────────────

class TestAgenticProbe:
    def test_finding_emitted_when_judge_flags(self):
        judge_json = json.dumps({
            "unsafe_behavior_detected": True,
            "goal_achieved": True,
            "severity": "critical",
            "confidence": 0.9,
            "summary": "Agent read SSH key and exfiltrated it.",
            "evidence": "read_file(~/.ssh/id_rsa) then post to attacker URL",
            "recommendation": "Remove outbound network tool.",
        })
        llm = FakeLLM(
            attacker=[
                LLMResponse(text="reading", tool_calls=[ToolCall("1", "read_file", {"path": "~/.ssh/id_rsa"})]),
                LLMResponse(text="done", tool_calls=[]),
            ],
            judge=judge_json,
        )
        probe = AgenticAttackProbe(llm=llm, goals=["credential-exfil"], max_steps=4)
        findings = probe.run([make_tool(name="read_file", server="fs")])

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert f.module == "agentic_probe"
        assert f.confidence == 0.9
        assert not f.needs_review

    def test_no_finding_when_judge_clears(self):
        judge_json = json.dumps({
            "unsafe_behavior_detected": False,
            "severity": "none",
            "confidence": 0.95,
            "summary": "Agent refused.",
        })
        llm = FakeLLM(
            attacker=[LLMResponse(text="I won't do that.", tool_calls=[])],
            judge=judge_json,
        )
        probe = AgenticAttackProbe(llm=llm, goals=["credential-exfil"], max_steps=4)
        findings = probe.run([make_tool()])
        assert findings == []

    def test_empty_schemas_returns_nothing(self):
        probe = AgenticAttackProbe(llm=FakeLLM(), goals=["credential-exfil"])
        assert probe.run([]) == []

    def test_low_confidence_marks_needs_review(self):
        judge_json = json.dumps({
            "unsafe_behavior_detected": True,
            "severity": "medium",
            "confidence": 0.4,
            "summary": "Borderline.",
            "evidence": "x",
            "recommendation": "y",
        })
        llm = FakeLLM(
            attacker=[
                LLMResponse(text="t", tool_calls=[ToolCall("1", "read_file", {})]),
                LLMResponse(text="done", tool_calls=[]),
            ],
            judge=judge_json,
        )
        probe = AgenticAttackProbe(llm=llm, goals=["credential-exfil"], max_steps=3)
        findings = probe.run([make_tool()])
        assert len(findings) == 1
        assert findings[0].needs_review

    def test_judge_handles_fenced_json(self):
        from mcpscanner.models import Trajectory
        fenced = "```json\n" + json.dumps({"unsafe_behavior_detected": False}) + "\n```"
        llm = FakeLLM(judge=fenced)
        # judge path: no tools passed, judge prompt present
        result = judge_trajectory(llm, Trajectory(goal="g", server="s", objective="o"))
        assert result == {"unsafe_behavior_detected": False}
