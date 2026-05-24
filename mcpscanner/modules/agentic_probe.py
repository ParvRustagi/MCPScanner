"""Agentic attack probe — an autonomous attacker LLM, not a scripted prompt list.

For each goal, an AttackAgent is given an objective and the server's tools, then
runs its own observe-act loop against an observation backend. A judge LLM scores
the resulting trajectory.

Phase 1 uses the SimulatedBackend (safe by default — a simulator LLM role-plays the
server, nothing real is executed). The "live" backend (real gated execution) is
Phase 2; requesting it here is a no-op for now.
"""
from __future__ import annotations

from .base import BaseAttackModule
from ..models import Finding, ToolSchema
from ..agent import (
    AttackAgent,
    AnthropicLLM,
    LLMClient,
    SimulatedBackend,
    LiveExecutionBackend,
    CapabilityGate,
    MCPConnector,
    build_connector,
    DEFAULT_GOALS,
    GOALS_BY_NAME,
    Goal,
    judge_trajectory,
)

CONFIDENCE_THRESHOLD = 0.6


class AgenticAttackProbe(BaseAttackModule):
    name = "agentic_probe"

    def __init__(
        self,
        attacker_model: str = "claude-sonnet-4-6",
        provider: str = "anthropic",
        target: str | None = None,
        allow_execution: bool = False,
        max_steps: int = 6,
        goals: list[str] | None = None,
        llm: LLMClient | None = None,
        connector: MCPConnector | None = None,
    ) -> None:
        self.attacker_model = attacker_model
        self.provider = provider
        self.target = target
        self.allow_execution = allow_execution
        self.max_steps = max_steps
        self._goals = _resolve_goals(goals)
        self._llm = llm  # injectable for tests
        self._connector = connector  # injectable for tests

    def run(self, schemas: list[ToolSchema]) -> list[Finding]:
        if not schemas:
            return []

        llm = self._llm or AnthropicLLM.from_env(model=self.attacker_model)
        if llm is None:
            return []  # missing key / package — already warned

        connector = self._resolve_connector()  # None unless live execution is on

        tools_by_server: dict[str, list[ToolSchema]] = {}
        for t in schemas:
            tools_by_server.setdefault(t.server, []).append(t)

        findings: list[Finding] = []
        for server, server_tools in tools_by_server.items():
            for goal in self._goals:
                backend, client = self._make_backend(llm, connector, server, server_tools)
                try:
                    agent = AttackAgent(llm, server_tools, backend, max_steps=self.max_steps)
                    traj = agent.pursue(goal, server)
                finally:
                    if client is not None:
                        client.close()
                result = judge_trajectory(llm, traj)
                if result and result.get("unsafe_behavior_detected"):
                    findings.append(_to_finding(server, goal, traj, result))
        return findings

    def _resolve_connector(self) -> MCPConnector | None:
        if not self.allow_execution:
            return None
        if self._connector is not None:
            return self._connector
        if not self.target:
            print("[warn] agentic_probe: --allow-execution needs a target — using simulated backend")
            return None
        try:
            return build_connector(self.target)
        except Exception as e:
            print(f"[warn] agentic_probe: could not build live connector ({e}) — using simulated backend")
            return None

    def _make_backend(self, llm, connector, server, server_tools):
        """Returns (backend, client). client is non-None only for live execution
        (so the caller closes the session). Falls back to simulated on connect failure."""
        if connector is not None:
            try:
                client = connector.connect(server)
                return LiveExecutionBackend(client, server_tools, CapabilityGate()), client
            except Exception as e:
                print(f"[warn] agentic_probe: live connect to '{server}' failed ({e}) — simulating")
        # Fresh simulator per goal so its state doesn't bleed across runs.
        return SimulatedBackend(llm, server_tools), None


def _resolve_goals(names: list[str] | None) -> list[Goal]:
    if not names:
        return DEFAULT_GOALS
    resolved = [GOALS_BY_NAME[n] for n in names if n in GOALS_BY_NAME]
    return resolved or DEFAULT_GOALS


def _to_finding(server: str, goal: Goal, traj, result: dict) -> Finding:
    confidence = result.get("confidence", 0.0)
    actions = [s.tool for s in traj.steps if s.tool]
    return Finding(
        severity=result.get("severity", "high"),
        module="agentic_probe",
        tool_name="(agentic)",
        server=server,
        title=f"Agentic attack succeeded: {goal.name} on {server}",
        detail=result.get("summary", ""),
        evidence=(
            f"Goal: {goal.description}\n"
            f"Steps taken: {len(traj.steps)} ({' → '.join(actions) or 'none'})\n"
            f"Stopped: {traj.stopped_reason}\n"
            f"Goal achieved: {result.get('goal_achieved', False)}\n"
            f"Key action: {result.get('evidence', '')}"
        ),
        recommendation=result.get("recommendation", ""),
        confidence=confidence,
        needs_review=confidence < CONFIDENCE_THRESHOLD,
    )
