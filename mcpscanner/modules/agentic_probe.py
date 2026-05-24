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
        backend: str = "simulated",
        max_steps: int = 6,
        goals: list[str] | None = None,
        llm: LLMClient | None = None,
    ) -> None:
        self.attacker_model = attacker_model
        self.provider = provider
        self.target = target
        self.backend = backend
        self.max_steps = max_steps
        self._goals = _resolve_goals(goals)
        self._llm = llm  # injectable for tests

    def run(self, schemas: list[ToolSchema]) -> list[Finding]:
        if not schemas:
            return []

        llm = self._llm or AnthropicLLM.from_env(model=self.attacker_model)
        if llm is None:
            return []  # missing key / package — already warned

        if self.backend == "live":
            print("[warn] agentic_probe: live backend is Phase 2 — using simulated backend")

        tools_by_server: dict[str, list[ToolSchema]] = {}
        for t in schemas:
            tools_by_server.setdefault(t.server, []).append(t)

        findings: list[Finding] = []
        for server, server_tools in tools_by_server.items():
            for goal in self._goals:
                # Fresh backend per goal so simulator state doesn't bleed across runs.
                sim = SimulatedBackend(llm, server_tools)
                agent = AttackAgent(llm, server_tools, sim, max_steps=self.max_steps)
                traj = agent.pursue(goal, server)
                result = judge_trajectory(llm, traj)
                if result and result.get("unsafe_behavior_detected"):
                    findings.append(_to_finding(server, goal, traj, result))
        return findings


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
