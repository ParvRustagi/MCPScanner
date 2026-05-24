from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class ParameterSchema:
    name: str
    type: str = "string"
    description: str = ""
    enum: list[str] = field(default_factory=list)
    required: bool = False
    raw: dict = field(default_factory=dict)


@dataclass
class ToolSchema:
    name: str
    server: str
    description: str = ""
    parameters: list[ParameterSchema] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class ToolResult:
    """The observation returned to the agent after a tool call (simulated or real)."""
    tool: str
    content: str
    is_error: bool = False
    blocked: bool = False  # True if a safety gate refused to run the call (live backend)


@dataclass
class AgentStep:
    """A single observe-act step in an attack trajectory."""
    index: int
    thought: str  # assistant text accompanying the action this step
    tool: str  # tool the agent called this step ("" if it produced only text)
    args: dict = field(default_factory=dict)
    observation: str = ""  # tool result content the agent observed
    blocked: bool = False


@dataclass
class Trajectory:
    """The full record of one agent's attempt to pursue a goal against a server."""
    goal: str
    server: str
    objective: str = ""
    steps: list[AgentStep] = field(default_factory=list)
    stopped_reason: str = ""  # "agent_done" | "max_steps" | "error"

    def transcript(self) -> str:
        lines = [f"Goal: {self.goal} — {self.objective}"]
        for s in self.steps:
            if s.thought:
                lines.append(f"Step {s.index} — Agent: {s.thought[:300]}")
            if s.tool:
                tag = " [BLOCKED]" if s.blocked else ""
                lines.append(f"Step {s.index} — Action: {s.tool}({s.args}){tag}")
                lines.append(f"Step {s.index} — Observation: {s.observation[:400]}")
        lines.append(f"Stopped: {self.stopped_reason}")
        return "\n".join(lines)


@dataclass
class Finding:
    severity: str  # critical / high / medium / low
    module: str
    tool_name: str
    server: str
    title: str
    detail: str
    evidence: str = ""
    recommendation: str = ""
    confidence: Optional[float] = None
    needs_review: bool = False

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "module": self.module,
            "tool_name": self.tool_name,
            "server": self.server,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "needs_review": self.needs_review,
        }
