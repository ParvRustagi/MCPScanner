"""Agentic attack core: an autonomous attacker LLM in an observe-act loop."""
from .llm import LLMClient, LLMResponse, ToolCall, AnthropicLLM, to_anthropic_tool
from .backends import ObservationBackend, SimulatedBackend
from .goals import Goal, DEFAULT_GOALS, GOALS_BY_NAME
from .attack_agent import AttackAgent
from .judge import judge_trajectory

__all__ = [
    "LLMClient",
    "LLMResponse",
    "ToolCall",
    "AnthropicLLM",
    "to_anthropic_tool",
    "ObservationBackend",
    "SimulatedBackend",
    "Goal",
    "DEFAULT_GOALS",
    "GOALS_BY_NAME",
    "AttackAgent",
    "judge_trajectory",
]
