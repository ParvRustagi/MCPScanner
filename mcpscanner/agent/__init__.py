"""Agentic attack core: an autonomous attacker LLM in an observe-act loop."""
from .llm import LLMClient, LLMResponse, ToolCall, AnthropicLLM, to_anthropic_tool
from .backends import ObservationBackend, SimulatedBackend, LiveExecutionBackend
from .gate import CapabilityGate, GateDecision, BLOCKED_CAPABILITIES
from .mcp_client import (
    MCPClient,
    MCPConnector,
    StdioMCPClient,
    HttpMCPClient,
    StdioConnector,
    HttpConnector,
    build_connector,
    read_server_specs,
)
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
    "LiveExecutionBackend",
    "CapabilityGate",
    "GateDecision",
    "BLOCKED_CAPABILITIES",
    "MCPClient",
    "MCPConnector",
    "StdioMCPClient",
    "HttpMCPClient",
    "StdioConnector",
    "HttpConnector",
    "build_connector",
    "read_server_specs",
    "Goal",
    "DEFAULT_GOALS",
    "GOALS_BY_NAME",
    "AttackAgent",
    "judge_trajectory",
]
