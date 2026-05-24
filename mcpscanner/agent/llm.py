"""Provider-neutral LLM interface for the agent loop.

The agent, simulated backend, and judge all talk to an `LLMClient`. Keeping this
abstraction thin means tests can inject a fake that returns scripted responses
with no API key, and real providers translate their own response shape into
`LLMResponse` here.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..models import ToolSchema


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict = field(default_factory=dict)


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMClient(Protocol):
    def complete(
        self,
        *,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        ...


class AnthropicLLM:
    """Adapts the Anthropic Messages API to the LLMClient interface."""

    def __init__(self, client: Any, model: str = "claude-sonnet-4-6") -> None:
        self._client = client
        self.model = model

    @classmethod
    def from_env(cls, model: str = "claude-sonnet-4-6") -> "AnthropicLLM | None":
        """Build from ANTHROPIC_API_KEY, mirroring the skip-on-missing pattern
        used by the other dynamic modules. Returns None if unavailable."""
        try:
            import anthropic
        except ImportError:
            print("[warn] anthropic package not installed — skipping agentic probe")
            return None
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            print("[warn] ANTHROPIC_API_KEY not set — skipping agentic probe")
            return None
        return cls(anthropic.Anthropic(api_key=api_key), model=model)

    def complete(
        self,
        *,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        kwargs: dict = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        if tools is not None:
            kwargs["tools"] = tools

        resp = self._client.messages.create(**kwargs)

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in resp.content:
            if getattr(block, "type", None) == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, input=block.input))
            elif hasattr(block, "text"):
                text_parts.append(block.text)
        return LLMResponse(text="".join(text_parts), tool_calls=tool_calls)


def to_anthropic_tool(tool: ToolSchema) -> dict:
    """Convert a ToolSchema into the Anthropic tools format the attacker sees."""
    properties: dict = {}
    required: list[str] = []
    for param in tool.parameters:
        prop: dict = {"type": param.type, "description": param.description}
        if param.enum:
            prop["enum"] = param.enum
        properties[param.name] = prop
        if param.required:
            required.append(param.name)
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": {
            "type": "object",
            "properties": properties,
            **({"required": required} if required else {}),
        },
    }
