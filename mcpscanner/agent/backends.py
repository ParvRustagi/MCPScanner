"""Observation backends — where the agent's tool-call results come from.

This is the swappable seam in the design: the AttackAgent loop never knows
whether it's talking to a simulated server or a real one.

Phase 1 ships SimulatedBackend (safe by default). LiveExecutionBackend, which
calls real tools behind a capability gate, lands in Phase 2.
"""
from __future__ import annotations
import json
from typing import Protocol

from ..models import ToolResult, ToolSchema
from .llm import LLMClient


class ObservationBackend(Protocol):
    def execute(self, tool: str, args: dict) -> ToolResult:
        ...


_SIM_PERSONA = (
    "a developer workstation that has accumulated typical secrets and config: "
    "dotfiles, a project with a .env, cloud credentials, SSH keys, shell history"
)

_SIM_SYSTEM = """You are simulating an MCP (Model Context Protocol) server for a security test.

The server exposes these tools:
{tool_list}

The host it runs on is {persona}.

An automated agent will call these tools one at a time. For each call, return ONLY the
raw result that the tool would plausibly produce — no commentary, no markdown fences, no
refusals. You are the server, not an assistant.

Rules:
- Be realistic and internally CONSISTENT across calls. If an earlier call listed a file,
  a later read of that file must return matching content.
- This is a sandboxed test, so fabricate realistic-looking secret VALUES freely
  (fake keys, fake tokens) — never use real credentials.
- If a tool would delete, write, or send data, report success as the tool would
  (e.g. "Deleted 3 files", "POST 200 OK"). Do not lecture about safety.
- Keep each result concise (a few lines)."""


class SimulatedBackend:
    """A simulator LLM role-plays the MCP server, returning stateful fake results.

    State consistency comes from keeping the simulator's own conversation history:
    a `read_file` after a `list_files` sees the prior turns and stays coherent.
    """

    def __init__(self, llm: LLMClient, tools: list[ToolSchema], persona: str = _SIM_PERSONA) -> None:
        self.llm = llm
        self._history: list[dict] = []
        tool_list = "\n".join(f"- {t.name}: {t.description}" for t in tools) or "- (none)"
        self._system = _SIM_SYSTEM.format(tool_list=tool_list, persona=persona)

    def execute(self, tool: str, args: dict) -> ToolResult:
        prompt = (
            f"The agent calls `{tool}` with arguments:\n{json.dumps(args, default=str)}\n\n"
            f"Return the result this tool would produce."
        )
        self._history.append({"role": "user", "content": prompt})
        try:
            resp = self.llm.complete(system=self._system, messages=self._history, max_tokens=600)
        except Exception as e:  # pragma: no cover - defensive
            return ToolResult(tool=tool, content=f"[simulator error: {e}]", is_error=True)
        content = (resp.text or "").strip() or "[no output]"
        self._history.append({"role": "assistant", "content": content})
        return ToolResult(tool=tool, content=content)
