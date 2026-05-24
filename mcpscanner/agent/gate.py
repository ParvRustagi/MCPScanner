"""Safety gate for live tool execution.

When the agentic probe runs against a *real* server, every proposed tool call
passes through this gate first. It enforces two layers:

1. Capability block — tools that can execute, destroy, exfiltrate, or read
   credentials are never run.
2. Sensitive-path screening — even an allowed read is blocked if its arguments
   point at secret material (.ssh, .aws, .env, ...), so real secrets never enter
   the LLM context.

Only read/enumerate calls with non-sensitive arguments reach the real server.
"""
from __future__ import annotations
import re
from dataclasses import dataclass

from ..capabilities import classify_tool
from ..models import ToolSchema

# Capabilities that must never run against a real server.
BLOCKED_CAPABILITIES: frozenset[str] = frozenset({"EXECUTE", "DESTROY", "EXFILTRATE", "CREDENTIAL"})

# Argument values pointing at these are blocked even for read/enumerate tools.
_SENSITIVE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.I)
    for p in (
        r"\.ssh\b",
        r"\bid_rsa\b",
        r"\bid_ed25519\b",
        r"\.pem\b",
        r"\.aws\b",
        r"\.env\b",
        r"\.netrc\b",
        r"\.npmrc\b",
        r"\.git-credentials\b",
        r"\.kube\b",
        r"\.docker/config\b",
        r"/etc/shadow\b",
        r"\bcredential",
        r"\bsecret",
        r"\bprivate[_\-/.]?key",
        r"\bpassword",
    )
]


@dataclass
class GateDecision:
    allowed: bool
    reason: str = ""


class CapabilityGate:
    def __init__(
        self,
        blocked_capabilities: frozenset[str] = BLOCKED_CAPABILITIES,
        screen_paths: bool = True,
    ) -> None:
        self.blocked_capabilities = blocked_capabilities
        self.screen_paths = screen_paths

    def check(self, tool: ToolSchema, args: dict) -> GateDecision:
        cats, _ = classify_tool(tool)
        blocked = cats & self.blocked_capabilities
        if blocked:
            return GateDecision(False, f"blocked capability: {', '.join(sorted(blocked))}")

        if self.screen_paths:
            hit = _scan_args_for_sensitive(args)
            if hit:
                return GateDecision(False, f"sensitive path in arguments: {hit}")

        return GateDecision(True)


def _scan_args_for_sensitive(args: dict) -> str | None:
    for value in _iter_strings(args):
        for pat in _SENSITIVE_PATH_PATTERNS:
            if pat.search(value):
                return pat.pattern
    return None


def _iter_strings(obj) -> "list[str]":
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_iter_strings(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_iter_strings(v))
    return out
