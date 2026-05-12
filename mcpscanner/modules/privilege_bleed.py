"""Detect cross-server privilege bleed — when outputs from one server can influence another."""
from __future__ import annotations
from collections import defaultdict
from itertools import combinations

from .base import BaseAttackModule
from ..models import Finding, ToolSchema

# Server capability categories
_READ_KEYWORDS = {"read", "list", "get", "fetch", "search", "query", "find", "scan", "load", "retrieve"}
_WRITE_KEYWORDS = {"write", "create", "update", "delete", "post", "send", "publish", "push", "insert", "execute", "run", "modify"}

# Servers that typically handle sensitive data
_SENSITIVE_SERVER_PATTERNS = ["filesystem", "file", "database", "db", "vault", "secret", "credential", "key", "config"]
_WRITE_SERVER_PATTERNS = ["github", "slack", "email", "gmail", "webhook", "http", "api", "web", "sns", "pubsub", "queue"]


class PrivilegeBleedModule(BaseAttackModule):
    name = "privilege_bleed"

    def run(self, schemas: list[ToolSchema]) -> list[Finding]:
        by_server: dict[str, list[ToolSchema]] = defaultdict(list)
        for tool in schemas:
            by_server[tool.server].append(tool)

        if len(by_server) < 2:
            return []

        server_caps = {name: _classify_server(name, tools) for name, tools in by_server.items()}
        findings = []

        sensitive_readers = [s for s, caps in server_caps.items() if caps["reads_sensitive"]]
        external_writers = [s for s, caps in server_caps.items() if caps["writes_external"]]

        for reader in sensitive_readers:
            for writer in external_writers:
                if reader == writer:
                    continue
                findings.append(Finding(
                    severity="medium",
                    module="privilege_bleed",
                    tool_name="(cross-server)",
                    server=f"{reader} → {writer}",
                    title=f"Privilege bleed risk — {reader} → {writer}",
                    detail=(
                        f"Server '{reader}' reads potentially sensitive data, and server '{writer}' "
                        f"can write to external systems. An LLM agent with access to both could "
                        f"chain these tool calls to exfiltrate data without explicit user intent."
                    ),
                    evidence=(
                        f"Read server: {reader} (tools: {', '.join(t.name for t in by_server[reader][:3])}...)\n"
                        f"Write server: {writer} (tools: {', '.join(t.name for t in by_server[writer][:3])}...)"
                    ),
                    recommendation=(
                        "Sanitize tool outputs before passing across server boundaries. "
                        "Treat cross-server data as untrusted input. "
                        "Consider requiring explicit user confirmation before chaining read→write across servers."
                    ),
                ))

        # Also flag any two servers with overlapping high-privilege operations
        all_servers = list(by_server.keys())
        for s1, s2 in combinations(all_servers, 2):
            caps1, caps2 = server_caps[s1], server_caps[s2]
            if caps1["has_shell"] and caps2["has_network"]:
                findings.append(Finding(
                    severity="high",
                    module="privilege_bleed",
                    tool_name="(cross-server)",
                    server=f"{s1} + {s2}",
                    title=f"Shell + network privilege combination — {s1} / {s2}",
                    detail=(
                        f"Server '{s1}' has shell execution capabilities and server '{s2}' has network "
                        f"access. An attacker who can influence either server's inputs could chain these "
                        f"to achieve remote code execution with exfiltration."
                    ),
                    evidence=f"Shell server: {s1}\nNetwork server: {s2}",
                    recommendation=(
                        "Isolate shell-capable servers from network-capable servers where possible. "
                        "Apply strict input validation on all parameters passed to shell tools."
                    ),
                ))

        return findings


def _classify_server(name: str, tools: list[ToolSchema]) -> dict:
    name_lower = name.lower()
    all_tool_names = " ".join(t.name.lower() for t in tools)
    all_descriptions = " ".join(t.description.lower() for t in tools)
    corpus = f"{name_lower} {all_tool_names} {all_descriptions}"

    reads_sensitive = any(kw in name_lower for kw in _SENSITIVE_SERVER_PATTERNS) or (
        any(kw in all_tool_names for kw in _READ_KEYWORDS) and
        any(kw in corpus for kw in ["secret", "credential", "password", "key", "token", "private", "sensitive"])
    )
    writes_external = any(kw in name_lower for kw in _WRITE_SERVER_PATTERNS) or (
        any(kw in all_tool_names for kw in _WRITE_KEYWORDS) and
        any(kw in corpus for kw in ["external", "remote", "http", "api", "webhook", "email", "message", "post", "publish"])
    )
    has_shell = any(kw in all_tool_names for kw in ["execute", "shell", "bash", "run_command", "subprocess", "exec"])
    has_network = any(kw in all_tool_names for kw in ["http", "fetch", "request", "get_url", "post_url", "download", "upload"])

    return {
        "reads_sensitive": reads_sensitive,
        "writes_external": writes_external,
        "has_shell": has_shell,
        "has_network": has_network,
    }
