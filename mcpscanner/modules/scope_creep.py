"""Audit MCP server permissions against what its tools actually require."""
from __future__ import annotations
import re
from collections import defaultdict

from .base import BaseAttackModule
from ..models import Finding, ToolSchema

# Maps tool name patterns to the minimum permissions they need
_TOOL_PERMISSION_MAP: list[tuple[re.Pattern, set[str]]] = [
    (re.compile(r"read_file|write_file|list_dir|delete_file|create_dir|move_file|copy_file", re.I), {"filesystem"}),
    (re.compile(r"execute|run_command|shell|bash|subprocess|exec", re.I), {"shell"}),
    (re.compile(r"create_issue|list_issues|update_issue|close_issue|github", re.I), {"github"}),
    (re.compile(r"post_message|send_message|slack", re.I), {"slack"}),
    (re.compile(r"send_email|compose_email|email|gmail|smtp", re.I), {"email"}),
    (re.compile(r"query|select|insert|update|delete|sql|database|db_", re.I), {"database"}),
    (re.compile(r"http_get|http_post|fetch|request|curl|wget|web_", re.I), {"network"}),
    (re.compile(r"get_weather|weather|forecast", re.I), {"network"}),
    (re.compile(r"s3_|upload|download|bucket|blob|storage", re.I), {"aws", "network"}),
    (re.compile(r"docker|container|pod|kubectl|k8s", re.I), {"docker"}),
    (re.compile(r"stripe|payment|charge|invoice", re.I), {"payments"}),
    (re.compile(r"sms|twilio|text_message", re.I), {"sms"}),
]

# Permissions that grant significant risk if over-provisioned
_HIGH_RISK_PERMS = {"shell", "docker", "aws"}

# Permissions that are almost never needed together with a narrow-purpose server
_UNEXPECTED_COMBOS: list[tuple[str, set[str], str]] = [
    ("weather", {"filesystem", "shell", "database", "aws"}, "A weather server should only need outbound network access."),
    ("github", {"shell", "docker", "aws"}, "A GitHub server should only need github API access."),
    ("slack", {"filesystem", "shell", "database"}, "A Slack messaging server should not need filesystem or shell access."),
    ("email", {"shell", "docker", "database"}, "An email server should not need shell or docker access."),
]


class ScopeCreepModule(BaseAttackModule):
    name = "scope_creep"

    def run(self, schemas: list[ToolSchema]) -> list[Finding]:
        # Group tools by server
        by_server: dict[str, list[ToolSchema]] = defaultdict(list)
        for tool in schemas:
            by_server[tool.server].append(tool)

        findings = []
        for server_name, tools in by_server.items():
            findings.extend(_audit_server(server_name, tools))
        return findings


def _audit_server(server_name: str, tools: list[ToolSchema]) -> list[Finding]:
    findings = []
    declared_perms: set[str] = set()
    for t in tools:
        declared_perms.update(t.permissions)

    if not declared_perms:
        return []

    # Derive minimum required permissions from tool names
    required_perms: set[str] = set()
    for tool in tools:
        for pattern, perms in _TOOL_PERMISSION_MAP:
            if pattern.search(tool.name):
                required_perms.update(perms)

    excess = declared_perms - required_perms
    if excess:
        # Determine severity
        sev = "high" if excess & _HIGH_RISK_PERMS else "medium"
        findings.append(Finding(
            severity=sev,
            module="scope_creep",
            tool_name="(server-level)",
            server=server_name,
            title=f"Scope creep in {server_name}",
            detail=(
                f"Server '{server_name}' holds credentials/permissions for: "
                f"{', '.join(sorted(excess))} — but its tools only require: "
                f"{', '.join(sorted(required_perms)) or 'none detected'}."
            ),
            evidence=(
                f"Declared permissions: {', '.join(sorted(declared_perms))}\n"
                f"Required permissions: {', '.join(sorted(required_perms)) or 'none'}\n"
                f"Excess: {', '.join(sorted(excess))}"
            ),
            recommendation=(
                f"Remove credentials for {', '.join(sorted(excess))} from this server's environment. "
                "Apply least-privilege: each server should hold only the credentials its tools require."
            ),
        ))

    # Check for unexpected permission combos based on server name
    server_lower = server_name.lower()
    for keyword, suspicious_perms, rationale in _UNEXPECTED_COMBOS:
        if keyword in server_lower:
            unexpected = declared_perms & suspicious_perms
            if unexpected:
                findings.append(Finding(
                    severity="high",
                    module="scope_creep",
                    tool_name="(server-level)",
                    server=server_name,
                    title=f"Unexpected permissions for {server_name}",
                    detail=(
                        f"Server '{server_name}' has access to {', '.join(sorted(unexpected))} "
                        f"which is unexpected for its apparent purpose. {rationale}"
                    ),
                    evidence=f"Unexpected permissions detected: {', '.join(sorted(unexpected))}",
                    recommendation=rationale,
                ))

    return findings
