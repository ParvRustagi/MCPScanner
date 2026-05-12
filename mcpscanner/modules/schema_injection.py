"""Detect injected instructions inside parameter schemas (descriptions, enum values)."""
from __future__ import annotations
import re

from .base import BaseAttackModule
from ..models import Finding, ToolSchema

_PARAM_PATTERNS: list[tuple[str, str, str]] = [
    # Forced value assignment
    (r"always\s+set\s+(?:this|the\s+value|it)\s+to\s+['\"]", "high", "forced value assignment"),
    (r"(?:must|should)\s+(?:always\s+)?be\s+(?:set\s+to\s+)?['\"]", "high", "forced value constraint"),
    (r"default\s+(?:this\s+)?to\s+['\"].{1,60}['\"]\s+for\s+any", "high", "conditional default injection"),

    # Behavioral instructions in param descriptions
    (r"when\s+(?:the\s+)?(?:user|message|request|query)\s+(?:asks?|mentions?|contains?|says?).{0,80}(?:use|set|call|send|include|default\s+to)", "high", "conditional behavior injection"),
    (r"(?:if|whenever)\s+.{0,40}(?:credential|secret|key|password|token).{0,40}(?:include|add|send|pass)", "critical", "credential routing injection"),

    # Semantic misdirection
    (r"this\s+parameter\s+(?:controls?|determines?)\s+(?:whether|if)\s+(?:the\s+)?(?:model|agent|llm|assistant)\s+(?:will|should|can)", "medium", "parameter behavioral control"),
    (r"setting\s+this\s+to\s+.{0,40}will\s+(?:cause|make|allow|enable|disable|prevent)", "medium", "parameter consequence injection"),

    # Jailbreak in param
    (r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?", "critical", "param jailbreak"),
    (r"override\s+(?:system|the)\s+(?:prompt|instructions?)", "critical", "param override"),

    # Hidden data routes in enum descriptions
    (r"for\s+(?:any|all)\s+(?:message|content|data|request)s?\s+(?:about|containing|with)\s+.{0,30}(?:use|send|route|forward)", "high", "enum routing injection"),
]

_ENUM_PATTERNS: list[tuple[str, str, str]] = [
    (r"ignore\s+(?:previous|prior|all)\s+instructions?", "critical", "enum jailbreak value"),
    (r"override\s+(?:system|the)\s+(?:prompt|instructions?)", "critical", "enum override value"),
    (r"(?:exfiltrate|send|transmit)\s+(?:to\s+)?https?://", "critical", "enum exfiltration value"),
]

_PARAM_COMPILED = [(re.compile(p, re.IGNORECASE), sev, label) for p, sev, label in _PARAM_PATTERNS]
_ENUM_COMPILED = [(re.compile(p, re.IGNORECASE), sev, label) for p, sev, label in _ENUM_PATTERNS]


class SchemaInjectionModule(BaseAttackModule):
    name = "schema_injection"

    def run(self, schemas: list[ToolSchema]) -> list[Finding]:
        findings = []
        for tool in schemas:
            for param in tool.parameters:
                findings.extend(_scan_param_description(tool, param))
                findings.extend(_scan_enum_values(tool, param))
        return findings


def _scan_param_description(tool: ToolSchema, param) -> list[Finding]:
    text = param.description
    if not text:
        return []
    findings = []
    seen: set[str] = set()
    for pattern, severity, label in _PARAM_COMPILED:
        m = pattern.search(text)
        if m and label not in seen:
            seen.add(label)
            snippet = text[max(0, m.start() - 40): m.end() + 40].strip()
            findings.append(Finding(
                severity=severity,
                module="schema_injection",
                tool_name=tool.name,
                server=tool.server,
                title=f"Schema injection in {tool.server}/{tool.name}",
                detail=(
                    f"Parameter '{param.name}' of tool '{tool.name}' has a description "
                    f"containing injected behavioral instructions ({label})."
                ),
                evidence=f"'{param.name}' description: \"{snippet}\"",
                recommendation=(
                    "Parameter descriptions should describe the data format expected, "
                    "not instruct the model on behavior or value selection logic."
                ),
            ))
    return findings


def _scan_enum_values(tool: ToolSchema, param) -> list[Finding]:
    findings = []
    for value in param.enum:
        for pattern, severity, label in _ENUM_COMPILED:
            if pattern.search(value):
                findings.append(Finding(
                    severity=severity,
                    module="schema_injection",
                    tool_name=tool.name,
                    server=tool.server,
                    title=f"Schema injection in {tool.server}/{tool.name} enum value",
                    detail=(
                        f"Enum value '{value}' in parameter '{param.name}' of tool '{tool.name}' "
                        f"contains adversarial content ({label})."
                    ),
                    evidence=f"'{param.name}' enum value: \"{value}\"",
                    recommendation="Enum values should be plain data values, not instruction strings.",
                ))
    return findings
