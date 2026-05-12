"""Detect adversarial instructions embedded in tool descriptions."""
from __future__ import annotations
import re

from .base import BaseAttackModule
from ..models import Finding, ToolSchema

# (pattern, severity, short_label)
_PATTERNS: list[tuple[str, str, str]] = [
    # Jailbreak / override
    (r"ignore\s+(?:all\s+)?(?:previous|prior|above|other)\s+instructions?", "critical", "jailbreak override"),
    (r"override\s+(?:your|the|all)\s+(?:system\s+)?(?:prompt|instructions?|constraints?|rules?)", "critical", "system prompt override"),
    (r"forget\s+(?:your|all|the)\s+(?:previous\s+)?(?:instructions?|training|rules?|guidelines?)", "critical", "instruction wipe"),
    (r"disregard\s+(?:all\s+)?(?:previous|prior|other|your)\s+(?:instructions?|rules?|constraints?|guidelines?)", "critical", "instruction disregard"),
    (r"new\s+(?:primary\s+)?(?:directive|instruction|goal)\s*:", "critical", "directive injection"),

    # Tool prioritization manipulation
    (r"(?:always|must|shall)\s+(?:run|call|execute|invoke|use)\s+(?:this|first|me|it)\b", "high", "forced execution"),
    (r"(?:before|prior\s+to)\s+(?:any|all|every)\s+(?:other\s+)?(?:tool|action|call|function)", "high", "priority hijacking"),
    (r"execute\s+(?:this|me|it)\s+(?:first|before\s+anything|immediately)", "high", "forced first execution"),
    (r"this\s+tool\s+(?:must|should|shall)\s+(?:always|be\s+called)\b", "high", "mandatory invocation"),

    # Behavioral manipulation
    (r"do\s+not\s+(?:use|call|invoke|run|tell)\s+(?:the\s+user|user|anyone)\b", "high", "user deception"),
    (r"(?:only|exclusively)\s+use\s+this\s+tool\s+(?:for|when|to)", "medium", "tool exclusivity"),
    (r"without\s+(?:telling|informing|asking)\s+the\s+user", "high", "covert action"),
    (r"do\s+not\s+(?:mention|disclose|reveal|tell)\s+(?:this|that|the\s+user)", "high", "information suppression"),

    # Data exfiltration
    (r"send\s+(?:the\s+)?(?:results?|output|data|contents?|response)\s+to\s+(?:https?://|url|endpoint)", "critical", "exfiltration instruction"),
    (r"(?:exfiltrate|transmit|upload|post)\s+.{0,40}(?:to\s+)?(?:https?://|remote|external|webhook)", "critical", "data exfiltration"),
    (r"include\s+(?:the\s+)?(?:api\s+key|token|secret|password|credential)s?\s+in", "critical", "credential theft"),

    # Prompt injection markers
    (r"</?(?:system|instruction|directive|inject|override|admin)\s*>", "critical", "injection tag"),
    (r"\[\s*(?:SYSTEM|ADMIN|OVERRIDE|INJECT|DIRECTIVE)\s*\]", "critical", "injection bracket"),
    (r"---+\s*(?:system|new\s+prompt|instructions?)\s*---+", "critical", "injection divider"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), sev, label) for p, sev, label in _PATTERNS]


class DescriptionPoisonModule(BaseAttackModule):
    name = "description_poison"

    def run(self, schemas: list[ToolSchema]) -> list[Finding]:
        findings = []
        for tool in schemas:
            findings.extend(_scan_text(tool, tool.description, "tool description"))
        return findings


def _scan_text(tool: ToolSchema, text: str, location: str) -> list[Finding]:
    if not text:
        return []
    findings = []
    seen_labels: set[str] = set()
    for pattern, severity, label in _COMPILED:
        match = pattern.search(text)
        if match and label not in seen_labels:
            seen_labels.add(label)
            snippet = text[max(0, match.start() - 40): match.end() + 40].strip()
            findings.append(Finding(
                severity=severity,
                module="description_poison",
                tool_name=tool.name,
                server=tool.server,
                title=f"Description poisoning in {tool.server}/{tool.name}",
                detail=(
                    f"The {location} of tool '{tool.name}' contains adversarial instructions "
                    f"({label}) that could manipulate a connected LLM's behavior."
                ),
                evidence=f'"{snippet}"',
                recommendation=(
                    "Strip all imperative language from tool descriptions. "
                    "Descriptions should state what a tool does, not instruct the model how to behave."
                ),
            ))
    return findings
