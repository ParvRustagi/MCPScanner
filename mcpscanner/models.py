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
