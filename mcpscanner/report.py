from __future__ import annotations
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Finding, ToolSchema

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_EMOJI = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


@dataclass
class Report:
    target: str
    tools: list["ToolSchema"] = field(default_factory=list)
    findings: list["Finding"] = field(default_factory=list)
    date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))

    @property
    def servers(self) -> list[str]:
        return sorted({t.server for t in self.tools})

    def summary(self) -> str:
        lines = [
            f"MCPScanner Report — {self.date}",
            f"Target: {self.target}",
            f"Servers: {len(self.servers)}   Tools: {len(self.tools)}   Findings: {len(self.findings)}",
        ]
        if not self.findings:
            lines.append("\nNo findings.")
            return "\n".join(lines)

        sorted_findings = sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        lines.append("")
        for f in sorted_findings:
            tag = f"[{f.severity.upper()}]"
            lines.append(f"{tag} {f.title}")
            if f.evidence:
                lines.append(f"  Evidence: {f.evidence}")
            if f.recommendation:
                lines.append(f"  Recommendation: {f.recommendation}")
            lines.append("")
        return "\n".join(lines)

    def to_json(self) -> str:
        data = {
            "mcpscanner_version": "0.1.0",
            "date": self.date,
            "target": self.target,
            "servers": self.servers,
            "tool_count": len(self.tools),
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        return json.dumps(data, indent=2)

    def to_markdown(self) -> str:
        sorted_findings = sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        lines = [
            f"# MCPScanner Report",
            f"",
            f"**Date:** {self.date}  ",
            f"**Target:** `{self.target}`  ",
            f"**Servers:** {len(self.servers)} | **Tools:** {len(self.tools)} | **Findings:** {len(self.findings)}",
            f"",
        ]
        if self.servers:
            lines += ["## Servers", ""]
            for s in self.servers:
                lines.append(f"- `{s}`")
            lines.append("")

        if not sorted_findings:
            lines.append("## Findings\n\nNo findings.")
            return "\n".join(lines)

        lines += ["## Findings", ""]
        for i, f in enumerate(sorted_findings, 1):
            lines += [
                f"### {i}. [{f.severity.upper()}] {f.title}",
                f"",
                f"| Field | Value |",
                f"|---|---|",
                f"| **Severity** | `{f.severity}` |",
                f"| **Module** | `{f.module}` |",
                f"| **Server** | `{f.server}` |",
                f"| **Tool** | `{f.tool_name}` |",
            ]
            if f.confidence is not None:
                lines.append(f"| **Confidence** | {f.confidence:.0%} |")
            lines += [
                f"",
                f"**Detail:** {f.detail}",
                f"",
            ]
            if f.evidence:
                lines += [f"**Evidence:**", f"```", f.evidence, f"```", f""]
            if f.recommendation:
                lines += [f"**Recommendation:** {f.recommendation}", f""]

        return "\n".join(lines)

    def to_sarif(self) -> str:
        rules = {}
        results = []

        for f in self.findings:
            rule_id = f"{f.module}/{f.title.lower().replace(' ', '_')}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.detail},
                    "defaultConfiguration": {
                        "level": _sarif_level(f.severity)
                    },
                    "properties": {"tags": [f.module, f.severity]},
                }
            results.append({
                "ruleId": rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.detail},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": f.tool_name,
                                "kind": "function",
                                "decoratedName": f"{f.server}/{f.tool_name}",
                            }
                        ]
                    }
                ],
                "partialFingerprints": {
                    "evidence/v1": f.evidence[:200] if f.evidence else "",
                },
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MCPScanner",
                            "version": "0.1.0",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity, "note")
