"""Detect dangerous multi-step tool chains that enable privilege escalation or data exfiltration."""
from __future__ import annotations
import re
from itertools import combinations, permutations

from .base import BaseAttackModule
from ..models import Finding, ToolSchema

# ── Category patterns ────────────────────────────────────────────────────────
# Each entry: (name_pattern, description_pattern)

_CATEGORY_PATTERNS: dict[str, tuple[re.Pattern, re.Pattern]] = {
    "READ": (
        re.compile(r"\b(read|get|fetch|load|retrieve|download|open|view|show|cat|stat)\b", re.I),
        re.compile(r"\b(reads?|fetches?|retrieves?|returns the contents?|loads?)\b", re.I),
    ),
    "CREDENTIAL": (
        re.compile(
            r"\b(get|read|fetch|retrieve)_(secret|token|key|password|credential|api_key)\b"
            r"|\b(vault_read|kv_get|secret_get|get_credentials?|get_api_key)\b",
            re.I,
        ),
        re.compile(r"\b(secret|credential|api[_\s]?key|password|private[_\s]?key|auth[_\s]?token|bearer)\b", re.I),
    ),
    "ENUMERATE": (
        re.compile(
            r"\b(list|ls|find|search|scan|glob|enumerate|discover|ps|whoami|id|get_env)\b",
            re.I,
        ),
        re.compile(r"\b(lists?|enumerates?|discovers?|all (files?|users?|repos?|processes?)|environment variables?)\b", re.I),
    ),
    "EXECUTE": (
        re.compile(r"\b(execute|run_command|shell|bash|subprocess|exec|eval|invoke|run_script|spawn|popen)\b", re.I),
        re.compile(r"\b(executes?|runs? (a )?command|spawns?|shell|subprocess)\b", re.I),
    ),
    "DESTROY": (
        re.compile(r"\b(delete|remove|drop|truncate|purge|wipe|rm|destroy|unlink|erase|overwrite|format)\b", re.I),
        re.compile(r"\b(deletes?|removes?|drops? the|wipes?|permanently (removes?|deletes?|destroys?))\b", re.I),
    ),
    "EXFILTRATE": (
        re.compile(
            r"\b(send_email|post_message|http_post|webhook|upload|push|publish|send_sms"
            r"|create_issue|notify|forward|relay|emit|send_request|post_to|send_to)\b",
            re.I,
        ),
        re.compile(r"\b(sends? (to|data|email)|posts? to|uploads? to|external|webhook|outbound|http (post|request)|notify)\b", re.I),
    ),
}


def _classify_tool(tool: ToolSchema) -> tuple[frozenset[str], bool]:
    """Returns (categories, classified_by_name). classified_by_name=True if name matched."""
    cats: set[str] = set()
    by_name = False
    corpus_name = tool.name.lower()
    corpus_desc = tool.description.lower()

    for cat, (name_pat, desc_pat) in _CATEGORY_PATTERNS.items():
        if name_pat.search(corpus_name):
            cats.add(cat)
            by_name = True
        elif desc_pat.search(corpus_desc):
            cats.add(cat)

    return frozenset(cats), by_name


# ── Chain rules ───────────────────────────────────────────────────────────────

# 2-step: (required_cats_step1, required_cats_step2, severity, label, recommendation)
_CHAIN_RULES_2: list[tuple[str, str, str, str, str]] = [
    ("CREDENTIAL", "EXFILTRATE", "critical", "credential-theft",
     "Ensure credential-fetching tools cannot be called in the same session as outbound-write "
     "tools without explicit user confirmation. Consider separating them into different servers."),

    ("CREDENTIAL", "EXECUTE", "critical", "lateral-movement",
     "Prevent credential tools from feeding into execution tools. Credentials should only be "
     "passed to the service that requires them, not to a shell or command runner."),

    ("EXECUTE", "DESTROY", "critical", "scorched-earth",
     "Gate destructive tools behind a confirmation parameter or separate permission scope "
     "from execution tools to prevent a single agent action from causing irreversible damage."),

    ("ENUMERATE", "EXFILTRATE", "high", "recon-exfil",
     "An agent can enumerate sensitive resources and immediately exfiltrate the list. "
     "Require explicit user approval before any enumeration result is sent externally."),

    ("ENUMERATE", "EXECUTE", "high", "recon-execute",
     "An agent can enumerate running processes or environment details and pass that "
     "information directly to a shell. Isolate enumeration tools from execution tools."),

    ("READ", "EXFILTRATE", "medium", "read-exfil",
     "A read tool and an outbound-write tool coexist in the same server. "
     "Sanitize tool outputs and require confirmation before sending data externally."),
]

# 3-step: (cat1, cat2, cat3, severity, label, recommendation)
_CHAIN_RULES_3: list[tuple[str, str, str, str, str, str]] = [
    ("ENUMERATE", "READ", "EXFILTRATE", "critical", "full-recon-exfil",
     "This three-step chain (enumerate → read → send) is a complete data exfiltration path. "
     "Audit whether all three capability types need to coexist in a single agent session."),

    ("ENUMERATE", "CREDENTIAL", "EXFILTRATE", "critical", "recon-cred-exfil",
     "An agent can discover which credentials exist, read them, then send them externally. "
     "Separate credential access from external write capabilities."),

    ("CREDENTIAL", "EXECUTE", "DESTROY", "critical", "cred-rce-destroy",
     "An agent can steal credentials, use them to execute commands, and then destroy evidence. "
     "This is a full attack chain. Isolate each capability into separate servers."),

    ("ENUMERATE", "READ", "EXECUTE", "high", "recon-read-rce",
     "An agent can enumerate files, read their contents, and pass that to a shell — enabling "
     "dynamic code execution from discovered file contents."),

    ("READ", "CREDENTIAL", "EXFILTRATE", "critical", "read-cred-exfil",
     "An agent can read a file that contains credentials and then exfiltrate them. "
     "Ensure files with credentials are not accessible alongside outbound-write tools."),
]


# ── Module ────────────────────────────────────────────────────────────────────

class ToolChainAbuseModule(BaseAttackModule):
    name = "tool_chain_abuse"

    def run(self, schemas: list[ToolSchema]) -> list[Finding]:
        tool_cats: list[tuple[frozenset[str], bool]] = [_classify_tool(t) for t in schemas]
        findings: list[Finding] = []
        findings.extend(_check_2step(schemas, tool_cats))
        findings.extend(_check_3step(schemas, tool_cats))
        return findings


def _check_2step(
    schemas: list[ToolSchema],
    tool_cats: list[tuple[frozenset[str], bool]],
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[frozenset] = set()

    for i, j in permutations(range(len(schemas)), 2):
        t1, t2 = schemas[i], schemas[j]
        # Skip cross-server 2-step — that's PrivilegeBleedModule's domain
        if t1.server != t2.server:
            continue

        cats1, by_name1 = tool_cats[i]
        cats2, by_name2 = tool_cats[j]

        for req1, req2, severity, label, recommendation in _CHAIN_RULES_2:
            if req1 not in cats1 or req2 not in cats2:
                continue

            key = frozenset({t1.name, t2.name, label})
            if key in seen:
                continue
            seen.add(key)

            confidence = 0.9 if (by_name1 and by_name2) else 0.7

            findings.append(Finding(
                severity=severity,
                module="tool_chain_abuse",
                tool_name=f"{t1.name} | {t2.name}",
                server=t1.server,
                title=f"Dangerous tool chain: {label} in {t1.server}",
                detail=(
                    f"Tools '{t1.name}' [{req1}] and '{t2.name}' [{req2}] "
                    f"coexist in server '{t1.server}' and form a dangerous {label} chain."
                ),
                evidence=_evidence_2step(t1, t2, req1, req2, label),
                recommendation=recommendation,
                confidence=confidence,
            ))

    return findings


def _check_3step(
    schemas: list[ToolSchema],
    tool_cats: list[tuple[frozenset[str], bool]],
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[frozenset] = set()

    for i, j, k in permutations(range(len(schemas)), 3):
        t1, t2, t3 = schemas[i], schemas[j], schemas[k]
        cats1, by_name1 = tool_cats[i]
        cats2, by_name2 = tool_cats[j]
        cats3, by_name3 = tool_cats[k]

        for req1, req2, req3, severity, label, recommendation in _CHAIN_RULES_3:
            if req1 not in cats1 or req2 not in cats2 or req3 not in cats3:
                continue

            key = frozenset({t1.name, t2.name, t3.name, label})
            if key in seen:
                continue
            seen.add(key)

            cross_server = len({t1.server, t2.server, t3.server}) > 1
            confidence = 0.85 if (by_name1 and by_name2 and by_name3) else 0.65
            if cross_server:
                confidence -= 0.1

            server_field = (
                f"{t1.server} → {t2.server} → {t3.server}"
                if cross_server
                else t1.server
            )

            findings.append(Finding(
                severity=severity,
                module="tool_chain_abuse",
                tool_name=f"{t1.name} | {t2.name} | {t3.name}",
                server=server_field,
                title=f"Dangerous tool chain: {label} ({server_field})",
                detail=(
                    f"A {len({t1.server, t2.server, t3.server})}-server chain "
                    f"'{t1.name}' [{req1}] → '{t2.name}' [{req2}] → '{t3.name}' [{req3}] "
                    f"forms a complete {label} attack path."
                ),
                evidence=_evidence_3step(t1, t2, t3, req1, req2, req3, label, cross_server),
                recommendation=recommendation,
                confidence=confidence,
            ))

    return findings


def _evidence_2step(t1: ToolSchema, t2: ToolSchema, req1: str, req2: str, label: str) -> str:
    return (
        f"Chain: {label} (2-step, same-server)\n"
        f"Server: {t1.server}\n"
        f"Step 1 [{req1}] {t1.name} — \"{t1.description[:80]}\"\n"
        f"Step 2 [{req2}] {t2.name} — \"{t2.description[:80]}\""
    )


def _evidence_3step(
    t1: ToolSchema, t2: ToolSchema, t3: ToolSchema,
    req1: str, req2: str, req3: str,
    label: str, cross_server: bool,
) -> str:
    scope = "cross-server" if cross_server else "same-server"
    return (
        f"Chain: {label} (3-step, {scope})\n"
        f"Step 1 [{req1}] {t1.name} @ {t1.server} — \"{t1.description[:80]}\"\n"
        f"Step 2 [{req2}] {t2.name} @ {t2.server} — \"{t2.description[:80]}\"\n"
        f"Step 3 [{req3}] {t3.name} @ {t3.server} — \"{t3.description[:80]}\""
    )
