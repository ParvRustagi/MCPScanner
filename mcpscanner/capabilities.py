"""Shared tool capability taxonomy.

A single source of truth for classifying what a tool *can do* — used both by the
static tool_chain_abuse detector and the live-execution safety gate.
"""
from __future__ import annotations
import re

from .models import ToolSchema

# Each entry: (name_pattern, description_pattern)
CATEGORY_PATTERNS: dict[str, tuple[re.Pattern, re.Pattern]] = {
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


def classify_tool(tool: ToolSchema) -> tuple[frozenset[str], bool]:
    """Return (categories, classified_by_name).

    classified_by_name is True if a tool *name* matched (higher confidence than a
    description-only match).
    """
    cats: set[str] = set()
    by_name = False
    corpus_name = tool.name.lower()
    corpus_desc = tool.description.lower()

    for cat, (name_pat, desc_pat) in CATEGORY_PATTERNS.items():
        if name_pat.search(corpus_name):
            cats.add(cat)
            by_name = True
        elif desc_pat.search(corpus_desc):
            cats.add(cat)

    return frozenset(cats), by_name
