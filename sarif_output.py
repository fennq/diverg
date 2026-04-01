"""
SARIF 2.1.0 output for Diverg scan findings.

Converts the canonical Diverg findings list into a SARIF log that GitHub
Code Scanning (and other SARIF consumers) can ingest.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import re
from typing import Any

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Diverg"
TOOL_URI = "https://github.com/fennq/diverg"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "note",
}

_SEVERITY_RANK: dict[str, int] = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower())
    return s.strip("-") or "unknown"


def _build_rules(findings: list[dict]) -> tuple[list[dict], dict[str, int]]:
    """Deduplicate findings into SARIF rule definitions.

    Returns (rules_list, rule_id_to_index) so results can reference by index.
    """
    rules: list[dict] = []
    rule_index: dict[str, int] = {}

    for f in findings:
        category = f.get("category", "Assessment")
        rule_id = _slugify(category)

        if rule_id in rule_index:
            continue

        help_parts = []
        if f.get("impact"):
            help_parts.append(f"**Impact:** {f['impact']}")
        if f.get("remediation"):
            help_parts.append(f"**Remediation:** {f['remediation']}")

        rule: dict[str, Any] = {
            "id": rule_id,
            "name": category,
            "shortDescription": {"text": category},
            "help": {"text": "\n\n".join(help_parts) or category, "markdown": "\n\n".join(help_parts) or category},
            "defaultConfiguration": {
                "level": _SEVERITY_TO_LEVEL.get(f.get("severity", "Info"), "note"),
            },
        }
        rule_index[rule_id] = len(rules)
        rules.append(rule)

    return rules, rule_index


def _finding_to_result(f: dict, rule_index: dict[str, int]) -> dict:
    """Convert a single Diverg finding into a SARIF result object."""
    category = f.get("category", "Assessment")
    rule_id = _slugify(category)
    severity = f.get("severity", "Info")
    level = _SEVERITY_TO_LEVEL.get(severity, "note")

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index.get(rule_id, 0),
        "level": level,
        "message": {"text": f.get("title", "Untitled finding")},
        "locations": [],
        "properties": {},
    }

    url = f.get("url", "")
    if url:
        result["locations"].append({
            "physicalLocation": {
                "artifactLocation": {"uri": url},
            }
        })

    props = result["properties"]
    props["severity"] = severity
    if f.get("evidence"):
        props["evidence"] = f["evidence"]
    if f.get("confidence"):
        props["confidence"] = f["confidence"]
    if f.get("_source_skill"):
        props["source_skill"] = f["_source_skill"]
    if f.get("finding_type"):
        props["finding_type"] = f["finding_type"]
    if f.get("impact"):
        props["impact"] = f["impact"]
    if f.get("remediation"):
        props["remediation"] = f["remediation"]

    return result


def findings_to_sarif(
    findings: list[dict],
    target_url: str = "",
    scanned_at: str = "",
) -> dict:
    """Convert Diverg findings into a complete SARIF 2.1.0 log.

    Args:
        findings: List of normalised Diverg finding dicts.
        target_url: The scanned target (informational).
        scanned_at: ISO timestamp of the scan.

    Returns:
        A dict representing the SARIF JSON structure.
    """
    rules, rule_index = _build_rules(findings)
    results = [_finding_to_result(f, rule_index) for f in findings]

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "target_url": target_url,
                    "scanned_at": scanned_at,
                },
            }
        ],
    }
    return sarif


def check_severity_gate(findings: list[dict], fail_on: str) -> bool:
    """Return True if any finding meets or exceeds the severity threshold.

    Args:
        findings: List of normalised Diverg finding dicts.
        fail_on: Minimum severity to trigger failure (critical/high/medium/low).

    Returns:
        True if the gate is breached (caller should exit non-zero).
    """
    threshold = _SEVERITY_RANK.get(fail_on.capitalize(), 0)
    for f in findings:
        rank = _SEVERITY_RANK.get(f.get("severity", "Info"), 0)
        if rank >= threshold:
            return True
    return False
