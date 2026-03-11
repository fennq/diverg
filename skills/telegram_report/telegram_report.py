"""
Telegram reporting skill — formats security scan findings into structured
messages and sends them to a configured Telegram chat.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from telegram import Bot
from telegram.constants import ParseMode


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
MAX_MESSAGE_LENGTH = 4096


# ---------------------------------------------------------------------------
# Severity badges
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {
    "Critical": "\u2622\ufe0f",  # radioactive
    "High":     "\U0001f534",    # red circle
    "Medium":   "\U0001f7e0",    # orange circle
    "Low":      "\U0001f7e1",    # yellow circle
    "Info":     "\U0001f535",    # blue circle
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SendResult:
    success: bool
    messages_sent: int = 0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Message formatting
# ---------------------------------------------------------------------------

def _escape_md(text: str) -> str:
    """Escape MarkdownV2 special characters."""
    special = r"_*[]()~`>#+-=|{}.!\\"
    result = []
    for ch in text:
        if ch in special:
            result.append(f"\\{ch}")
        else:
            result.append(ch)
    return "".join(result)


def format_summary(target: str, findings: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    severity_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines = [
        f"\u2622\ufe0f *SecTester Scan Report*",
        f"",
        f"\U0001f3af *Target:* `{_escape_md(target)}`",
        f"\U0001f4c5 *Date:* {_escape_md(now)}",
        f"\U0001f4ca *Total findings:* {len(findings)}",
        f"",
        f"*Severity Breakdown:*",
    ]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = severity_counts[sev]
        badge = SEVERITY_EMOJI.get(sev, "")
        lines.append(f"  {badge} {_escape_md(sev)}: {count}")

    if findings:
        lines.append(f"")
        lines.append(f"*Top Findings:*")
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 99))
        for i, f in enumerate(sorted_findings[:10], 1):
            sev = f.get("severity", "Info")
            badge = SEVERITY_EMOJI.get(sev, "")
            title = _escape_md(f.get("title", "Untitled"))
            url = _escape_md(f.get("url", ""))
            lines.append(f"  {i}\\. {badge} *{title}*")
            if url:
                lines.append(f"     `{url}`")

        if len(findings) > 10:
            remaining = len(findings) - 10
            lines.append(f"")
            lines.append(f"  _\\.\\.\\.and {remaining} more findings_")

    return "\n".join(lines)


def format_detailed(target: str, findings: list[dict]) -> list[str]:
    messages: list[str] = []
    header = format_summary(target, findings)
    messages.append(header)

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 99))

    for f in sorted_findings:
        sev = f.get("severity", "Info")
        badge = SEVERITY_EMOJI.get(sev, "")
        lines = [
            f"{badge} *\\[{_escape_md(sev)}\\] {_escape_md(f.get('title', 'Untitled'))}*",
            f"",
        ]
        if f.get("url"):
            lines.append(f"\U0001f517 *URL:* `{_escape_md(f['url'])}`")
        if f.get("category"):
            lines.append(f"\U0001f3f7 *Category:* {_escape_md(f['category'])}")
        if f.get("evidence"):
            evidence = f["evidence"][:500]
            lines.append(f"\U0001f50d *Evidence:*")
            lines.append(f"```\n{evidence}\n```")
        if f.get("impact"):
            lines.append(f"\U0001f4a5 *Impact:* {_escape_md(f['impact'])}")
        if f.get("remediation"):
            lines.append(f"\u2705 *Remediation:* {_escape_md(f['remediation'])}")
        if f.get("cvss"):
            lines.append(f"\U0001f4cf *CVSS:* {_escape_md(f['cvss'])}")

        msg = "\n".join(lines)
        messages.append(msg)

    return messages


def format_alert(target: str, findings: list[dict]) -> str:
    critical_high = [f for f in findings if f.get("severity") in ("Critical", "High")]
    if not critical_high:
        return f"\u2705 *SecTester Alert*\n\nNo critical or high severity findings for `{_escape_md(target)}`\\."

    lines = [
        f"\U0001f6a8 *SecTester Alert \\- Urgent Findings\\!*",
        f"",
        f"\U0001f3af *Target:* `{_escape_md(target)}`",
        f"\u26a0\ufe0f *{len(critical_high)} critical/high findings detected*",
        f"",
    ]
    for i, f in enumerate(critical_high[:5], 1):
        sev = f.get("severity", "High")
        badge = SEVERITY_EMOJI.get(sev, "")
        title = _escape_md(f.get("title", "Untitled"))
        lines.append(f"{i}\\. {badge} *{title}*")
        if f.get("url"):
            lines.append(f"   `{_escape_md(f['url'])}`")

    lines.append(f"")
    lines.append(f"_Run a detailed scan for full report\\._")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Telegram sending
# ---------------------------------------------------------------------------

async def _send_messages(messages: list[str]) -> SendResult:
    if not BOT_TOKEN or not CHAT_ID:
        return SendResult(
            success=False,
            errors=["TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured. Set them in .env"],
        )

    result = SendResult(success=True)
    bot = Bot(token=BOT_TOKEN)

    for msg in messages:
        chunks = _split_message(msg)
        for chunk in chunks:
            try:
                await bot.send_message(
                    chat_id=CHAT_ID,
                    text=chunk,
                    parse_mode=ParseMode.MARKDOWN_V2,
                )
                result.messages_sent += 1
            except Exception as exc:
                # Fall back to plain text if MarkdownV2 parsing fails
                try:
                    plain = chunk.replace("\\", "").replace("*", "").replace("`", "").replace("_", "")
                    await bot.send_message(chat_id=CHAT_ID, text=plain)
                    result.messages_sent += 1
                except Exception as exc2:
                    result.errors.append(f"Send error: {exc2}")
                    result.success = False

    return result


def _split_message(text: str) -> list[str]:
    if len(text) <= MAX_MESSAGE_LENGTH:
        return [text]
    chunks: list[str] = []
    while text:
        if len(text) <= MAX_MESSAGE_LENGTH:
            chunks.append(text)
            break
        split_at = text.rfind("\n", 0, MAX_MESSAGE_LENGTH)
        if split_at == -1:
            split_at = MAX_MESSAGE_LENGTH
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(findings_json: str, target: str, report_type: str = "summary") -> str:
    try:
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except json.JSONDecodeError as exc:
        return json.dumps({"success": False, "error": f"Invalid JSON: {exc}"})

    if not isinstance(findings, list):
        all_findings: list[dict] = []
        for key in ("findings", "header_findings", "ssl_findings", "ports", "subdomains", "technologies"):
            if key in findings and isinstance(findings[key], list):
                all_findings.extend(findings[key])
        findings = all_findings

    if report_type == "summary":
        messages = [format_summary(target, findings)]
    elif report_type == "detailed":
        messages = format_detailed(target, findings)
    elif report_type == "alert":
        messages = [format_alert(target, findings)]
    else:
        messages = [format_summary(target, findings)]

    result = asyncio.run(_send_messages(messages))
    return json.dumps(asdict(result), indent=2)


if __name__ == "__main__":
    sample_findings = json.dumps([
        {
            "title": "Missing HSTS Header",
            "severity": "High",
            "url": "https://example.com",
            "category": "OWASP-A05 Security Misconfiguration",
            "evidence": "Strict-Transport-Security header not present",
            "impact": "Users may be redirected to HTTP, enabling MITM attacks.",
            "remediation": "Add Strict-Transport-Security header with max-age=31536000.",
        },
    ])
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    rt = sys.argv[2] if len(sys.argv) > 2 else "summary"
    print(run(sample_findings, target, rt))
