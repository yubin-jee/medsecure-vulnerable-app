"""
SecureFlow Orchestrator - Slack Notification Module

Routes notifications to the right channel with the right audience:

#security  — Critical/high fix completions, needs-human-review, failed sessions
#engineering — PR review requests (one per PR, targeted)
#all       — Weekly burndown summary for management (not per-run spam)

Design principles:
- Never send the full scan summary every run. Only on first scan or when counts change significantly.
- PR notifications go to #engineering only.
- Security-relevant events (failures, human review needed) go to #security only.
- Management gets a weekly digest, not real-time noise.
"""

from __future__ import annotations

import requests
import logging
from datetime import datetime
from typing import Optional
from config import Config
from ingest import CodeQLAlert
from dispatch import DevinSession

logger = logging.getLogger(__name__)


# --- Low-level sender ---

def _send(webhook_url: str, blocks: list[dict]) -> bool:
    """Send Block Kit message to a specific Slack webhook."""
    if not webhook_url:
        logger.warning("No webhook URL provided. Skipping.")
        return False
    try:
        resp = requests.post(webhook_url, json={"blocks": blocks})
        resp.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Slack send failed: {e}")
        return False


def _webhook_for(config: Config, channel: str) -> str:
    """Resolve webhook URL for a channel, falling back to the default."""
    mapping = {
        "security": config.slack_webhook_security,
        "engineering": config.slack_webhook_engineering,
        "all": config.slack_webhook_all,
    }
    url = mapping.get(channel, "")
    return url or config.slack_webhook_url


def send_to(config: Config, channel: str, blocks: list[dict]) -> bool:
    """Send a message to a named channel."""
    url = _webhook_for(config, channel)
    if not url:
        logger.warning(f"No webhook configured for #{channel}. Skipping.")
        return False
    ok = _send(url, blocks)
    if ok:
        logger.info(f"Sent notification to #{channel}.")
    return ok


# --- #security channel ---

def notify_initial_scan(config: Config, summary: dict) -> bool:
    """
    Send once when SecureFlow first connects to a repo.
    NOT sent on every run — only when there are genuinely new alerts
    the security team hasn't seen.
    """
    sev_lines = []
    for sev, emoji in [("critical", ":red_circle:"), ("high", ":large_orange_circle:"),
                        ("medium", ":large_yellow_circle:"), ("low", ":white_circle:")]:
        count = summary["by_severity"].get(sev, 0)
        if count > 0:
            sev_lines.append(f"{emoji} {sev.upper()}: {count}")

    top_rules = sorted(summary["by_rule"].items(), key=lambda x: -x[1])[:5]
    rules_text = "\n".join(f"• {rule}: {count}" for rule, count in top_rules)

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "SecureFlow — Initial Scan Report"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{summary['total']} open CodeQL alerts* in "
                    f"`{config.github_owner}/{config.github_repo}`\n\n"
                    + "\n".join(sev_lines)
                ),
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Top categories:*\n{rules_text}",
            },
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": (
                "SecureFlow is now actively remediating these alerts via Devin. "
                "You'll receive targeted notifications as fixes are completed."
            )}],
        },
    ]

    return send_to(config, "security", blocks)


def notify_needs_human_review(
    config: Config,
    session: DevinSession,
    batch_description: str,
    reason: str,
) -> bool:
    """
    #security — A PR has a failing CodeQL check that Devin can't resolve.
    Needs a human to review whether it's a false positive or out-of-scope alert.
    """
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Human Review Required"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"Devin completed a fix but the CodeQL check is still failing "
                    f"due to an issue outside the fix scope.\n\n"
                    f"*Fix:* {batch_description}\n"
                    f"*PR:* <{session.pr_url}|View PR>\n"
                    f"*Reason:* {reason}\n\n"
                    f"A security engineer should review the PR and either merge "
                    f"(if the remaining alert is unrelated) or dismiss the false positive."
                ),
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Review PR"},
                    "url": session.pr_url or session.url,
                    "style": "primary",
                },
            ],
        },
    ]

    return send_to(config, "security", blocks)


def notify_session_failed(
    config: Config, session: DevinSession, batch_description: str
) -> bool:
    """#security — Devin couldn't fix this, needs manual remediation."""
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Fix Failed — Manual Remediation Needed"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"Devin was unable to automatically fix:\n\n"
                    f"*Issue:* {batch_description}\n"
                    f"*Alerts:* {', '.join(f'#{n}' for n in session.alert_numbers)}\n"
                    f"*Error:* {session.error or 'Session did not complete'}\n\n"
                    f"This needs to be assigned to an engineer for manual fix."
                ),
            },
        },
    ]

    return send_to(config, "security", blocks)


# --- #engineering channel ---

def notify_pr_ready(
    config: Config, session: DevinSession, batch_description: str
) -> bool:
    """
    #engineering — A specific PR is ready for code review.
    One message per PR. Tells the engineer exactly what was fixed and where.
    """
    if not session.pr_url:
        return False

    pr_num = session.pr_url.rstrip("/").split("/")[-1]

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"PR #{pr_num} — Security Fix Ready for Review"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*What was fixed:* {batch_description}\n"
                    f"*Alerts resolved:* {', '.join(f'#{n}' for n in session.alert_numbers)}\n"
                    f"*PR:* <{session.pr_url}|View PR #{pr_num}>"
                ),
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Review PR"},
                    "url": session.pr_url,
                    "style": "primary",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in Devin"},
                    "url": session.url,
                },
            ],
        },
    ]

    return send_to(config, "engineering", blocks)


# --- #all channel (management) ---

def notify_weekly_digest(
    config: Config,
    total_alerts: int,
    fixed_this_week: int,
    remaining: int,
    prs_merged: int,
    prs_open: int,
) -> bool:
    """
    #all — Weekly burndown summary for management.
    Sent once per week (caller is responsible for scheduling).
    """
    progress_pct = (
        round((fixed_this_week / total_alerts) * 100) if total_alerts > 0 else 0
    )
    filled = int(progress_pct / 5)
    bar = "█" * filled + "░" * (20 - filled)

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "SecureFlow — Weekly Security Report"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Security Backlog Burndown*\n\n"
                    f"`{bar}` {progress_pct}%\n\n"
                    f"*Fixed this week:* {fixed_this_week}\n"
                    f"*PRs merged:* {prs_merged}\n"
                    f"*PRs awaiting review:* {prs_open}\n"
                    f"*Remaining alerts:* {remaining}\n"
                    f"*Total tracked:* {total_alerts}"
                ),
            },
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": (
                f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | "
                f"Powered by SecureFlow + Devin"
            )}],
        },
    ]

    return send_to(config, "all", blocks)
