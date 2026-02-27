"""
SecureFlow Orchestrator - Slack Notification Module

Two-channel strategy:
  #security   = Command Center — sees the full autonomous lifecycle
  #engineering = Action Inbox  — only sees "review this PR"

Design principles:
- #security sees: scan report, retries (self-healing), resolutions, failures
- #engineering sees: only PRs that need a human to click "merge"
- Confidence scoring on PR review requests helps engineers prioritize
- One notification per event per session (deduped by caller via notified_sessions)
"""

from __future__ import annotations

import requests
import logging
from datetime import datetime
from typing import Optional
from config import Config
from dispatch import DevinSession

logger = logging.getLogger(__name__)


# --- Low-level sender ---

def _send(webhook_url: str, blocks: list[dict]) -> bool:
    """Send Block Kit message to a specific Slack webhook."""
    if not webhook_url:
        logger.warning("No webhook URL provided. Skipping.")
        return False
    try:
        resp = requests.post(webhook_url, json={"blocks": blocks}, timeout=10)
        resp.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Slack send failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Slack response body: {e.response.text[:200]}")
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


# ---------------------------------------------------------------------------
# #security channel — "Command Center"
#
# Security team sees the full autonomous lifecycle:
#   scan report → retry (self-healing) → resolved → failures
# ---------------------------------------------------------------------------

def notify_initial_scan(config: Config, summary: dict) -> bool:
    """
    #security — Sent once when SecureFlow first connects to a repo.
    Shows the scope of the problem and that autonomous remediation has begun.
    """
    sev_lines = []
    for sev, emoji in [("critical", ":red_circle:"), ("high", ":large_orange_circle:"),
                        ("medium", ":large_yellow_circle:"), ("low", ":white_circle:")]:
        count = summary["by_severity"].get(sev, 0)
        if count > 0:
            sev_lines.append(f"{emoji} {sev.upper()}: {count}")

    top_rules = sorted(summary["by_rule"].items(), key=lambda x: -x[1])[:5]
    rules_text = "\n".join(f"  {rule}: {count}" for rule, count in top_rules)

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
                    f"*{summary['total']} open CodeQL alerts* detected in "
                    f"`{config.github_owner}/{config.github_repo}`\n\n"
                    + "\n".join(sev_lines)
                    + f"\n\n*Top vulnerability categories:*\n{rules_text}"
                ),
            },
        },
        {"type": "divider"},
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": (
                "SecureFlow is dispatching the highest-priority batches to Devin for "
                "autonomous remediation. You'll be notified as fixes are verified and "
                "ready for engineer review."
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
    Needs a human to determine if it's a false positive or pre-existing alert.
    """
    pr_num = session.pr_url.rstrip("/").split("/")[-1] if session.pr_url else "?"

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
                    f"Devin's fix for *{batch_description}* is complete, but a "
                    f"CodeQL check is failing due to an issue outside the fix scope.\n\n"
                    f"*PR:* <{session.pr_url}|#{pr_num}>\n"
                    f"*Reason:* {reason}\n\n"
                    f"A security engineer should review and either merge "
                    f"(if the failing alert is unrelated) or dismiss the false positive."
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
    """#security — Devin couldn't fix this vulnerability. Needs manual remediation."""
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
                    f"Devin was unable to automatically fix *{batch_description}*.\n\n"
                    f"*Alerts:* {', '.join(f'#{n}' for n in session.alert_numbers)}\n"
                    f"*Error:* {session.error or 'Session did not complete'}\n\n"
                    f"This needs to be assigned to an engineer for manual remediation."
                ),
            },
        },
    ]

    return send_to(config, "security", blocks)


def notify_retry_sent(
    config: Config,
    session: DevinSession,
    batch_description: str,
    remaining_alerts: int,
) -> bool:
    """
    #security — A PR failed CodeQL re-check. Devin is auto-retrying.
    This is the "self-healing" moment — shows the system catches its own mistakes.
    """
    pr_num = session.pr_url.rstrip("/").split("/")[-1] if session.pr_url else "?"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"Auto-Retry: PR #{pr_num} Failed CodeQL"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"Devin's fix for *{batch_description}* introduced "
                    f"{remaining_alerts} new CodeQL finding(s). "
                    f"A retry has been sent automatically.\n\n"
                    f"*PR:* <{session.pr_url}|#{pr_num}>\n"
                    f"*Retry #:* {session.retry_count}\n"
                    f"*Devin:* <{session.url}|View Session>"
                ),
            },
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": (
                "No action needed — Devin is re-analyzing the failing checks "
                "and will push a fix to the same PR."
            )}],
        },
    ]

    return send_to(config, "security", blocks)


def notify_alert_resolved(
    config: Config,
    session: DevinSession,
    batch_description: str,
) -> bool:
    """
    #security — A vulnerability has been verified fixed (PR passed CodeQL).
    Closes the loop for the security team — they see risk being eliminated.
    """
    pr_num = session.pr_url.rstrip("/").split("/")[-1] if session.pr_url else "?"
    alert_count = len(session.alert_numbers)
    retries = session.retry_count

    retry_note = ""
    if retries > 0:
        retry_note = f" after {retries} retry(s)"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"Resolved: {batch_description}"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f":white_check_mark: *{alert_count} alert(s) remediated{retry_note}*\n\n"
                    f"PR <{session.pr_url}|#{pr_num}> passed all CodeQL checks "
                    f"and is awaiting engineer merge.\n"
                    f"*Alerts:* {', '.join(f'#{n}' for n in session.alert_numbers)}"
                ),
            },
        },
    ]

    return send_to(config, "security", blocks)


# ---------------------------------------------------------------------------
# #engineering channel — "Action Inbox"
#
# Engineers only get pinged when a human needs to act.
# Confidence scoring helps them prioritize which PRs to review first.
# ---------------------------------------------------------------------------

def notify_pr_ready(
    config: Config, session: DevinSession, batch_description: str
) -> bool:
    """
    #engineering — A specific PR is ready for code review.
    One message per PR. Tells the engineer exactly what was fixed and where.
    Includes confidence score based on retry count to help prioritize review.
    """
    if not session.pr_url:
        return False

    pr_num = session.pr_url.rstrip("/").split("/")[-1]

    confidence = session.confidence
    if confidence == "low":
        conf_emoji = ":red_circle:"
        conf_text = "LOW — multiple retries, review carefully"
    elif confidence == "medium":
        conf_emoji = ":large_yellow_circle:"
        conf_text = "MEDIUM — required 1 retry"
    else:
        conf_emoji = ":large_green_circle:"
        conf_text = "HIGH — passed all checks first try"

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
                    f"{conf_emoji} *Confidence: {conf_text}*\n\n"
                    f"*What was fixed:* {batch_description}\n"
                    f"*Alerts resolved:* {', '.join(f'#{n}' for n in session.alert_numbers)}\n"
                    f"*Retries:* {session.retry_count}\n"
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


# ---------------------------------------------------------------------------
# #all channel (management)
# ---------------------------------------------------------------------------

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
