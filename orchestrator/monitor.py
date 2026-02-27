"""
SecureFlow Orchestrator - Session Monitor

Polls active Devin sessions, tracks status changes, and extracts
PR URLs when sessions complete. Handles blocked sessions by
providing additional context.
"""

from __future__ import annotations

import re
import time
import logging
from config import Config
from dispatch import DevinSession, get_session_status, send_message

logger = logging.getLogger(__name__)


# Map Devin API statuses to our internal statuses
STATUS_MAP = {
    "running": "running",
    "working": "running",  # Devin uses "working" for active sessions
    "blocked": "blocked",
    "stopped": "finished",
    "finished": "finished",
    "failed": "failed",
    "error": "failed",
}


def normalize_status(raw_status: str) -> str:
    """Normalize Devin API status to our internal status values."""
    return STATUS_MAP.get(raw_status, raw_status)


def update_session_status(config: Config, session: DevinSession) -> DevinSession:
    """Check the current status of a Devin session and update our tracking."""
    # Skip sessions that are already fully resolved or have been verified
    if session.status in ("merged", "closed", "review_ready", "needs_human_review"):
        return session

    # Skip failed sessions with no session ID (dispatch failures)
    if session.status == "failed" and not session.session_id:
        return session

    if not session.session_id:
        return session

    try:
        data = get_session_status(config, session.session_id)
        raw_status = data.get("status_enum", data.get("status", session.status))
        new_status = normalize_status(raw_status)

        if new_status != session.status:
            logger.info(
                f"Session {session.session_id} ({session.batch_id}): "
                f"{session.status} → {new_status} (raw: {raw_status})"
            )
            session.status = new_status
            session.updated_at = data.get("updated_at", session.updated_at)

        # Try to extract PR URL from structured output or session data
        structured = data.get("structured_output", {})
        if structured and isinstance(structured, dict):
            pr = structured.get("pull_request_url") or structured.get("pr_url")
            if pr:
                session.pr_url = pr
                logger.info(f"Session {session.session_id}: PR created at {pr}")

        # Also check for PR URL in the pull_request field (Devin sometimes uses this)
        pr_data = data.get("pull_request", {})
        if pr_data and isinstance(pr_data, dict) and not session.pr_url:
            pr_url = pr_data.get("url") or pr_data.get("html_url")
            if pr_url:
                session.pr_url = pr_url
                logger.info(f"Session {session.session_id}: PR found at {pr_url}")

    except Exception as e:
        logger.error(f"Error polling session {session.session_id}: {e}")

    return session


def handle_blocked_session(config: Config, session: DevinSession) -> None:
    """If Devin is blocked and hasn't created a PR yet, try to unblock it."""
    if session.status != "blocked":
        return

    # If the session already has a PR, don't send generic unblock message.
    # Step 4.5 (checks.py) handles blocked sessions with PRs — it checks
    # CodeQL status and sends a targeted retry if needed.
    if session.pr_url:
        logger.info(
            f"Session {session.session_id} is blocked with PR {session.pr_url}. "
            f"Step 4.5 will handle CodeQL check verification."
        )
        return

    logger.info(
        f"Session {session.session_id} is blocked (no PR yet). Sending guidance..."
    )
    try:
        send_message(
            config,
            session.session_id,
            "Please continue with the security fix. If you need repository access, "
            "the repo should already be connected via GitHub integration. "
            "Focus on fixing the CodeQL alerts described in the original task. "
            "Create a PR when done.",
        )
    except Exception as e:
        logger.error(f"Failed to send unblock message: {e}")


def monitor_all_sessions(
    config: Config, sessions: list[DevinSession]
) -> list[DevinSession]:
    """Update status for all active sessions."""
    updated = []
    for session in sessions:
        session = update_session_status(config, session)

        if session.status == "blocked":
            handle_blocked_session(config, session)

        updated.append(session)

    # Log summary
    statuses = {}
    for s in updated:
        statuses[s.status] = statuses.get(s.status, 0) + 1
    logger.info(f"Session status summary: {statuses}")

    return updated


def get_session_summary(sessions: list[DevinSession]) -> dict:
    """Get a summary of all session statuses for the dashboard."""
    summary = {
        "total": len(sessions),
        "running": 0,
        "blocked": 0,
        "finished": 0,
        "failed": 0,
        "needs_review": 0,
        "prs_created": 0,
        "alerts_addressed": 0,
        "sessions": [],
    }

    for session in sessions:
        status = session.status
        # Map our internal statuses to summary buckets
        if status in ("running", "working"):
            summary["running"] += 1
        elif status == "blocked":
            summary["blocked"] += 1
        elif status in ("finished", "review_ready", "merged", "closed"):
            summary["finished"] += 1
        elif status in ("failed", "error"):
            summary["failed"] += 1
        elif status == "needs_human_review":
            summary["needs_review"] += 1

        if session.pr_url:
            summary["prs_created"] += 1
        summary["alerts_addressed"] += len(session.alert_numbers)
        summary["sessions"].append(session.to_dict())

    return summary
