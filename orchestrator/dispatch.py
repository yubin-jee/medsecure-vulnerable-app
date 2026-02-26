"""
SecureFlow Orchestrator - Devin Dispatcher

Creates and manages Devin sessions for security remediation.
Each batch of related alerts gets a single Devin session with a
carefully crafted prompt including CodeQL guidance.
"""

from __future__ import annotations

import requests
import logging
import json
from dataclasses import dataclass, field
from datetime import datetime
from config import Config
from prioritize import AlertBatch

logger = logging.getLogger(__name__)


@dataclass
class DevinSession:
    """Tracks a Devin session and its associated alert batch."""
    session_id: str
    batch_id: str
    alert_numbers: list[int]
    status: str  # running, blocked, finished, failed
    url: str  # link to Devin UI
    pr_url: str | None = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "batch_id": self.batch_id,
            "alert_numbers": self.alert_numbers,
            "status": self.status,
            "url": self.url,
            "pr_url": self.pr_url,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "error": self.error,
        }


def build_prompt(batch: AlertBatch) -> str:
    """
    Craft a detailed prompt for Devin that includes all the context
    needed to fix the security issues in this batch.
    """
    alerts = batch.alerts
    primary_alert = alerts[0]

    prompt = f"""You are fixing security vulnerabilities identified by CodeQL in this repository.

## Task
Fix {len(alerts)} {batch.category} issue(s) in `{batch.file_path}`.

## Alerts to Fix
"""

    for alert in alerts:
        prompt += f"""
### Alert #{alert.number}: {alert.rule_name}
- **Severity**: {alert.security_severity.upper()}
- **CWE**: {', '.join(alert.cwe_ids) if alert.cwe_ids else 'N/A'}
- **Location**: `{alert.file_path}`, line {alert.start_line}
- **Description**: {alert.message or alert.rule_description}
"""

    # Include CodeQL's help text (has fix examples) from the first alert
    if primary_alert.help_text:
        prompt += f"""
## CodeQL Remediation Guidance
{primary_alert.help_text[:2000]}
"""

    prompt += f"""
## Requirements
1. Fix ALL {len(alerts)} alert(s) listed above in `{batch.file_path}`
2. Use secure coding practices (parameterized queries, input validation, etc.)
3. Ensure the fix doesn't break existing functionality
4. Run any existing tests to verify
5. Create a pull request with:
   - Title: "fix: remediate {batch.category} in {batch.file_path}"
   - Description that references each CodeQL alert number
   - Clear explanation of what was changed and why

## Important
- Do NOT just suppress the warnings — actually fix the underlying vulnerability
- Follow the existing code style and patterns in the repository
- If a fix requires adding a dependency (e.g., a sanitization library), that's acceptable
"""

    return prompt


def create_session(config: Config, batch: AlertBatch) -> DevinSession:
    """Create a new Devin session to fix a batch of alerts."""
    prompt = build_prompt(batch)

    payload = {
        "prompt": prompt,
        "idempotent": False,
    }

    logger.info(
        f"Creating Devin session for {batch.batch_id} "
        f"({batch.alert_count} alerts, {batch.severity} severity)..."
    )

    response = requests.post(
        f"{config.devin_api_base}/sessions",
        headers=config.devin_headers,
        json=payload,
    )
    response.raise_for_status()
    data = response.json()

    session = DevinSession(
        session_id=data.get("session_id", ""),
        batch_id=batch.batch_id,
        alert_numbers=[a.number for a in batch.alerts],
        status=data.get("status", "running"),
        url=data.get("url", ""),
    )

    logger.info(
        f"Session {session.session_id} created for {batch.batch_id}. "
        f"URL: {session.url}"
    )
    return session


def get_session_status(config: Config, session_id: str) -> dict:
    """Poll Devin for the current status of a session."""
    response = requests.get(
        f"{config.devin_api_base}/sessions/{session_id}",
        headers=config.devin_headers,
    )
    response.raise_for_status()
    return response.json()


def send_message(config: Config, session_id: str, message: str) -> dict:
    """Send a follow-up message to a Devin session."""
    response = requests.post(
        f"{config.devin_api_base}/sessions/{session_id}/message",
        headers=config.devin_headers,
        json={"message": message},
    )
    response.raise_for_status()
    return response.json()


def dispatch_batches(
    config: Config,
    batches: list[AlertBatch],
    existing_sessions: list[DevinSession],
) -> list[DevinSession]:
    """
    Dispatch batches to Devin, respecting concurrency limits.
    Skips batches that already have active sessions.
    """
    active_sessions = [
        s for s in existing_sessions if s.status in ("running", "working", "blocked")
    ]
    active_batch_ids = {s.batch_id for s in active_sessions}
    available_slots = config.max_concurrent_sessions - len(active_sessions)

    if available_slots <= 0:
        logger.info(
            f"All {config.max_concurrent_sessions} session slots in use. "
            f"Waiting for sessions to complete."
        )
        return existing_sessions

    new_sessions = []
    for batch in batches:
        if batch.batch_id in active_batch_ids:
            logger.debug(f"Skipping {batch.batch_id} — already has an active session.")
            continue

        if available_slots <= 0:
            logger.info(f"Reached concurrent session limit. Queued remaining batches.")
            break

        try:
            session = create_session(config, batch)
            new_sessions.append(session)
            available_slots -= 1
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create session for {batch.batch_id}: {e}")
            # Stop dispatching on rate limit — don't hammer the API
            if "429" in str(e):
                logger.error("Rate limited by Devin API. Stopping dispatch.")
                break
            new_sessions.append(
                DevinSession(
                    session_id="",
                    batch_id=batch.batch_id,
                    alert_numbers=[a.number for a in batch.alerts],
                    status="failed",
                    url="",
                    error=str(e),
                )
            )

    all_sessions = existing_sessions + new_sessions
    logger.info(
        f"Dispatched {len(new_sessions)} new sessions. "
        f"Total active: {len([s for s in all_sessions if s.status == 'running'])}."
    )
    return all_sessions
