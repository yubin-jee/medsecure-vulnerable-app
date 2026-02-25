"""
SecureFlow Orchestrator - State Persistence

Simple JSON-based state management to track progress across runs.
Stores alert history, session mappings, and burndown data.
"""

from __future__ import annotations

import json
import os
import logging
from datetime import datetime
from dispatch import DevinSession
from ingest import CodeQLAlert

logger = logging.getLogger(__name__)

STATE_FILE = os.path.join(os.path.dirname(__file__), "state.json")


def load_state() -> dict:
    """Load the orchestrator state from disk."""
    if not os.path.exists(STATE_FILE):
        return {
            "sessions": [],
            "processed_alerts": [],
            "notified_sessions": [],
            "history": [],
            "last_run": None,
        }

    with open(STATE_FILE, "r") as f:
        return json.load(f)


def save_state(state: dict) -> None:
    """Persist the orchestrator state to disk."""
    state["last_run"] = datetime.utcnow().isoformat()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)
    logger.debug(f"State saved to {STATE_FILE}")


def add_session_to_state(state: dict, session: DevinSession) -> None:
    """Record a new Devin session in state."""
    state["sessions"].append(session.to_dict())
    state["processed_alerts"].extend(session.alert_numbers)


def update_session_in_state(state: dict, session: DevinSession) -> None:
    """Update an existing session's status in state."""
    for i, s in enumerate(state["sessions"]):
        if s["session_id"] == session.session_id:
            state["sessions"][i] = session.to_dict()
            return


def record_history(state: dict, total_open: int, fixed: int, in_progress: int) -> None:
    """Record a data point for the burndown chart."""
    state["history"].append(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "total_open": total_open,
            "fixed": fixed,
            "in_progress": in_progress,
        }
    )


def get_sessions_from_state(state: dict) -> list[DevinSession]:
    """Reconstruct DevinSession objects from state."""
    sessions = []
    for s in state.get("sessions", []):
        sessions.append(
            DevinSession(
                session_id=s["session_id"],
                batch_id=s["batch_id"],
                alert_numbers=s["alert_numbers"],
                status=s["status"],
                url=s["url"],
                pr_url=s.get("pr_url"),
                created_at=s.get("created_at", ""),
                updated_at=s.get("updated_at", ""),
                error=s.get("error"),
            )
        )
    return sessions
