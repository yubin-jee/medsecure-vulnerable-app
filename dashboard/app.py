"""
SecureFlow Dashboard - FastAPI Web Application

Provides a visual dashboard for tracking the security remediation pipeline:
- Alert burndown chart
- Active Devin session status
- PR links and review status
- Severity breakdown
- Remediation queue
- Action items requiring human attention
"""

from __future__ import annotations

import sys
import os

# Add orchestrator to path so we can import its modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "orchestrator"))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

import logging
import requests

from config import Config
from state import load_state, save_state, get_sessions_from_state
from monitor import get_session_summary
from ingest import fetch_alerts, get_alert_summary
from prioritize import group_alerts
from checks import extract_pr_number

logger = logging.getLogger(__name__)

# Healthcare business impact constants
# HIPAA penalty tiers (inflation-adjusted 2024, per 42 USC 1320d-5 / HITECH Act)
HIPAA_TIER3_PER_VIOLATION = 13_785   # willful neglect, corrected within 30 days
HIPAA_TIER4_PER_VIOLATION = 68_928   # willful neglect, NOT corrected within 30 days
# IBM Cost of a Data Breach 2024 — healthcare sector
BREACH_COST_PER_RECORD = 408
ESTIMATED_RECORDS_AT_RISK = 50_000   # MedSecure patient database estimate
AVG_BREACH_COST_HEALTHCARE = 9_770_000
# Industry average MTTR for code vulnerabilities
INDUSTRY_AVG_MTTR_DAYS = 58
# Vulnerability type weights — higher weight = more direct PHI exposure risk
VULN_RISK_WEIGHTS = {
    "SQL Injection": 1.5,
    "Command Injection": 1.5,
    "Hardcoded Credentials": 1.5,
    "Weak Cryptography": 1.3,
    "Insufficient Key Size": 1.3,
    "Stored XSS": 1.2,
    "Cross-Site Scripting (XSS)": 1.2,
    "Server-Side Request Forgery": 1.2,
    "Path Traversal": 1.2,
    "Unsafe Deserialization": 1.2,
}
DEFAULT_VULN_WEIGHT = 1.0

app = FastAPI(title="SecureFlow Dashboard")

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


def get_queued_batches(state, alerts):
    """Figure out which batches haven't been dispatched yet."""
    processed = set(state.get("processed_alerts", []))
    new_alerts = [a for a in alerts if a.number not in processed]

    if not new_alerts:
        return []

    batches = group_alerts(new_alerts)

    # Convert to dicts for the template
    return [b.to_dict() for b in batches]


def enrich_sessions(session_dicts, state):
    """Add description and severity info to session dicts for display."""
    # Build a map from batch descriptions stored during dispatch
    batch_info = state.get("batch_info", {})

    for session in session_dicts:
        batch_id = session.get("batch_id", "")
        info = batch_info.get(batch_id, {})
        session["description"] = info.get("description", "")
        session["severity"] = info.get("severity", "medium")
        session["category"] = info.get("category", "")
        session["file_path"] = info.get("file_path", "")

        # Confidence score based on retry count
        retries = session.get("retry_count", 0)
        if retries == 0:
            session["confidence"] = "high"
            session["confidence_order"] = 2
        elif retries == 1:
            session["confidence"] = "medium"
            session["confidence_order"] = 1
        else:
            session["confidence"] = "low"
            session["confidence_order"] = 0

    return session_dicts


def sync_pr_states(config: Config, session_dicts: list[dict], state: dict) -> None:
    """Check live PR state from GitHub and update sessions that have been merged.

    This fixes stale state when a human merges a PR outside the orchestrator
    cycle.  Only queries GitHub for sessions that have a PR and aren't already
    resolved, so the cost is minimal (one API call per unresolved PR).
    Updates are written back to state.json so the orchestrator stays in sync.
    """
    dirty = False

    for session in session_dicts:
        pr_url = session.get("pr_url")
        status = session.get("status", "")

        # Only check sessions that have a PR and aren't already resolved
        if not pr_url or status in ("merged", "closed"):
            continue

        try:
            pr_number = extract_pr_number(pr_url)
            api_url = (
                f"{config.github_api_base}/repos/{config.github_owner}"
                f"/{config.github_repo}/pulls/{pr_number}"
            )
            resp = requests.get(api_url, headers=config.github_headers, timeout=5)
            resp.raise_for_status()
            pr_data = resp.json()

            merged = pr_data.get("merged", False)
            pr_state = pr_data.get("state", "open")

            if merged:
                session["status"] = "merged"
                dirty = True
            elif pr_state == "closed":
                session["status"] = "closed"
                dirty = True
        except Exception as e:
            logger.warning(f"Failed to check live PR state for {pr_url}: {e}")

    # Persist changes back to state.json so the orchestrator stays in sync
    if dirty:
        for st_session in state.get("sessions", []):
            for live in session_dicts:
                if st_session.get("session_id") == live.get("session_id"):
                    st_session["status"] = live["status"]
        save_state(state)


def compute_pipeline_stages(alert_summary, session_dicts, queued_batches):
    """Compute counts for each pipeline stage.

    Counts PRs (sessions), not individual alerts, so the numbers match
    what engineers actually see on GitHub.
    """
    total_open = alert_summary.get("total", 0)

    # Count sessions in each stage
    devin_working = 0
    pr_created = 0
    engineer_review = 0
    resolved = 0

    # Also count alerts for the "detected" calculation
    alerts_in_pipeline = 0

    for s in session_dicts:
        status = s.get("status", "")
        has_pr = bool(s.get("pr_url"))
        alert_count = len(s.get("alert_numbers", []))

        if status in ("merged", "closed"):
            resolved += 1
            alerts_in_pipeline += alert_count
        elif status in ("needs_human_review", "review_ready"):
            engineer_review += 1
            alerts_in_pipeline += alert_count
        elif status == "finished" and has_pr:
            pr_created += 1
            alerts_in_pipeline += alert_count
        elif has_pr:
            # Has a PR but still running/blocked (Devin retrying)
            pr_created += 1
            alerts_in_pipeline += alert_count
        elif status in ("running", "working", "blocked", "finished"):
            devin_working += 1
            alerts_in_pipeline += alert_count

    # "Detected" = total open alerts minus those already being worked on
    detected = max(0, total_open - alerts_in_pipeline)

    return {
        "detected": detected,
        "devin_working": devin_working,
        "pr_created": pr_created,
        "engineer_review": engineer_review,
        "resolved": resolved,
    }


def compute_business_impact(alert_summary, session_dicts, batch_info):
    """Compute healthcare-specific business impact metrics."""
    from datetime import datetime

    by_sev = alert_summary.get("by_severity", {})
    critical_open = by_sev.get("critical", 0)
    high_open = by_sev.get("high", 0)

    # Metric 1: HIPAA Risk Exposure
    hipaa_exposure = (
        critical_open * HIPAA_TIER4_PER_VIOLATION
        + high_open * HIPAA_TIER3_PER_VIOLATION
    )

    # Metric 2: MTTR — average time from session creation to PR creation
    mttr_minutes = None
    session_times = []
    for s in session_dicts:
        if s.get("pr_url") and s.get("created_at") and s.get("updated_at"):
            try:
                # Normalize timestamps: strip Z suffix and timezone info
                # for simple delta calculation (both are UTC)
                c = s["created_at"].replace("Z", "").split("+")[0]
                u = s["updated_at"].replace("Z", "").split("+")[0]
                created = datetime.fromisoformat(c)
                updated = datetime.fromisoformat(u)
                delta = (updated - created).total_seconds() / 60
                if delta > 0:
                    session_times.append(delta)
            except (ValueError, TypeError):
                pass
    if session_times:
        mttr_minutes = round(sum(session_times) / len(session_times))

    # Metric 3: Breach Risk Reduction
    resolved_alerts = 0
    total_tracked = alert_summary.get("total", 0)
    weighted_resolved = 0.0
    weighted_total = 0.0

    for s in session_dicts:
        alert_count = len(s.get("alert_numbers", []))
        info = batch_info.get(s.get("batch_id", ""), {})
        category = info.get("category", "")
        weight = VULN_RISK_WEIGHTS.get(category, DEFAULT_VULN_WEIGHT)

        weighted_total += alert_count * weight
        if s.get("status") in ("merged", "closed"):
            resolved_alerts += alert_count
            weighted_resolved += alert_count * weight

    unprocessed = max(0, total_tracked - sum(
        len(s.get("alert_numbers", [])) for s in session_dicts
    ))
    weighted_total += unprocessed * DEFAULT_VULN_WEIGHT

    if weighted_total > 0:
        risk_reduced = round(
            (weighted_resolved / weighted_total) * AVG_BREACH_COST_HEALTHCARE
        )
    else:
        risk_reduced = 0

    return {
        "hipaa_exposure": hipaa_exposure,
        "hipaa_critical_count": critical_open,
        "hipaa_critical_rate": HIPAA_TIER4_PER_VIOLATION,
        "hipaa_high_count": high_open,
        "hipaa_high_rate": HIPAA_TIER3_PER_VIOLATION,
        "mttr_minutes": mttr_minutes,
        "mttr_sessions_counted": len(session_times),
        "industry_mttr_days": INDUSTRY_AVG_MTTR_DAYS,
        "risk_reduced": risk_reduced,
        "risk_total_exposure": AVG_BREACH_COST_HEALTHCARE,
        "risk_pct_resolved": round((weighted_resolved / weighted_total * 100) if weighted_total > 0 else 0),
        "resolved_alerts": resolved_alerts,
    }


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page."""
    state = load_state()
    sessions = get_sessions_from_state(state)
    session_summary = get_session_summary(sessions)
    history = state.get("history", [])

    config = Config()

    # Try to get live alert data, fall back to state
    alerts = []
    try:
        alerts = fetch_alerts(config)
        alert_summary = get_alert_summary(alerts)
    except Exception:
        alert_summary = {
            "total": len(state.get("processed_alerts", [])),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_rule": {},
            "by_file": {},
        }

    # Get queued batches (not yet dispatched)
    queued_batches = []
    try:
        if alerts:
            queued_batches = get_queued_batches(state, alerts)
    except Exception:
        pass

    # Enrich session data with descriptions
    session_dicts = enrich_sessions(session_summary.get("sessions", []), state)

    # Live-sync PR states from GitHub (catches merges done outside orchestrator)
    sync_pr_states(config, session_dicts, state)

    # Compute pipeline stages for flow visualization
    pipeline_stages = compute_pipeline_stages(alert_summary, session_dicts, queued_batches)

    # Compute business impact metrics
    batch_info = state.get("batch_info", {})
    business_impact = compute_business_impact(alert_summary, session_dicts, batch_info)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "alert_summary": alert_summary,
            "session_summary": session_summary,
            "history": history,
            "sessions": session_dicts,
            "queued_batches": queued_batches,
            "pipeline_stages": pipeline_stages,
            "business_impact": business_impact,
            "max_concurrent": config.max_concurrent_sessions,
            "last_run": state.get("last_run", "Never"),
        },
    )


@app.get("/api/status")
async def api_status():
    """JSON endpoint for dashboard auto-refresh."""
    state = load_state()
    sessions = get_sessions_from_state(state)
    session_summary = get_session_summary(sessions)

    return {
        "last_run": state.get("last_run"),
        "session_summary": session_summary,
        "history": state.get("history", []),
    }


@app.get("/api/alerts")
async def api_alerts():
    """Fetch live alert data from GitHub."""
    config = Config()
    try:
        alerts = fetch_alerts(config)
        summary = get_alert_summary(alerts)
        return {
            "alerts": [a.to_dict() for a in alerts],
            "summary": summary,
        }
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    config = Config()
    uvicorn.run(app, host="0.0.0.0", port=config.dashboard_port)
