"""
SecureFlow Orchestrator - Main Entry Point

Runs the complete pipeline:
1. Ingest CodeQL alerts from GitHub
2. Prioritize and batch related alerts
3. Dispatch batches to Devin for remediation
4. Monitor session progress
5. Send Slack notifications
6. Update state for the dashboard

Can run as a one-shot command or in continuous polling mode.
"""

from __future__ import annotations

import sys
import time
import logging
import argparse
from config import Config
from ingest import fetch_alerts, get_alert_summary
from prioritize import group_alerts
from dispatch import dispatch_batches, DevinSession
from monitor import monitor_all_sessions, get_session_summary
from notify import (
    notify_initial_scan,
    notify_pr_ready,
    notify_session_failed,
    notify_needs_human_review,
)
from checks import check_and_retry_sessions
from state import (
    load_state,
    save_state,
    add_session_to_state,
    update_session_in_state,
    record_history,
    get_sessions_from_state,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("secureflow")


def run_pipeline(config: Config, notify: bool = True) -> dict:
    """Execute a single run of the SecureFlow pipeline."""
    state = load_state()

    # --- Step 1: Ingest ---
    logger.info("=" * 60)
    logger.info("STEP 1: Ingesting CodeQL alerts from GitHub...")
    alerts = fetch_alerts(config)

    if not alerts:
        logger.info("No open alerts found. Nothing to do.")
        return {"alerts": 0, "batches": 0, "sessions": 0}

    summary = get_alert_summary(alerts)
    logger.info(
        f"Found {summary['total']} alerts: "
        f"{summary['by_severity'].get('critical', 0)} critical, "
        f"{summary['by_severity'].get('high', 0)} high, "
        f"{summary['by_severity'].get('medium', 0)} medium, "
        f"{summary['by_severity'].get('low', 0)} low"
    )

    # --- Step 2: Prioritize ---
    logger.info("=" * 60)
    logger.info("STEP 2: Prioritizing and batching alerts...")

    # Filter out already-processed alerts
    processed = set(state.get("processed_alerts", []))
    new_alerts = [a for a in alerts if a.number not in processed]

    if not new_alerts:
        logger.info("All alerts already processed. Checking session statuses...")
    else:
        logger.info(f"{len(new_alerts)} new alerts to process.")

    batches = group_alerts(new_alerts) if new_alerts else []

    for batch in batches:
        logger.info(
            f"  {batch.batch_id}: {batch.description} "
            f"[{batch.severity.upper()}] ({batch.alert_count} alerts)"
        )

    # --- Step 3: Dispatch to Devin ---
    logger.info("=" * 60)
    logger.info("STEP 3: Dispatching to Devin...")
    existing_sessions = get_sessions_from_state(state)

    if batches:
        all_sessions = dispatch_batches(config, batches, existing_sessions)

        # Record new sessions in state
        new_session_ids = {s.session_id for s in existing_sessions}
        for session in all_sessions:
            if session.session_id not in new_session_ids:
                add_session_to_state(state, session)

        # Save batch metadata so the dashboard can show descriptions
        if "batch_info" not in state:
            state["batch_info"] = {}
        for batch in batches:
            state["batch_info"][batch.batch_id] = {
                "description": batch.description,
                "severity": batch.severity,
                "category": batch.category,
                "file_path": batch.file_path,
                "alert_count": batch.alert_count,
            }
    else:
        all_sessions = existing_sessions

    # --- Step 4: Monitor sessions ---
    logger.info("=" * 60)
    logger.info("STEP 4: Monitoring active sessions...")
    previous_statuses = {s.session_id: s.status for s in all_sessions}
    all_sessions = monitor_all_sessions(config, all_sessions)

    # --- Step 4.5: Check PR CodeQL results & retry failures ---
    logger.info("=" * 60)
    logger.info("STEP 4.5: Verifying PR CodeQL status...")
    retry_actions = check_and_retry_sessions(config, all_sessions, state)
    retried = [a for a in retry_actions if a["action"] == "retry"]
    needs_human = [a for a in retry_actions if a["action"] == "needs_human_review"]
    merged = [a for a in retry_actions if a["action"] == "merged"]
    if retried:
        logger.info(f"Sent {len(retried)} retry(s) to Devin for fixable PR failures.")
    if needs_human:
        for item in needs_human:
            logger.info(
                f"PR #{item['pr_number']}: Flagged for human review — {item['reason']}"
            )
    if merged:
        logger.info(f"{len(merged)} PR(s) already merged.")
    if not retried and not needs_human and not merged:
        logger.info("All finished PRs are passing or still in progress.")

    # --- Step 5: Notify (routed to correct channels) ---
    if notify:
        logger.info("=" * 60)
        logger.info("STEP 5: Sending notifications...")

        # #security — Initial scan report (only first time, not every run)
        if not state.get("initial_scan_sent") and summary:
            notify_initial_scan(config, summary)
            state["initial_scan_sent"] = True
            logger.info("Sent initial scan report to #security.")

        # Track which sessions we've already notified about
        notified_sessions = set(state.get("notified_sessions", []))

        for session in all_sessions:
            if session.session_id in notified_sessions:
                continue

            batch_desc = next(
                (b.description for b in batches if b.batch_id == session.batch_id),
                "Security fix",
            )

            # #engineering — PR ready for code review
            if session.status == "finished" and session.pr_url:
                notify_pr_ready(config, session, batch_desc)
                notified_sessions.add(session.session_id)

            # #security — Devin couldn't fix, needs manual remediation
            elif session.status == "failed":
                notify_session_failed(config, session, batch_desc)
                notified_sessions.add(session.session_id)

            # #security — PR has out-of-scope failing check, needs human judgment
            elif session.status == "needs_human_review":
                reason = next(
                    (a["reason"] for a in retry_actions
                     if a.get("action") == "needs_human_review"
                     and a["session_id"] == session.session_id),
                    "CodeQL check failing due to an alert outside the fix scope.",
                )
                notify_needs_human_review(config, session, batch_desc, reason)
                notified_sessions.add(session.session_id)

        state["notified_sessions"] = list(notified_sessions)

    # --- Update state ---
    for session in all_sessions:
        update_session_in_state(state, session)

    session_summary = get_session_summary(all_sessions)
    record_history(
        state,
        total_open=summary["total"],
        fixed=session_summary["finished"],
        in_progress=session_summary["running"],
    )
    save_state(state)

    # --- Report ---
    logger.info("=" * 60)
    logger.info("PIPELINE COMPLETE")
    logger.info(f"  Total alerts: {summary['total']}")
    logger.info(f"  Batches created: {len(batches)}")
    logger.info(f"  Active sessions: {session_summary['running']}")
    logger.info(f"  Completed: {session_summary['finished']}")
    logger.info(f"  PRs created: {session_summary['prs_created']}")
    logger.info(f"  Failed (needs manual): {session_summary['failed']}")

    return {
        "alerts": summary["total"],
        "batches": len(batches),
        "sessions": len(all_sessions),
        "summary": summary,
        "session_summary": session_summary,
    }


def run_continuous(config: Config):
    """Run the pipeline in a continuous loop."""
    logger.info(
        f"Starting SecureFlow in continuous mode. "
        f"Polling every {config.poll_interval}s..."
    )

    while True:
        try:
            run_pipeline(config)
        except KeyboardInterrupt:
            logger.info("Shutting down SecureFlow.")
            break
        except Exception as e:
            logger.error(f"Pipeline error: {e}", exc_info=True)

        logger.info(f"Next run in {config.poll_interval}s...")
        time.sleep(config.poll_interval)


def main():
    parser = argparse.ArgumentParser(description="SecureFlow Security Remediation Pipeline")
    parser.add_argument(
        "--mode",
        choices=["once", "continuous", "status"],
        default="once",
        help="Run mode: 'once' for single run, 'continuous' for polling, 'status' for current state",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Skip Slack notifications",
    )
    args = parser.parse_args()

    config = Config()

    if not config.github_token:
        logger.error("GITHUB_TOKEN not set. Please configure .env file.")
        sys.exit(1)

    if not config.devin_api_key:
        logger.error("DEVIN_API_KEY not set. Please configure .env file.")
        sys.exit(1)

    if args.mode == "status":
        state = load_state()
        sessions = get_sessions_from_state(state)
        summary = get_session_summary(sessions)
        print(f"\nSecureFlow Status")
        print(f"{'=' * 40}")
        print(f"Last run: {state.get('last_run', 'Never')}")
        print(f"Total sessions: {summary['total']}")
        print(f"Running: {summary['running']}")
        print(f"Finished: {summary['finished']}")
        print(f"Failed: {summary['failed']}")
        print(f"PRs created: {summary['prs_created']}")
        print(f"Alerts addressed: {summary['alerts_addressed']}")
        return

    if args.mode == "continuous":
        run_continuous(config)
    else:
        run_pipeline(config, notify=not args.no_notify)


if __name__ == "__main__":
    main()
