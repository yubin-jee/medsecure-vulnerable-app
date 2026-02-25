"""
SecureFlow Orchestrator - PR Check Monitor & Retry

Checks whether PRs created by Devin pass CodeQL checks.
Three outcomes:
1. CodeQL passing → mark as verified
2. CodeQL failing with fixable alerts → send Devin a retry
3. CodeQL failing with no clear alerts → flag for human review (out-of-scope alert)
"""

from __future__ import annotations

import requests
import logging
from config import Config
from dispatch import DevinSession, send_message

logger = logging.getLogger(__name__)


def get_pr_check_status(config: Config, pr_number: int) -> dict:
    """Get the CodeQL check status and PR state for a specific PR."""
    pr_url = (
        f"{config.github_api_base}/repos/{config.github_owner}/{config.github_repo}"
        f"/pulls/{pr_number}"
    )
    resp = requests.get(pr_url, headers=config.github_headers)
    resp.raise_for_status()
    pr_data = resp.json()
    head_sha = pr_data["head"]["sha"]
    branch = pr_data["head"]["ref"]
    pr_state = pr_data["state"]  # "open" or "closed"
    merged = pr_data.get("merged", False)

    # Get check runs for this commit
    checks_url = (
        f"{config.github_api_base}/repos/{config.github_owner}/{config.github_repo}"
        f"/commits/{head_sha}/check-runs"
    )
    resp = requests.get(checks_url, headers=config.github_headers)
    resp.raise_for_status()
    checks = resp.json()

    codeql_status = "unknown"
    for run in checks.get("check_runs", []):
        if run["name"] == "CodeQL":
            codeql_status = run.get("conclusion") or run.get("status", "unknown")
            break

    # Get code scanning alerts on the PR merge ref
    # IMPORTANT: GitHub's branch ref often returns 0 alerts even when the PR
    # has failing checks. The merge ref (refs/pull/N/merge) is what CodeQL
    # actually analyzes, so we must query that instead.
    alerts_url = (
        f"{config.github_api_base}/repos/{config.github_owner}/{config.github_repo}"
        f"/code-scanning/alerts?ref=refs/pull/{pr_number}/merge&state=open"
    )
    try:
        resp = requests.get(alerts_url, headers=config.github_headers)
        resp.raise_for_status()
        open_alerts = resp.json()
    except Exception:
        open_alerts = []

    return {
        "pr_number": pr_number,
        "head_sha": head_sha,
        "branch": branch,
        "pr_state": pr_state,
        "merged": merged,
        "codeql_status": codeql_status,
        "open_alerts_on_branch": len(open_alerts),
        "alerts": open_alerts,
    }


def extract_pr_number(pr_url: str) -> int:
    """Extract the PR number from a GitHub PR URL."""
    parts = pr_url.rstrip("/").split("/")
    return int(parts[-1])


def build_retry_prompt(check_info: dict) -> str:
    """Build a follow-up prompt for Devin to fix remaining alerts."""
    alerts = check_info.get("alerts", [])

    prompt = (
        f"The PR you created still has {check_info['open_alerts_on_branch']} "
        f"CodeQL alert(s) that need to be fixed. The CodeQL check is failing.\n\n"
        f"Please fix the remaining issues:\n\n"
    )

    for alert in alerts[:10]:
        rule = alert.get("rule", {})
        loc = alert.get("most_recent_instance", {}).get("location", {})
        prompt += (
            f"- **{rule.get('description', 'Unknown')}** "
            f"({rule.get('security_severity_level', 'unknown')} severity) "
            f"at `{loc.get('path', '?')}:{loc.get('start_line', '?')}`\n"
        )

    prompt += (
        "\n\nPlease update the existing PR branch with fixes for these remaining alerts. "
        "Do not create a new PR — push to the same branch."
    )

    return prompt


def check_and_retry_sessions(
    config: Config,
    sessions: list[DevinSession],
    state: dict,
) -> list[dict]:
    """
    Check all finished sessions with PRs for CodeQL status.

    Three outcomes per PR:
    1. Passing or merged → mark session as "verified"
    2. Failing with fixable alerts → retry via Devin
    3. Failing with 0 branch alerts → flag as "needs_human_review"
       (the alert is from adjacent/out-of-scope code, Devin can't fix it)
    """
    actions = []
    already_checked = set(state.get("verified_sessions", []))

    for session in sessions:
        # Check sessions that have a PR and are either finished or blocked
        # (Devin goes "blocked" when it creates a PR and CodeQL fails)
        if session.status not in ("finished", "blocked") or not session.pr_url:
            continue

        if session.session_id in already_checked:
            continue

        pr_number = extract_pr_number(session.pr_url)

        try:
            check_info = get_pr_check_status(config, pr_number)
        except Exception as e:
            logger.error(f"Failed to check PR #{pr_number}: {e}")
            continue

        status = check_info["codeql_status"]
        remaining = check_info["open_alerts_on_branch"]
        pr_state = check_info["pr_state"]
        merged = check_info["merged"]

        # PR was merged — it's done
        if merged or pr_state == "closed":
            logger.info(f"PR #{pr_number}: {'Merged' if merged else 'Closed'}. Marking verified.")
            session.status = "merged" if merged else "closed"
            already_checked.add(session.session_id)
            actions.append({
                "action": "merged" if merged else "closed",
                "session_id": session.session_id,
                "pr_number": pr_number,
            })
            continue

        # CodeQL passing — verified, ready for human merge
        if status == "success":
            logger.info(f"PR #{pr_number}: CodeQL PASSING. Ready for engineer review.")
            session.status = "review_ready"
            already_checked.add(session.session_id)
            actions.append({
                "action": "passing",
                "session_id": session.session_id,
                "pr_number": pr_number,
            })
            continue

        # CodeQL failing with alerts on the branch — Devin can retry
        if status == "failure" and remaining > 0:
            logger.warning(
                f"PR #{pr_number}: CodeQL FAILING, {remaining} alert(s) on branch. "
                f"Sending Devin a retry."
            )
            retry_prompt = build_retry_prompt(check_info)
            try:
                send_message(config, session.session_id, retry_prompt)
                session.status = "running"
                actions.append({
                    "action": "retry",
                    "session_id": session.session_id,
                    "pr_number": pr_number,
                    "remaining_alerts": remaining,
                })
                logger.info(f"Retry sent to session {session.session_id}.")
            except Exception as e:
                logger.error(f"Retry failed for session {session.session_id}: {e}")
                actions.append({
                    "action": "retry_failed",
                    "session_id": session.session_id,
                    "pr_number": pr_number,
                    "error": str(e),
                })
            continue

        # CodeQL failing but 0 alerts on the branch — out-of-scope alert
        # This means the failing check is from an adjacent vulnerability
        # that wasn't part of this batch. Devin can't fix it. Needs human.
        if status == "failure" and remaining == 0:
            logger.warning(
                f"PR #{pr_number}: CodeQL FAILING but 0 alerts on branch. "
                f"This is likely an out-of-scope alert from adjacent code. "
                f"Flagging for human review."
            )
            session.status = "needs_human_review"
            actions.append({
                "action": "needs_human_review",
                "session_id": session.session_id,
                "pr_number": pr_number,
                "reason": (
                    "CodeQL check failing due to pre-existing alert in adjacent code. "
                    "The fix itself is correct but a separate vulnerability in the same "
                    "file is causing the check to fail. A human should review and either "
                    "merge with the failing check or dismiss the unrelated alert."
                ),
            })
            continue

        # Still running
        if status in ("in_progress", "queued"):
            logger.info(f"PR #{pr_number}: CodeQL still running. Will check next cycle.")
        else:
            logger.info(f"PR #{pr_number}: CodeQL status '{status}', {remaining} alerts.")

    state["verified_sessions"] = list(already_checked)
    return actions
