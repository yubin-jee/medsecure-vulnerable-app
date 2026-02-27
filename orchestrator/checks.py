"""
SecureFlow Orchestrator - PR Check Monitor & Retry

Checks whether PRs created by Devin pass CodeQL checks.
Three outcomes:
1. CodeQL passing → mark as "review_ready"
2. CodeQL failing with new alerts (annotations) → send Devin a retry
3. CodeQL failing with 0 annotations → flag for human review (out-of-scope)
"""

from __future__ import annotations

import requests
import logging
from config import Config
from dispatch import DevinSession, send_message

logger = logging.getLogger(__name__)


def get_pr_check_status(config: Config, pr_number: int) -> dict:
    """
    Get the CodeQL check status for a specific PR.

    Uses check-run annotations to detect new alerts introduced by the PR,
    because the code-scanning/alerts?ref={branch} API doesn't reliably
    return "new in PR" alerts on feature branches.
    """
    base = f"{config.github_api_base}/repos/{config.github_owner}/{config.github_repo}"

    # Get PR metadata
    resp = requests.get(f"{base}/pulls/{pr_number}", headers=config.github_headers)
    resp.raise_for_status()
    pr_data = resp.json()
    head_sha = pr_data["head"]["sha"]
    branch = pr_data["head"]["ref"]
    pr_state = pr_data["state"]
    merged = pr_data.get("merged", False)

    # Get check runs for this commit
    resp = requests.get(
        f"{base}/commits/{head_sha}/check-runs", headers=config.github_headers
    )
    resp.raise_for_status()
    checks = resp.json()

    codeql_status = "unknown"
    codeql_run_id = None
    codeql_title = ""
    for run in checks.get("check_runs", []):
        name = run.get("name", "").lower()
        if "codeql" in name or "code-scanning" in name:
            codeql_status = run.get("conclusion") or run.get("status", "unknown")
            codeql_run_id = run["id"]
            codeql_title = run.get("output", {}).get("title", "")
            break

    # If CodeQL is failing, fetch check-run annotations to see the actual alerts.
    # The code-scanning/alerts?ref={branch} API returns 0 for PR branches because
    # "new alerts in code changed by this PR" are tracked as check-run annotations,
    # not as repo-level code-scanning alerts on the branch ref.
    annotations = []
    if codeql_status == "failure" and codeql_run_id:
        try:
            resp = requests.get(
                f"{base}/check-runs/{codeql_run_id}/annotations",
                headers=config.github_headers,
            )
            resp.raise_for_status()
            annotations = resp.json()
        except Exception:
            annotations = []

    return {
        "pr_number": pr_number,
        "head_sha": head_sha,
        "branch": branch,
        "pr_state": pr_state,
        "merged": merged,
        "codeql_status": codeql_status,
        "codeql_title": codeql_title,
        "annotations": annotations,
        "annotation_count": len(annotations),
    }


def extract_pr_number(pr_url: str) -> int:
    """Extract the PR number from a GitHub PR URL."""
    parts = pr_url.rstrip("/").split("/")
    return int(parts[-1])


def build_retry_prompt(check_info: dict) -> str:
    """Build a follow-up prompt for Devin to fix remaining alerts."""
    annotations = check_info.get("annotations", [])
    count = check_info["annotation_count"]
    title = check_info.get("codeql_title", "")

    prompt = (
        f"The PR you created has a failing CodeQL check: {title}\n\n"
        f"Please fix the following {count} issue(s):\n\n"
    )

    for ann in annotations[:10]:
        path = ann.get("path", "?")
        line = ann.get("start_line", "?")
        ann_title = ann.get("title", "Unknown issue")
        message = ann.get("message", "")
        if len(message) > 200:
            message = message[:200] + "..."
        prompt += f"- **{ann_title}** at `{path}:{line}` — {message}\n"

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
    Check finished/blocked sessions with PRs for CodeQL status.

    Three outcomes per PR:
    1. Passing or merged → mark as verified
    2. Failing with annotations (new alerts) → retry via Devin
    3. Failing with 0 annotations → flag as "needs_human_review"
    """
    actions = []
    already_checked = set(state.get("verified_sessions", []))

    for session in sessions:
        if not session.pr_url:
            continue

        # Skip sessions that are already in a terminal/verified state
        if session.status in ("merged", "closed", "review_ready", "needs_human_review"):
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
        annotation_count = check_info["annotation_count"]
        pr_state = check_info["pr_state"]
        merged = check_info["merged"]

        # PR was merged or closed
        if merged or pr_state == "closed":
            logger.info(
                f"PR #{pr_number}: {'Merged' if merged else 'Closed'}. Marking done."
            )
            session.status = "merged" if merged else "closed"
            already_checked.add(session.session_id)
            actions.append({
                "action": "merged" if merged else "closed",
                "session_id": session.session_id,
                "pr_number": pr_number,
            })
            continue

        # CodeQL passing — ready for engineer review
        if status == "success":
            logger.info(f"PR #{pr_number}: CodeQL PASSING. Ready for review.")
            session.status = "review_ready"
            already_checked.add(session.session_id)
            actions.append({
                "action": "passing",
                "session_id": session.session_id,
                "pr_number": pr_number,
            })
            continue

        # CodeQL failing with annotations — Devin can retry
        if status == "failure" and annotation_count > 0:
            logger.warning(
                f"PR #{pr_number}: CodeQL FAILING — "
                f"{check_info['codeql_title']}. Sending Devin a retry."
            )
            retry_prompt = build_retry_prompt(check_info)
            try:
                send_message(config, session.session_id, retry_prompt)
                session.status = "running"
                session.retry_count += 1
                actions.append({
                    "action": "retry",
                    "session_id": session.session_id,
                    "pr_number": pr_number,
                    "remaining_alerts": annotation_count,
                })
                logger.info(f"Retry message sent to session {session.session_id}.")
            except Exception as e:
                logger.error(f"Retry failed for {session.session_id}: {e}")
                actions.append({
                    "action": "retry_failed",
                    "session_id": session.session_id,
                    "pr_number": pr_number,
                    "error": str(e),
                })
            continue

        # CodeQL failing but 0 annotations — out-of-scope / pre-existing alert
        if status == "failure" and annotation_count == 0:
            logger.warning(
                f"PR #{pr_number}: CodeQL FAILING but 0 annotations. "
                f"Flagging for human review."
            )
            session.status = "needs_human_review"
            actions.append({
                "action": "needs_human_review",
                "session_id": session.session_id,
                "pr_number": pr_number,
                "reason": (
                    "CodeQL check failing due to a pre-existing alert in adjacent code. "
                    "The fix itself is correct but a separate vulnerability is causing "
                    "the check to fail. A human should review and either merge or "
                    "dismiss the unrelated alert."
                ),
            })
            continue

        # Still running
        if status in ("in_progress", "queued"):
            logger.info(f"PR #{pr_number}: CodeQL still running. Will check next cycle.")
        else:
            logger.info(
                f"PR #{pr_number}: CodeQL status '{status}', "
                f"{annotation_count} annotations."
            )

    state["verified_sessions"] = list(already_checked)
    return actions
