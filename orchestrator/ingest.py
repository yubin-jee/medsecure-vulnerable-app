"""
SecureFlow Orchestrator - Alert Ingestion Module

Pulls open CodeQL alerts from GitHub's code scanning API and normalizes
them into a standard format for downstream processing.
"""

from __future__ import annotations

import requests
import logging
from dataclasses import dataclass
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)


@dataclass
class CodeQLAlert:
    """Normalized representation of a CodeQL alert."""
    number: int
    state: str
    rule_id: str
    rule_name: str
    rule_description: str
    severity: str  # error, warning, note
    security_severity: str  # critical, high, medium, low
    cwe_ids: list[str]
    file_path: str
    start_line: int
    end_line: int
    message: str
    help_text: str
    html_url: str
    created_at: str
    tool_name: str

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "state": self.state,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_description": self.rule_description,
            "severity": self.severity,
            "security_severity": self.security_severity,
            "cwe_ids": self.cwe_ids,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "message": self.message,
            "help_text": self.help_text,
            "html_url": self.html_url,
            "created_at": self.created_at,
            "tool_name": self.tool_name,
        }


def extract_cwes(tags: list[str]) -> list[str]:
    """Extract CWE IDs from CodeQL rule tags."""
    cwes = []
    for tag in tags:
        if tag.startswith("external/cwe/cwe-"):
            cwe_id = tag.replace("external/cwe/cwe-", "CWE-")
            cwes.append(cwe_id)
    return cwes


def fetch_alerts(config: Config, state: str = "open") -> list[CodeQLAlert]:
    """
    Fetch all open CodeQL alerts from the repository.
    Handles pagination automatically.
    """
    alerts = []
    page = 1
    per_page = 100

    while True:
        url = (
            f"{config.github_api_base}/repos/{config.github_owner}/{config.github_repo}"
            f"/code-scanning/alerts"
        )
        params = {
            "state": state,
            "tool_name": "CodeQL",
            "per_page": per_page,
            "page": page,
            "sort": "created",
            "direction": "desc",
        }

        logger.info(f"Fetching alerts page {page}...")
        response = requests.get(url, headers=config.github_headers, params=params)

        if response.status_code == 404:
            logger.warning("Repository not found or code scanning not enabled.")
            return []

        response.raise_for_status()
        data = response.json()

        if not data:
            break

        for alert_data in data:
            rule = alert_data.get("rule", {})
            instance = alert_data.get("most_recent_instance", {})
            location = instance.get("location", {})
            tags = rule.get("tags", [])

            alert = CodeQLAlert(
                number=alert_data["number"],
                state=alert_data["state"],
                rule_id=rule.get("id", ""),
                rule_name=rule.get("name", ""),
                rule_description=rule.get("full_description", rule.get("description", "")),
                severity=rule.get("severity", "warning"),
                security_severity=rule.get("security_severity_level", "medium"),
                cwe_ids=extract_cwes(tags),
                file_path=location.get("path", ""),
                start_line=location.get("start_line", 0),
                end_line=location.get("end_line", 0),
                message=instance.get("message", {}).get("text", ""),
                help_text=rule.get("help", ""),
                html_url=alert_data.get("html_url", ""),
                created_at=alert_data.get("created_at", ""),
                tool_name=alert_data.get("tool", {}).get("name", "CodeQL"),
            )
            alerts.append(alert)

        if len(data) < per_page:
            break
        page += 1

    logger.info(f"Fetched {len(alerts)} {state} alerts.")
    return alerts


def get_alert_summary(alerts: list[CodeQLAlert]) -> dict:
    """Generate a summary of alerts by severity and category."""
    summary = {
        "total": len(alerts),
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_rule": {},
        "by_file": {},
    }

    for alert in alerts:
        sev = alert.security_severity
        if sev in summary["by_severity"]:
            summary["by_severity"][sev] += 1

        rule = alert.rule_name
        summary["by_rule"][rule] = summary["by_rule"].get(rule, 0) + 1

        file = alert.file_path
        summary["by_file"][file] = summary["by_file"].get(file, 0) + 1

    return summary
